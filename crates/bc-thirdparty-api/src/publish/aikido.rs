//! Native Aikido issue updates. Repository identity is checked independently of
//! issue-group note scope. No Git commit is invented from scan timestamps.
use super::{ApprovedAction, PublishClient, PublishError, WriteResult, WriteStatus};
use bc_model::ProviderOrigin;
use reqwest::Method;
use serde_json::{json, Value};

fn id(value: &Option<String>, label: &str) -> Result<i64, PublishError> {
    value
        .as_deref()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .ok_or_else(|| PublishError::new(format!("Aikido requires a positive native {label}")))
}

pub(super) async fn read(
    client: &PublishClient,
    origin: &ProviderOrigin,
) -> Result<Value, PublishError> {
    let issue_id = id(&origin.native_ids.issue_id, "issue ID")?;
    let repo_id = id(&origin.repository_id, "repository ID")?;
    let issue = client
        .get(&format!("/api/public/v1/issues/{issue_id}"))
        .await?;
    if issue["id"].as_i64() != Some(issue_id)
        || issue["code_repo_id"].as_i64() != Some(repo_id)
        || issue["type"].as_str() != Some("sast")
    {
        return Err(PublishError::new(
            "Aikido issue identity, repository, or SAST product mismatch",
        ));
    }
    if issue["status"].as_str().is_none() || issue["severity"].as_str().is_none() {
        return Err(PublishError::new(
            "Aikido issue lacks current state or severity",
        ));
    }
    if origin.native_ids.group_id.is_some()
        && issue["group_id"].as_i64() != Some(id(&origin.native_ids.group_id, "group ID")?)
    {
        return Err(PublishError::new("Aikido issue group changed"));
    }
    let repository = client
        .get(&format!("/api/public/v1/repositories/code/{repo_id}"))
        .await?;
    if repository["id"].as_i64() != Some(repo_id) {
        return Err(PublishError::new("Aikido repository identity mismatch"));
    }
    if let Some(expected) = &origin.git_ref {
        if repository["branch"].as_str() != Some(expected.as_str()) {
            return Err(PublishError::new(
                "Aikido configured repository branch changed",
            ));
        }
    }
    // Notes are part of the baseline whenever an imported group ID is known.
    let notes = if origin.native_ids.group_id.is_some() {
        let group = id(&origin.native_ids.group_id, "group ID")?;
        client
            .get(&format!("/api/public/v1/issues/groups/{group}/notes"))
            .await?
    } else {
        Value::Null
    };
    Ok(
        json!({"source_revision":null,"source_ref":repository["branch"],"issue":issue,"repository":repository,"notes":notes}),
    )
}

pub(super) async fn write(
    client: &PublishClient,
    origin: &ProviderOrigin,
    action: &ApprovedAction,
    expected: &Value,
) -> Result<WriteResult, PublishError> {
    let issue_id = id(&origin.native_ids.issue_id, "issue ID")?;
    // A direct caller receives the same binding checks as the CLI publisher.
    let before = read(client, origin).await?;
    if before != *expected {
        return Err(PublishError::new(
            "Provider baseline changed before mutation",
        ));
    }
    if matches!(action, ApprovedAction::FalsePositive { .. }) && before["issue"]["status"] != "open"
    {
        return Err(PublishError::new(
            "Aikido false-positive publication would overwrite existing triage",
        ));
    }
    let (method, path, body) = match action {
        ApprovedAction::FalsePositive { reason } => (
            Method::PUT,
            format!("/api/public/v1/issues/{issue_id}/ignore"),
            json!({"reason":reason,"apply_for_all_tags":false}),
        ),
        ApprovedAction::Confirmed {
            reason,
            severity: Some(severity),
        } => {
            let severity = severity.to_ascii_lowercase();
            if !["low", "medium", "high", "critical"].contains(&severity.as_str()) {
                return Err(PublishError::new(
                    "Aikido severity must be low, medium, high, or critical",
                ));
            }
            (
                Method::POST,
                format!("/api/public/v1/issues/{issue_id}/severity/adjust"),
                json!({"adjusted_severity":severity,"reason":reason}),
            )
        }
        ApprovedAction::Confirmed {
            reason,
            severity: None,
        }
        | ApprovedAction::Note { reason } => {
            let group = id(
                &origin.native_ids.group_id,
                "group ID for group-scoped note",
            )?;
            (
                Method::POST,
                format!("/api/public/v1/issues/groups/{group}/notes"),
                json!({"note":reason}),
            )
        }
    };
    let response = client.send_once(method, &path, &body).await?;
    let after = match read(client, origin).await {
        Ok(value) => value,
        Err(_) => {
            return Ok(WriteResult {
                status: WriteStatus::AcceptedUnverified,
                response: json!({"provider_response":response,"readback":"failed"}),
            })
        }
    };
    let verified = match action {
        ApprovedAction::Note { .. } | ApprovedAction::Confirmed { severity: None, .. } => {
            response["note_id"].as_i64().is_some_and(|note_id| {
                note_id > 0 && contains_note(&after["notes"], note_id, action.reason())
            })
        }
        ApprovedAction::FalsePositive { reason } => {
            after["issue"]["status"] == "ignored"
                && after["issue"]["ignore_reasons"]
                    .as_array()
                    .is_some_and(|reasons| {
                        reasons
                            .iter()
                            .any(|r| r["kind"] == "api_ignore" && r["reason"] == *reason)
                    })
        }
        ApprovedAction::Confirmed {
            severity: Some(severity),
            ..
        } => {
            after["issue"]["severity"]
                .as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case(severity))
                && after["issue"]["status"] == before["issue"]["status"]
        }
    };
    Ok(WriteResult {
        status: if verified
            && before["issue"]["group_id"] == after["issue"]["group_id"]
            && before["repository"] == after["repository"]
        {
            WriteStatus::Verified
        } else {
            WriteStatus::AcceptedUnverified
        },
        response: json!({"provider_response":response,"observed":after}),
    })
}

fn contains_note(value: &Value, note_id: i64, reason: &str) -> bool {
    let matches =
        |v: &Value| v["id"].as_i64() == Some(note_id) && v["note"].as_str() == Some(reason);
    // The published schema describes an object; deployments may return a list.
    // Only direct note records count, never an arbitrary nested matching string.
    value
        .as_array()
        .map_or_else(|| matches(value), |notes| notes.iter().any(matches))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publish::Auth;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    async fn write_approved(
        client: &PublishClient,
        origin: &ProviderOrigin,
        action: &ApprovedAction,
    ) -> Result<WriteResult, PublishError> {
        let expected = read(client, origin).await?;
        write(client, origin, action, &expected).await
    }
    fn origin() -> ProviderOrigin {
        let mut o = ProviderOrigin {
            repository_id: Some("9".into()),
            git_ref: Some("main".into()),
            ..Default::default()
        };
        o.native_ids.issue_id = Some("42".into());
        o.native_ids.group_id = Some("7".into());
        o
    }
    async fn fixtures(
        server: &MockServer,
        changed: Arc<AtomicBool>,
        action: &ApprovedAction,
        original_status: &str,
    ) {
        let action = action.clone();
        let original_status = original_status.to_string();
        let issue_change = changed.clone();
        Mock::given(method("GET")).and(path("/api/public/v1/issues/42")).respond_with(move |_:&Request| {
            let changed=issue_change.load(Ordering::SeqCst);
            let status=if changed && matches!(action,ApprovedAction::FalsePositive{..}) {"ignored"} else {&original_status};
            let severity=if changed {if let ApprovedAction::Confirmed{severity:Some(s),..}=&action {s.as_str()}else{"high"}}else{"high"};
            ResponseTemplate::new(200).set_body_json(json!({"id":42,"code_repo_id":9,"group_id":7,"type":"sast","status":status,"severity":severity,"ignore_reasons":if changed {json!([{"kind":"api_ignore","reason":"approved reason"}])}else{json!([])}}))
        }).mount(server).await;
        Mock::given(method("GET"))
            .and(path("/api/public/v1/repositories/code/9"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":9,"branch":"main"})))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/public/v1/issues/groups/7/notes"))
            .respond_with(move |_: &Request| {
                ResponseTemplate::new(200).set_body_json(if changed.load(Ordering::SeqCst) {
                    json!([{"id":123,"note":"approved reason"}])
                } else {
                    json!([])
                })
            })
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn ignore_severity_and_group_note_are_verified_by_readback() {
        for action in [
            ApprovedAction::FalsePositive {
                reason: "approved reason".into(),
            },
            ApprovedAction::Confirmed {
                reason: "approved reason".into(),
                severity: Some("low".into()),
            },
            ApprovedAction::Note {
                reason: "approved reason".into(),
            },
            ApprovedAction::Confirmed {
                reason: "approved reason".into(),
                severity: None,
            },
        ] {
            let server = MockServer::start().await;
            let changed = Arc::new(AtomicBool::new(false));
            fixtures(&server, changed.clone(), &action, "open").await;
            let (verb, payload_path, body) = match &action {
                ApprovedAction::FalsePositive { .. } => (
                    "PUT",
                    "/api/public/v1/issues/42/ignore",
                    json!({"reason":"approved reason","apply_for_all_tags":false}),
                ),
                ApprovedAction::Confirmed {
                    severity: Some(_), ..
                } => (
                    "POST",
                    "/api/public/v1/issues/42/severity/adjust",
                    json!({"reason":"approved reason","adjusted_severity":"low"}),
                ),
                _ => (
                    "POST",
                    "/api/public/v1/issues/groups/7/notes",
                    json!({"note":"approved reason"}),
                ),
            };
            Mock::given(method(verb))
                .and(path(payload_path))
                .and(body_json(body))
                .respond_with(move |_: &Request| {
                    changed.store(true, Ordering::SeqCst);
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"note_id":123,"success":1,"status":"ok"}))
                })
                .expect(1)
                .mount(&server)
                .await;
            let result = write_approved(
                &PublishClient::test(server.uri(), Auth::Bearer("token".into())),
                &origin(),
                &action,
            )
            .await
            .unwrap();
            assert_eq!(result.status, WriteStatus::Verified);
        }
    }

    #[tokio::test]
    async fn accepted_mutation_without_observed_effect_is_unverified() {
        let server = MockServer::start().await;
        let action = ApprovedAction::FalsePositive {
            reason: "approved reason".into(),
        };
        fixtures(&server, Arc::new(AtomicBool::new(false)), &action, "open").await;
        Mock::given(method("PUT"))
            .and(path("/api/public/v1/issues/42/ignore"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status":"ok"})))
            .expect(1)
            .mount(&server)
            .await;
        let result = write_approved(
            &PublishClient::test(server.uri(), Auth::Bearer("t".into())),
            &origin(),
            &action,
        )
        .await
        .unwrap();
        assert_eq!(result.status, WriteStatus::AcceptedUnverified);
    }

    #[tokio::test]
    async fn existing_human_ignore_and_invalid_severity_send_no_mutation() {
        let server = MockServer::start().await;
        let action = ApprovedAction::FalsePositive {
            reason: "approved reason".into(),
        };
        fixtures(
            &server,
            Arc::new(AtomicBool::new(false)),
            &action,
            "ignored",
        )
        .await;
        let client = PublishClient::test(server.uri(), Auth::Bearer("t".into()));
        assert!(write_approved(&client, &origin(), &action)
            .await
            .unwrap_err()
            .message
            .contains("existing triage"));
        assert!(write_approved(
            &client,
            &origin(),
            &ApprovedAction::Confirmed {
                reason: "r".into(),
                severity: Some("info".into())
            }
        )
        .await
        .is_err());
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == Method::GET));
    }

    #[tokio::test]
    async fn wrong_issue_binding_fails_before_repository_lookup_or_write_approved() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/public/v1/issues/42"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"id":42,"code_repo_id":99,"type":"sast"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = PublishClient::test(server.uri(), Auth::Bearer("t".into()));
        assert!(read(&client, &origin()).await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn mutation_failure_is_not_retried() {
        let server = MockServer::start().await;
        let action = ApprovedAction::FalsePositive {
            reason: "approved reason".into(),
        };
        fixtures(&server, Arc::new(AtomicBool::new(false)), &action, "open").await;
        Mock::given(method("PUT"))
            .and(path("/api/public/v1/issues/42/ignore"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            write_approved(
                &PublishClient::test(server.uri(), Auth::Bearer("t".into())),
                &origin(),
                &action
            )
            .await
            .unwrap_err()
            .uncertain
        );
    }

    #[test]
    fn note_readback_requires_returned_id_and_exact_reason() {
        assert!(contains_note(&json!({"id":3,"note":"reason"}), 3, "reason"));
        assert!(!contains_note(
            &json!({"id":4,"note":"reason"}),
            3,
            "reason"
        ));
        assert!(!contains_note(
            &json!({"nested":{"id":3,"note":"reason"}}),
            3,
            "reason"
        ));
        assert!(id(&Some("0".into()), "issue").is_err());
    }
    #[tokio::test]
    async fn changed_approved_baseline_is_rejected_before_mutation() {
        let server = MockServer::start().await;
        let action = ApprovedAction::FalsePositive {
            reason: "approved reason".into(),
        };
        fixtures(&server, Arc::new(AtomicBool::new(false)), &action, "open").await;
        let client = PublishClient::test(server.uri(), Auth::Bearer("t".into()));
        let mut expected = read(&client, &origin()).await.unwrap();
        expected["reviewed_other_snapshot"] = json!(true);
        let error = write(&client, &origin(), &action, &expected)
            .await
            .unwrap_err();
        assert!(error.message.contains("baseline changed"));
        assert!(!error.uncertain);
    }
    #[tokio::test]
    async fn missing_state_group_or_repository_changes_refuse_baseline() {
        let good = json!({"id":42,"code_repo_id":9,"group_id":7,"type":"sast","status":"open","severity":"high"});
        let mut cases = Vec::new();
        for field in ["status", "severity"] {
            let mut issue = good.clone();
            issue[field] = Value::Null;
            cases.push(("/api/public/v1/issues/42", issue, "lacks current state"));
        }
        let mut wrong_group = good.clone();
        wrong_group["group_id"] = json!(88);
        cases.push(("/api/public/v1/issues/42", wrong_group, "group changed"));
        cases.push((
            "/api/public/v1/repositories/code/9",
            json!({"id":88,"branch":"main"}),
            "repository identity mismatch",
        ));
        cases.push((
            "/api/public/v1/repositories/code/9",
            json!({"id":9,"branch":"develop"}),
            "branch changed",
        ));
        for (endpoint, response, message) in cases {
            let server = MockServer::start().await;
            fixtures(
                &server,
                Arc::new(AtomicBool::new(false)),
                &ApprovedAction::Note { reason: "r".into() },
                "open",
            )
            .await;
            Mock::given(method("GET"))
                .and(path(endpoint))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .with_priority(1)
                .mount(&server)
                .await;
            let error = read(
                &PublishClient::test(server.uri(), Auth::Bearer("t".into())),
                &origin(),
            )
            .await
            .unwrap_err();
            assert!(error.message.contains(message), "{}", error.message);
        }
    }

    #[tokio::test]
    async fn missing_group_allows_issue_baseline_but_never_invents_note_scope() {
        let server = MockServer::start().await;
        fixtures(
            &server,
            Arc::new(AtomicBool::new(false)),
            &ApprovedAction::Note { reason: "r".into() },
            "open",
        )
        .await;
        let mut o = origin();
        o.git_ref = None;
        o.native_ids.group_id = None;
        let client = PublishClient::test(server.uri(), Auth::Bearer("t".into()));
        let expected = read(&client, &o).await.unwrap();
        assert!(expected["notes"].is_null());
        assert_eq!(expected["source_ref"], "main");
        let error = write(
            &client,
            &o,
            &ApprovedAction::Note {
                reason: "reviewed note".into(),
            },
            &expected,
        )
        .await
        .unwrap_err();
        assert!(error.message.contains("group ID"));
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == Method::GET && !r.url.path().ends_with("/notes")));
    }

    #[tokio::test]
    async fn successful_ignore_with_failed_readback_remains_accepted_unverified() {
        let server = MockServer::start().await;
        let changed = Arc::new(AtomicBool::new(false));
        let action = ApprovedAction::FalsePositive {
            reason: "approved reason".into(),
        };
        fixtures(&server, changed.clone(), &action, "open").await;
        let read_change = changed.clone();
        Mock::given(method("GET")).and(path("/api/public/v1/issues/42")).respond_with(move |_:&Request| {
            if read_change.load(Ordering::SeqCst) {ResponseTemplate::new(503)} else {
                ResponseTemplate::new(200).set_body_json(json!({"id":42,"code_repo_id":9,"group_id":7,"type":"sast","status":"open","severity":"high","ignore_reasons":[]}))
            }
        }).with_priority(1).mount(&server).await;
        Mock::given(method("PUT"))
            .and(path("/api/public/v1/issues/42/ignore"))
            .respond_with(move |_: &Request| {
                changed.store(true, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(json!({"status":"ok"}))
            })
            .expect(1)
            .mount(&server)
            .await;
        let result = write_approved(
            &PublishClient::test(server.uri(), Auth::Bearer("t".into())),
            &origin(),
            &action,
        )
        .await
        .unwrap();
        assert_eq!(result.status, WriteStatus::AcceptedUnverified);
        assert_eq!(result.response["readback"], "failed");
    }
}
