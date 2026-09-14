//! Semgrep native triage. Exact IDs still have cross-reference effects.
use bc_model::ProviderOrigin;
use serde_json::{json, Value};

fn selected<'a>(findings: &'a [Value], origin: &ProviderOrigin) -> Result<&'a Value, String> {
    let id = origin
        .native_ids
        .issue_id
        .as_deref()
        .ok_or("missing Semgrep issue ID")?
        .parse::<i64>()
        .map_err(|_| "invalid Semgrep issue ID")?;
    if id <= 0 {
        return Err("invalid Semgrep issue ID".into());
    }
    let matches: Vec<_> = findings
        .iter()
        .filter(|f| f["id"].as_i64() == Some(id))
        .collect();
    if matches.len() != 1 {
        return Err("Semgrep issue absent or ambiguous in repository inventory".into());
    }
    let finding = matches[0];
    if let Some(expected) = origin.native_ids.match_based_id.as_deref() {
        if finding["match_based_id"].as_str() != Some(expected) {
            return Err("Semgrep fingerprint changed".into());
        }
    }
    if let Some(expected) = origin.git_ref.as_deref() {
        if finding["ref"].as_str() != Some(expected) {
            return Err("Semgrep ref changed".into());
        }
    }
    if let Some(expected) = origin.repository_name.as_deref() {
        if finding["repository"]["name"].as_str() != Some(expected) {
            return Err("Semgrep repository changed".into());
        }
    }
    Ok(finding)
}

fn snapshot(findings: &[Value], origin: &ProviderOrigin) -> Result<Value, String> {
    let issue = selected(findings, origin)?;
    let fingerprint = issue["match_based_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("Semgrep fingerprint missing; cannot establish affected scope")?;
    let mut members: Vec<_> = findings.iter().filter(|f| f["match_based_id"].as_str() == Some(fingerprint))
        .map(|f| json!({"id":f["id"],"ref":f["ref"],"repository":f["repository"],"state":f["state"],"status":f["status"],"triage_state":f["triage_state"],"triage_reason":f["triage_reason"],"triage_comment":f["triage_comment"],"triaged_at":f["triaged_at"],"severity":f["severity"]})).collect();
    members.sort_by_key(|v| v["id"].as_i64());
    Ok(json!({"issue_id":issue["id"],"match_based_id":fingerprint,"members":members}))
}

use super::{ApprovedAction, PublishClient, PublishError, WriteResult, WriteStatus};
use reqwest::Method;

fn segment(value: Option<&str>) -> Result<&str, PublishError> {
    value
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 255
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        })
        .ok_or_else(|| PublishError::new("invalid Semgrep deployment slug"))
}

pub(super) async fn read(
    client: &PublishClient,
    origin: &ProviderOrigin,
) -> Result<Value, PublishError> {
    let deployment = segment(origin.tenant_id.as_deref())?;
    let repo = origin
        .repository_name
        .as_deref()
        .filter(|s| !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control))
        .ok_or_else(|| PublishError::new("missing or invalid Semgrep repository"))?;
    let mut findings = Vec::new();
    for page in 0..100 {
        let mut url = reqwest::Url::parse("https://query.invalid/").expect("constant URL");
        url.query_pairs_mut()
            .append_pair("repos", repo)
            .append_pair("dedup", "false")
            .append_pair("issue_type", "sast")
            .append_pair("page_size", "100")
            .append_pair("page", &page.to_string());
        let path = format!(
            "/api/v1/deployments/{deployment}/findings?{}",
            url.query().unwrap_or_default()
        );
        let response = client.get(&path).await?;
        let batch = response["findings"]
            .as_array()
            .ok_or_else(|| PublishError::new("Semgrep inventory missing findings array"))?;
        if batch.len() > 100 {
            return Err(PublishError::new(
                "Semgrep inventory page exceeded requested bound",
            ));
        }
        findings.extend(batch.iter().cloned());
        if batch.len() < 100 {
            return snapshot(&findings, origin).map_err(PublishError::new);
        }
    }
    Err(PublishError::new(
        "Semgrep inventory pagination cap reached; affected scope incomplete",
    ))
}

pub(super) async fn write(
    client: &PublishClient,
    origin: &ProviderOrigin,
    action: &ApprovedAction,
    expected: &Value,
) -> Result<WriteResult, PublishError> {
    let deployment = segment(origin.tenant_id.as_deref())?;
    let id = origin
        .native_ids
        .issue_id
        .as_deref()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| PublishError::new("invalid Semgrep native numeric ID"))?;
    if action.reason().is_empty() || action.reason().chars().count() > 3000 {
        return Err(PublishError::new(
            "Semgrep note must contain 1 to 3000 characters",
        ));
    }
    let mut body = json!({"deployment_slug":deployment,"issue_type":"sast","issue_ids":[id],"new_note":action.reason()});
    match action {
        ApprovedAction::FalsePositive { .. } => {
            body["new_triage_state"] = json!("ignored");
            body["new_triage_reason"] = json!("false_positive");
        }
        ApprovedAction::Confirmed {
            severity: Some(_), ..
        } => return Err(PublishError::new("Semgrep severity mutation unsupported")),
        _ => {}
    }
    let before = read(client, origin).await?;
    if &before != expected {
        return Err(PublishError::new(
            "Provider baseline changed before mutation",
        ));
    }
    if matches!(action, ApprovedAction::FalsePositive { .. })
        && before["members"]
            .as_array()
            .is_none_or(|members| members.iter().any(|m| m["triage_state"] != "untriaged"))
    {
        return Err(PublishError::new(
            "Existing Semgrep triage decision requires separate human reconciliation",
        ));
    }
    let response = client
        .send_once(
            Method::POST,
            &format!("/api/v1/deployments/{deployment}/triage"),
            &body,
        )
        .await?;
    let returned = response["triaged_issues"].as_array();
    let response_valid = returned.is_some_and(|ids| {
        let unique: std::collections::BTreeSet<_> = ids.iter().filter_map(Value::as_i64).collect();
        unique.contains(&id)
            && unique.len() == ids.len()
            && unique.iter().all(|id| *id > 0)
            && before["members"].as_array().is_some_and(|members| {
                unique
                    .iter()
                    .all(|id| members.iter().any(|m| m["id"].as_i64() == Some(*id)))
            })
            && response["num_triaged"].as_u64() == Some(ids.len() as u64)
    });
    let after = match read(client, origin).await {
        Ok(after) => after,
        Err(error) => {
            return Ok(WriteResult {
                status: WriteStatus::AcceptedUnverified,
                response: json!({"mutation":response,"readback_error":error.message}),
            });
        }
    };
    let members = after["members"].as_array();
    let verified = response_valid
        && members.is_some_and(|members| {
            let ids = returned.expect("response_valid checked IDs");
            ids.iter().all(|id| {
                members.iter().any(|m| {
                    m["id"] == *id
                        && m["triage_comment"]
                            .as_str()
                            .is_some_and(|s| s.contains(action.reason()))
                        && (!matches!(action, ApprovedAction::FalsePositive { .. })
                            || (m["triage_state"] == "ignored"
                                && m["triage_reason"] == "false_positive"))
                })
            })
        });
    Ok(WriteResult {
        status: if verified {
            WriteStatus::Verified
        } else {
            WriteStatus::AcceptedUnverified
        },
        response: json!({"mutation":response,"readback":after}),
    })
}

#[cfg(test)]
mod tests {
    async fn write(
        client: &PublishClient,
        origin: &ProviderOrigin,
        action: &ApprovedAction,
    ) -> Result<WriteResult, PublishError> {
        let expected = read(client, origin).await?;
        super::write(client, origin, action, &expected).await
    }

    use super::super::Auth;
    use super::*;
    use bc_model::ProviderNativeIds;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    fn origin() -> ProviderOrigin {
        ProviderOrigin {
            tenant_id: Some("tenant".into()),
            repository_name: Some("org/repo".into()),
            git_ref: Some("refs/heads/main".into()),
            native_ids: ProviderNativeIds {
                issue_id: Some("1".into()),
                match_based_id: Some("fp".into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }
    fn issue() -> Value {
        json!({"id":1,"match_based_id":"fp","ref":"refs/heads/main","repository":{"name":"org/repo"},"triage_state":"ignored","triage_reason":"false_positive","triage_comment":"checked"})
    }
    #[tokio::test]
    async fn native_ignore_reads_back_without_losing_cross_ref_members() {
        let server = MockServer::start().await;
        let mut other = issue();
        other["id"] = json!(2);
        other["ref"] = json!("refs/heads/develop");
        Mock::given(method("GET"))
            .and(path("/api/v1/deployments/tenant/findings"))
            .and(header("Authorization", "Bearer secret"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"findings":[issue(),other]})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST")).and(path("/api/v1/deployments/tenant/triage")).and(body_partial_json(json!({"deployment_slug":"tenant","issue_ids":[1],"new_triage_reason":"false_positive"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"num_triaged":2,"triaged_issues":[1,2]}))).expect(1).mount(&server).await;
        let mut first = issue();
        first["triage_state"] = json!("untriaged");
        let mut second = first.clone();
        second["id"] = json!(2);
        second["ref"] = json!("refs/heads/develop");
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"findings":[first,second]})),
            )
            .up_to_n_times(2)
            .with_priority(1)
            .mount(&server)
            .await;
        let client = PublishClient::test(server.uri(), Auth::Bearer("secret".into()));
        let result = write(
            &client,
            &origin(),
            &ApprovedAction::FalsePositive {
                reason: "checked".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(result.status, WriteStatus::Verified);
        assert_eq!(
            result.response["readback"]["members"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
    #[tokio::test]
    async fn failed_readback_does_not_erase_successful_mutation() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"findings":[issue()]})))
            .up_to_n_times(2)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"num_triaged":1,"triaged_issues":[1]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = PublishClient::test(server.uri(), Auth::Bearer("secret".into()));
        let result = write(
            &client,
            &origin(),
            &ApprovedAction::Note {
                reason: "checked".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(result.status, WriteStatus::AcceptedUnverified);
    }
    #[tokio::test]
    async fn mutation_server_failure_is_not_retried() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"findings":[issue()]})))
            .up_to_n_times(2)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        let client = PublishClient::test(server.uri(), Auth::Bearer("secret".into()));
        assert!(
            write(
                &client,
                &origin(),
                &ApprovedAction::Note {
                    reason: "checked".into()
                }
            )
            .await
            .unwrap_err()
            .uncertain
        );
    }
    #[test]
    fn changed_or_ambiguous_identity_is_refused() {
        assert!(snapshot(&[], &origin()).is_err());
        assert!(snapshot(&[issue(), issue()], &origin()).is_err());
        let mut f = issue();
        f["match_based_id"] = json!("changed");
        assert!(snapshot(&[f], &origin()).is_err());
        let mut f = issue();
        f["ref"] = json!("different");
        assert!(snapshot(&[f], &origin()).is_err());
        let mut f = issue();
        f["repository"]["name"] = json!("different");
        assert!(snapshot(&[f], &origin()).is_err());
    }
    #[tokio::test]
    async fn changed_prewrite_baseline_refuses_all_mutations() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"findings":[issue()]})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let client = PublishClient::test(server.uri(), Auth::Bearer("secret".into()));
        let error = super::write(
            &client,
            &origin(),
            &ApprovedAction::FalsePositive {
                reason: "checked".into(),
            },
            &Value::Null,
        )
        .await
        .unwrap_err();
        assert!(error.message.contains("baseline changed"));
    }
    #[test]
    fn native_identity_is_never_inferred_and_optional_bindings_are_explicit() {
        for id in [None, Some("0"), Some("bad")] {
            let mut o = origin();
            o.native_ids.issue_id = id.map(str::to_owned);
            assert!(snapshot(&[issue()], &o).is_err());
        }
        let mut o = origin();
        o.native_ids.match_based_id = None;
        o.git_ref = None;
        o.repository_name = None;
        assert!(snapshot(&[issue()], &o).is_ok());
        let mut f = issue();
        f["match_based_id"] = Value::Null;
        assert!(snapshot(&[f], &o).is_err());
    }
    #[tokio::test]
    async fn malformed_or_unbounded_inventories_fail_closed() {
        for variant in 0..3 {
            let server = MockServer::start().await;
            let data = match variant {
                0 => json!({}),
                1 => json!({"findings":vec![Value::Null;101]}),
                _ => json!({"findings":vec![Value::Null;100]}),
            };
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_json(data))
                .mount(&server)
                .await;
            let client = PublishClient::test(server.uri(), Auth::Bearer("secret".into()));
            let message = read(&client, &origin()).await.unwrap_err().message;
            assert!(message.contains(match variant {
                0 => "array",
                1 => "bound",
                _ => "pagination cap",
            }));
        }
    }
    #[tokio::test]
    async fn invalid_actions_and_identifiers_never_contact_provider() {
        let server = MockServer::start().await;
        let client = PublishClient::test(server.uri(), Auth::Bearer("secret".into()));
        for reason in [String::new(), "x".repeat(3001)] {
            assert!(super::write(
                &client,
                &origin(),
                &ApprovedAction::Note { reason },
                &Value::Null
            )
            .await
            .is_err());
        }
        assert!(super::write(
            &client,
            &origin(),
            &ApprovedAction::Confirmed {
                reason: "checked".into(),
                severity: Some("low".into())
            },
            &Value::Null
        )
        .await
        .is_err());
        let mut o = origin();
        o.tenant_id = Some("../other".into());
        assert!(read(&client, &o).await.is_err());
        o = origin();
        o.repository_name = None;
        assert!(read(&client, &o).await.is_err());
        o = origin();
        o.native_ids.issue_id = Some("bad".into());
        assert!(super::write(
            &client,
            &o,
            &ApprovedAction::Note {
                reason: "checked".into()
            },
            &Value::Null
        )
        .await
        .is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
    }
    #[tokio::test]
    async fn existing_triage_blocks_false_positive_and_bad_readback_stays_unverified() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"findings":[issue()]})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"num_triaged":1,"triaged_issues":[999]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = PublishClient::test(server.uri(), Auth::Bearer("secret".into()));
        assert!(write(
            &client,
            &origin(),
            &ApprovedAction::FalsePositive {
                reason: "checked".into()
            }
        )
        .await
        .unwrap_err()
        .message
        .contains("Existing Semgrep"));
        let result = write(
            &client,
            &origin(),
            &ApprovedAction::Confirmed {
                reason: "checked".into(),
                severity: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(result.status, WriteStatus::AcceptedUnverified);
    }
}
