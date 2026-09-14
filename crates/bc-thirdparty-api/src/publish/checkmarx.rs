//! Checkmarx native predicates. scanId identifies evidence and summary updates;
//! it never confines triage to one branch. Tenant grouping is read explicitly.
use super::{ApprovedAction, PublishClient, PublishError, WriteResult, WriteStatus};
use bc_model::ProviderOrigin;
use reqwest::Method;
use serde_json::{json, Value};

fn segment<'a>(value: &'a Option<String>, label: &str) -> Result<&'a str, PublishError> {
    value
        .as_deref()
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 256
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .ok_or_else(|| PublishError::new(format!("Checkmarx requires a safe native {label}")))
}
fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

pub(super) async fn read(
    client: &PublishClient,
    origin: &ProviderOrigin,
) -> Result<Value, PublishError> {
    let project = segment(&origin.project_id, "project ID")?;
    let similarity = segment(&origin.native_ids.similarity_id, "similarity ID")?;
    let scan_id = segment(&origin.scan_id, "scan ID")?;
    let scan = client.get(&format!("/api/scans/{scan_id}")).await?;
    if scan["id"] != scan_id
        || scan["projectId"] != project
        || scan["status"].as_str() != Some("Completed")
    {
        return Err(PublishError::new(
            "Checkmarx scan identity, project, or completed status mismatch",
        ));
    }
    if origin
        .git_ref
        .as_deref()
        .is_some_and(|r| scan["branch"].as_str() != Some(r))
    {
        return Err(PublishError::new("Checkmarx scan branch mismatch"));
    }
    if let (Some(expected), Some(actual)) = (origin.revision.as_deref(), scan["commitId"].as_str())
    {
        if expected != actual {
            return Err(PublishError::new("Checkmarx scan revision mismatch"));
        }
    }
    let result=client.get(&format!("/api/sast-results?scan-id={scan_id}&similarity-id={similarity}&similarity-id-operation=EQUAL&apply-predicates=true&include-nodes=false&limit=200&offset=0")).await?;
    let rows = result["results"]
        .as_array()
        .ok_or_else(|| PublishError::new("Checkmarx result lookup lacks results"))?;
    if rows.is_empty()
        || result["totalCount"].as_u64() != Some(rows.len() as u64)
        || rows.len() > 200
    {
        return Err(PublishError::new(
            "Checkmarx similarity result group is missing or exceeds bounded lookup",
        ));
    }
    let mut current = Vec::new();
    for row in rows {
        if scalar(&row["similarityID"]).as_deref() != Some(similarity)
            || row["state"].as_str().is_none()
            || row["severity"].as_str().is_none()
        {
            return Err(PublishError::new(
                "Checkmarx returned an unmatched or incomplete SAST result",
            ));
        }
        current.push(json!({"resultHash":row["resultHash"],"ID":row["ID"],"similarityID":row["similarityID"],"attackVectorID":row.get("attackVectorID").or_else(||row.get("attackVectorId")).unwrap_or(&Value::Null),"state":row["state"],"severity":row["severity"]}));
    }
    current.sort_by_key(Value::to_string);
    let mut grouping = client
        .send_once(
            Method::POST,
            "/api/sast-results-predicates/predicates-status",
            &json!({"scanID":scan_id,"similarResultsIDs":[similarity]}),
        )
        .await?;
    if grouping["isUpdatePredicatesRunning"].as_bool() != Some(false) {
        return Err(PublishError::new(
            "Checkmarx predicate update is running or status is unknown",
        ));
    }
    match grouping["groupingMode"].as_str() {
        Some("Similarity ID") => {}
        Some("Attack Vector ID") => {
            let attack = segment(&origin.native_ids.attack_vector_id, "attack vector ID")?;
            if attack.len() != 16
                || !attack.bytes().all(|b| b.is_ascii_hexdigit())
                || current
                    .iter()
                    .any(|r| r["attackVectorID"].as_str() != Some(attack))
            {
                return Err(PublishError::new(
                    "Checkmarx attack-vector identity is missing or spans inconsistent flows",
                ));
            }
            // The status key follows the tenant's grouping mode. The initial
            // request discovers that mode; check the actual attack-vector key
            // before relying on a non-running status for this group.
            grouping = client
                .send_once(
                    Method::POST,
                    "/api/sast-results-predicates/predicates-status",
                    &json!({"scanID":scan_id,"similarResultsIDs":[attack]}),
                )
                .await?;
            if grouping["groupingMode"] != "Attack Vector ID"
                || grouping["isUpdatePredicatesRunning"].as_bool() != Some(false)
            {
                return Err(PublishError::new(
                    "Checkmarx attack-vector update is running or grouping changed",
                ));
            }
        }
        _ => return Err(PublishError::new("Checkmarx grouping mode is unknown")),
    }
    let predicates=client.get(&format!("/api/sast-results-predicates/{similarity}/latest?project-ids={project}&scan-id={scan_id}")).await?;
    let entries = predicates["latestPredicatePerProject"]
        .as_array()
        .ok_or_else(|| PublishError::new("Checkmarx latest predicate response is malformed"))?;
    if entries.iter().any(|p| {
        p["projectId"] != project || scalar(&p["similarityId"]).as_deref() != Some(similarity)
    }) {
        return Err(PublishError::new("Checkmarx predicate identity mismatch"));
    }
    // Do not retain uploadUrl: a scan response may contain a signed source URL.
    let scan = json!({"id":scan["id"],"projectId":scan["projectId"],"status":scan["status"],
        "branch":scan["branch"],"commitId":scan["commitId"],"commitTag":scan["commitTag"]});
    Ok(
        json!({"source_revision":scan["commitId"],"source_ref":scan["branch"],"scan":scan,"results":current,"grouping":grouping,"predicates":predicates}),
    )
}

pub(super) async fn write(
    client: &PublishClient,
    origin: &ProviderOrigin,
    action: &ApprovedAction,
    expected: &Value,
) -> Result<WriteResult, PublishError> {
    let project = segment(&origin.project_id, "project ID")?;
    let similarity = segment(&origin.native_ids.similarity_id, "similarity ID")?;
    let scan_id = segment(&origin.scan_id, "scan ID")?;
    let before = read(client, origin).await?;
    if before != *expected {
        return Err(PublishError::new(
            "Provider baseline changed before mutation",
        ));
    }
    let rows = before["results"]
        .as_array()
        .ok_or_else(|| PublishError::new("Missing Checkmarx baseline results"))?;
    let expected_state = match action {
        ApprovedAction::FalsePositive { .. } => {
            if rows.iter().any(|r| r["state"] != "TO_VERIFY") {
                return Err(PublishError::new(
                    "Checkmarx false-positive publication would overwrite existing triage",
                ));
            }
            Some("NOT_EXPLOITABLE")
        }
        ApprovedAction::Confirmed { .. } => {
            if rows
                .iter()
                .any(|r| !matches!(r["state"].as_str(), Some("TO_VERIFY" | "CONFIRMED")))
            {
                return Err(PublishError::new(
                    "Checkmarx confirmation would overwrite existing triage",
                ));
            }
            Some("CONFIRMED")
        }
        ApprovedAction::Note { .. } => None,
    };
    let mut body = json!({"projectId":project,"scanId":scan_id,"comment":action.reason()});
    if let Some(state) = expected_state {
        body["state"] = json!(state);
    }
    if let ApprovedAction::Confirmed {
        severity: Some(severity),
        ..
    } = action
    {
        let severity = severity.to_ascii_uppercase();
        if !["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].contains(&severity.as_str()) {
            return Err(PublishError::new("Unsupported Checkmarx severity"));
        }
        body["severity"] = json!(severity);
    }
    let path = if before["grouping"]["groupingMode"] == "Attack Vector ID" {
        body["attackVectorId"] = json!(segment(
            &origin.native_ids.attack_vector_id,
            "attack vector ID"
        )?);
        body["filterBySimilarityId"] = json!(similarity);
        body["allowInconsistentStates"] = json!(false);
        "/api/sast-results-predicates/attack-vector"
    } else {
        body["similarityId"] = json!(similarity);
        "/api/sast-results-predicates/"
    };
    let response = client.send_once(Method::POST, path, &json!([body])).await?;
    let after = match read(client, origin).await {
        Ok(value) => value,
        Err(_) => {
            return Ok(WriteResult {
                status: WriteStatus::AcceptedUnverified,
                response: json!({"provider_response":response,"readback":"failed or still processing"}),
            })
        }
    };
    let state_ok = expected_state.is_none_or(|state| {
        after["results"]
            .as_array()
            .is_some_and(|rs| rs.iter().all(|r| r["state"] == state))
    });
    let severity_ok = match action {
        ApprovedAction::Confirmed {
            severity: Some(severity),
            ..
        } => after["results"].as_array().is_some_and(|rs| {
            rs.iter().all(|r| {
                r["severity"]
                    .as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case(severity))
            })
        }),
        _ => true,
    };
    let comment_ok = after["predicates"]["latestPredicatePerProject"]
        .as_array()
        .is_some_and(|ps| {
            ps.iter()
                .any(|p| p["comment"].as_str() == Some(action.reason()))
        });
    let grouping_ok = before["grouping"]["groupingMode"] == after["grouping"]["groupingMode"];
    let binding_ok = membership(&before) == membership(&after)
        && before["source_revision"] == after["source_revision"]
        && before["source_ref"] == after["source_ref"];
    Ok(WriteResult {
        status: if state_ok && severity_ok && comment_ok && grouping_ok && binding_ok {
            WriteStatus::Verified
        } else {
            WriteStatus::AcceptedUnverified
        },
        response: json!({"provider_response":response,"observed":after}),
    })
}

fn membership(snapshot: &Value) -> Vec<String> {
    let mut members: Vec<_> = snapshot["results"].as_array().into_iter().flatten()
        .map(|r| json!({"ID":r["ID"],"resultHash":r["resultHash"],"similarityID":r["similarityID"],"attackVectorID":r["attackVectorID"]}).to_string())
        .collect();
    members.sort();
    members
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publish::Auth;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use wiremock::matchers::{body_json, method, path, query_param};
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
            project_id: Some("p1".into()),
            scan_id: Some("s1".into()),
            git_ref: Some("main".into()),
            revision: Some("revision1".into()),
            ..Default::default()
        };
        o.native_ids.similarity_id = Some("42".into());
        o.native_ids.attack_vector_id = Some("1234567890abcdef".into());
        o
    }
    async fn fixtures(
        server: &MockServer,
        changed: Arc<AtomicBool>,
        action: &ApprovedAction,
        grouping: &str,
        initial_state: &str,
    ) {
        Mock::given(method("GET")).and(path("/api/scans/s1")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":"s1","projectId":"p1","status":"Completed","branch":"main","commitId":"revision1"}))).mount(server).await;
        let state = initial_state.to_string();
        let a = action.clone();
        let change = changed.clone();
        Mock::given(method("GET")).and(path("/api/sast-results")).and(query_param("similarity-id","42")).and(query_param("similarity-id-operation","EQUAL")).respond_with(move |_:&Request| {
            let changed=change.load(Ordering::SeqCst);
            let state=if changed {match a {ApprovedAction::FalsePositive{..}=>"NOT_EXPLOITABLE",ApprovedAction::Confirmed{..}=>"CONFIRMED",_=>&state}}else{&state};
            let severity=if changed {if let ApprovedAction::Confirmed{severity:Some(s),..}=&a{s.to_ascii_uppercase()}else{"HIGH".into()}}else{"HIGH".into()};
            ResponseTemplate::new(200).set_body_json(json!({"totalCount":1,"results":[{"similarityID":42,"attackVectorID":"1234567890abcdef","state":state,"severity":severity,"resultHash":"r1"}]}))
        }).mount(server).await;
        Mock::given(method("POST"))
            .and(path("/api/sast-results-predicates/predicates-status"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    json!({"isUpdatePredicatesRunning":false,"groupingMode":grouping}),
                ),
            )
            .mount(server)
            .await;
        Mock::given(method("GET")).and(path("/api/sast-results-predicates/42/latest")).and(query_param("project-ids","p1")).respond_with(move |_:&Request|ResponseTemplate::new(200).set_body_json(json!({"latestPredicatePerProject":if changed.load(Ordering::SeqCst){json!([{"projectId":"p1","similarityId":"42","comment":"approved reason"}])}else{json!([])},"totalCount":1}))).mount(server).await;
    }

    #[tokio::test]
    async fn native_predicates_write_and_verify_both_grouping_modes() {
        for grouping in ["Similarity ID", "Attack Vector ID"] {
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
            ] {
                let server = MockServer::start().await;
                let changed = Arc::new(AtomicBool::new(false));
                fixtures(&server, changed.clone(), &action, grouping, "TO_VERIFY").await;
                let mut body = json!({"projectId":"p1","scanId":"s1","comment":"approved reason"});
                match &action {
                    ApprovedAction::FalsePositive { .. } => {
                        body["state"] = json!("NOT_EXPLOITABLE")
                    }
                    ApprovedAction::Confirmed { .. } => {
                        body["state"] = json!("CONFIRMED");
                        body["severity"] = json!("LOW");
                    }
                    _ => {}
                }
                let endpoint = if grouping == "Attack Vector ID" {
                    body["attackVectorId"] = json!("1234567890abcdef");
                    body["filterBySimilarityId"] = json!("42");
                    body["allowInconsistentStates"] = json!(false);
                    "/api/sast-results-predicates/attack-vector"
                } else {
                    body["similarityId"] = json!("42");
                    "/api/sast-results-predicates/"
                };
                Mock::given(method("POST"))
                    .and(path(endpoint))
                    .and(body_json(json!([body])))
                    .respond_with(move |_: &Request| {
                        changed.store(true, Ordering::SeqCst);
                        ResponseTemplate::new(201)
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
                assert_eq!(result.status, WriteStatus::Verified);
            }
        }
    }

    #[tokio::test]
    async fn mutation_accepted_without_effect_remains_unverified() {
        let server = MockServer::start().await;
        let action = ApprovedAction::FalsePositive {
            reason: "approved reason".into(),
        };
        fixtures(
            &server,
            Arc::new(AtomicBool::new(false)),
            &action,
            "Similarity ID",
            "TO_VERIFY",
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/api/sast-results-predicates/"))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            write_approved(
                &PublishClient::test(server.uri(), Auth::Bearer("t".into())),
                &origin(),
                &action
            )
            .await
            .unwrap()
            .status,
            WriteStatus::AcceptedUnverified
        );
    }

    #[tokio::test]
    async fn human_confirmed_result_and_unknown_grouping_are_not_overridden() {
        for (group, state) in [
            ("Similarity ID", "CONFIRMED"),
            ("new grouping", "TO_VERIFY"),
        ] {
            let server = MockServer::start().await;
            let action = ApprovedAction::FalsePositive {
                reason: "approved reason".into(),
            };
            fixtures(
                &server,
                Arc::new(AtomicBool::new(false)),
                &action,
                group,
                state,
            )
            .await;
            assert!(write_approved(
                &PublishClient::test(server.uri(), Auth::Bearer("t".into())),
                &origin(),
                &action
            )
            .await
            .is_err());
            assert!(server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.url.path() != "/api/sast-results-predicates/"));
        }
    }

    #[tokio::test]
    async fn wrong_project_or_revision_fails_before_result_lookup() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/api/scans/s1")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":"s1","projectId":"p1","status":"Completed","branch":"main","commitId":"different"}))).expect(1).mount(&server).await;
        assert!(read(
            &PublishClient::test(server.uri(), Auth::Bearer("t".into())),
            &origin()
        )
        .await
        .unwrap_err()
        .message
        .contains("revision"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn mutation_server_failure_is_uncertain_and_never_retried() {
        let server = MockServer::start().await;
        let action = ApprovedAction::FalsePositive {
            reason: "approved reason".into(),
        };
        fixtures(
            &server,
            Arc::new(AtomicBool::new(false)),
            &action,
            "Similarity ID",
            "TO_VERIFY",
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/api/sast-results-predicates/"))
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
    fn unsafe_native_segments_cannot_change_request_routes() {
        for value in [
            "",
            "../other",
            "id?project-ids=other",
            "id/other",
            "id\\other",
        ] {
            assert!(segment(&Some(value.into()), "id").is_err());
        }
        assert_eq!(scalar(&json!(42)), Some("42".into()));
        assert_eq!(scalar(&json!(null)), None);
    }
    #[tokio::test]
    async fn changed_approved_baseline_is_rejected_before_mutation() {
        let server = MockServer::start().await;
        let action = ApprovedAction::FalsePositive {
            reason: "approved reason".into(),
        };
        fixtures(
            &server,
            Arc::new(AtomicBool::new(false)),
            &action,
            "Similarity ID",
            "TO_VERIFY",
        )
        .await;
        let client = PublishClient::test(server.uri(), Auth::Bearer("t".into()));
        let mut expected = read(&client, &origin()).await.unwrap();
        expected["reviewed_other_snapshot"] = json!(true);
        let error = write(&client, &origin(), &action, &expected)
            .await
            .unwrap_err();
        assert!(error.message.contains("baseline changed"));
        assert!(!error.uncertain);
    }

    #[test]
    fn membership_changes_are_distinct_from_expected_state_changes() {
        let before = json!({"results":[{"ID":"a","resultHash":"h","similarityID":42,"state":"TO_VERIFY","severity":"HIGH"}]});
        let mut after = before.clone();
        after["results"][0]["state"] = json!("NOT_EXPLOITABLE");
        assert_eq!(membership(&before), membership(&after));
        after["results"][0]["ID"] = json!("b");
        assert_ne!(membership(&before), membership(&after));
    }
    #[tokio::test]
    async fn attack_vector_busy_status_checks_the_attack_key() {
        let server = MockServer::start().await;
        let action = ApprovedAction::FalsePositive {
            reason: "approved reason".into(),
        };
        fixtures(
            &server,
            Arc::new(AtomicBool::new(false)),
            &action,
            "Attack Vector ID",
            "TO_VERIFY",
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/api/sast-results-predicates/predicates-status"))
            .and(body_json(
                json!({"scanID":"s1","similarResultsIDs":["1234567890abcdef"]}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"isUpdatePredicatesRunning":true,"groupingMode":"Attack Vector ID"}),
            ))
            .with_priority(1)
            .expect(1)
            .mount(&server)
            .await;
        let error = read(
            &PublishClient::test(server.uri(), Auth::Bearer("t".into())),
            &origin(),
        )
        .await
        .unwrap_err();
        assert!(error.message.contains("attack-vector update is running"));
    }
    #[tokio::test]
    async fn malformed_or_mismatched_contract_fields_refuse_baseline() {
        let good_scan = json!({"id":"s1","projectId":"p1","status":"Completed","branch":"main","commitId":"revision1"});
        let good_row =
            json!({"similarityID":42,"state":"TO_VERIFY","severity":"HIGH","resultHash":"r1"});
        let mut cases: Vec<(&str, Value, &str)> = Vec::new();
        for (field, value) in [
            ("id", "other"),
            ("projectId", "other"),
            ("status", "Running"),
            ("branch", "develop"),
        ] {
            let mut scan = good_scan.clone();
            scan[field] = json!(value);
            cases.push((
                "/api/scans/s1",
                scan,
                if field == "branch" {
                    "branch mismatch"
                } else {
                    "scan identity"
                },
            ));
        }
        cases.push(("/api/sast-results", json!({}), "lacks results"));
        cases.push((
            "/api/sast-results",
            json!({"results":[],"totalCount":0}),
            "bounded lookup",
        ));
        cases.push((
            "/api/sast-results",
            json!({"results":[good_row.clone()],"totalCount":2}),
            "bounded lookup",
        ));
        cases.push((
            "/api/sast-results",
            json!({"results":vec![good_row.clone();201],"totalCount":201}),
            "bounded lookup",
        ));
        for field in ["similarityID", "state", "severity"] {
            let mut row = good_row.clone();
            row[field] = Value::Null;
            cases.push((
                "/api/sast-results",
                json!({"results":[row],"totalCount":1}),
                "unmatched or incomplete",
            ));
        }
        for grouping in [
            json!({"isUpdatePredicatesRunning":true}),
            json!({"groupingMode":"Similarity ID"}),
        ] {
            cases.push((
                "/api/sast-results-predicates/predicates-status",
                grouping,
                "status is unknown",
            ));
        }
        cases.push((
            "/api/sast-results-predicates/42/latest",
            json!({}),
            "response is malformed",
        ));
        for predicate in [
            json!({"projectId":"other","similarityId":"42"}),
            json!({"projectId":"p1","similarityId":"other"}),
        ] {
            cases.push((
                "/api/sast-results-predicates/42/latest",
                json!({"latestPredicatePerProject":[predicate]}),
                "predicate identity mismatch",
            ));
        }
        for (endpoint, response, expected) in cases {
            let server = MockServer::start().await;
            fixtures(
                &server,
                Arc::new(AtomicBool::new(false)),
                &ApprovedAction::Note { reason: "r".into() },
                "Similarity ID",
                "TO_VERIFY",
            )
            .await;
            Mock::given(method(if endpoint.ends_with("predicates-status") {
                "POST"
            } else {
                "GET"
            }))
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
            assert!(
                error.message.contains(expected),
                "{endpoint}: {}",
                error.message
            );
            assert!(!error.uncertain);
        }
    }

    #[tokio::test]
    async fn attack_vector_validation_rejects_invalid_or_different_flows() {
        for attack in ["short", "zzzzzzzzzzzzzzzz", "0000000000000000"] {
            let server = MockServer::start().await;
            fixtures(
                &server,
                Arc::new(AtomicBool::new(false)),
                &ApprovedAction::Note { reason: "r".into() },
                "Attack Vector ID",
                "TO_VERIFY",
            )
            .await;
            let mut o = origin();
            o.native_ids.attack_vector_id = Some(attack.into());
            let error = read(
                &PublishClient::test(server.uri(), Auth::Bearer("t".into())),
                &o,
            )
            .await
            .unwrap_err();
            assert!(error.message.contains("inconsistent flows"));
        }
    }

    #[tokio::test]
    async fn absent_commit_is_not_invented_and_attack_alias_is_preserved() {
        let server = MockServer::start().await;
        fixtures(
            &server,
            Arc::new(AtomicBool::new(false)),
            &ApprovedAction::Note { reason: "r".into() },
            "Similarity ID",
            "TO_VERIFY",
        )
        .await;
        Mock::given(method("GET")).and(path("/api/scans/s1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":"s1","projectId":"p1","status":"Completed","branch":"main","commitTag":"v1","uploadUrl":"https://example.invalid/private?signature=secret"})))
            .with_priority(1).mount(&server).await;
        Mock::given(method("GET")).and(path("/api/sast-results"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"totalCount":1,"results":[{"similarityID":"42","attackVectorId":"1234567890abcdef","state":"TO_VERIFY","severity":"HIGH","resultHash":"r1"}]})))
            .with_priority(1).mount(&server).await;
        let baseline = read(
            &PublishClient::test(server.uri(), Auth::Bearer("t".into())),
            &origin(),
        )
        .await
        .unwrap();
        assert!(baseline["source_revision"].is_null());
        assert_eq!(baseline["scan"]["commitTag"], "v1");
        assert_eq!(baseline["results"][0]["attackVectorID"], "1234567890abcdef");
        assert!(!baseline.to_string().contains("signature"));
    }

    #[tokio::test]
    async fn confirmation_preserves_existing_triage_and_rejects_invalid_severity() {
        for (state, severity, expected) in [
            ("URGENT", None, "existing triage"),
            (
                "TO_VERIFY",
                Some("invalid"),
                "Unsupported Checkmarx severity",
            ),
        ] {
            let server = MockServer::start().await;
            let action = ApprovedAction::Confirmed {
                reason: "approved reason".into(),
                severity: severity.map(str::to_string),
            };
            fixtures(
                &server,
                Arc::new(AtomicBool::new(false)),
                &action,
                "Similarity ID",
                state,
            )
            .await;
            let error = write_approved(
                &PublishClient::test(server.uri(), Auth::Bearer("t".into())),
                &origin(),
                &action,
            )
            .await
            .unwrap_err();
            assert!(error.message.contains(expected));
            assert!(server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.url.path() != "/api/sast-results-predicates/"));
        }
    }

    #[tokio::test]
    async fn successful_mutation_with_failed_readback_is_not_reported_as_failure_or_verified() {
        let server = MockServer::start().await;
        let changed = Arc::new(AtomicBool::new(false));
        let action = ApprovedAction::FalsePositive {
            reason: "approved reason".into(),
        };
        fixtures(
            &server,
            changed.clone(),
            &action,
            "Similarity ID",
            "TO_VERIFY",
        )
        .await;
        let read_change = changed.clone();
        Mock::given(method("GET")).and(path("/api/scans/s1")).respond_with(move |_:&Request| {
            if read_change.load(Ordering::SeqCst) {ResponseTemplate::new(503)} else {
                ResponseTemplate::new(200).set_body_json(json!({"id":"s1","projectId":"p1","status":"Completed","branch":"main","commitId":"revision1"}))
            }
        }).with_priority(1).mount(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/sast-results-predicates/"))
            .respond_with(move |_: &Request| {
                changed.store(true, Ordering::SeqCst);
                ResponseTemplate::new(201)
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
        assert_eq!(result.response["readback"], "failed or still processing");
    }
}
