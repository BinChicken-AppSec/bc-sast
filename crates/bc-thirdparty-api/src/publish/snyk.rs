//! Snyk Code asset-scoped policies. Policy acceptance is not dashboard retesting.
use bc_model::ProviderOrigin;
use serde_json::{json, Value};

// Verified against the public 2026-03-25 schema. NotVulnerable data is unchanged;
// the newer schema expresses ignore types as a discriminated union.
const VERSION: &str = "2026-03-25";

fn validate_issue(issue: &Value, origin: &ProviderOrigin) -> Result<(), String> {
    let id = origin
        .native_ids
        .issue_id
        .as_deref()
        .ok_or("missing Snyk issue UUID")?;
    let key = origin
        .native_ids
        .asset_finding_id
        .as_deref()
        .ok_or("missing Snyk asset fingerprint")?;
    if issue["data"]["id"].as_str() != Some(id) {
        return Err("Snyk issue identity changed".into());
    }
    if issue["data"]["attributes"]["key_asset"].as_str() != Some(key) {
        return Err("Snyk asset fingerprint changed".into());
    }
    if issue["data"]["attributes"]["type"].as_str() != Some("code") {
        return Err("Snyk issue is not a Code finding".into());
    }
    if let Some(project) = origin.project_id.as_deref() {
        if issue["data"]["relationships"]["scan_item"]["data"]["id"].as_str() != Some(project)
            || issue["data"]["relationships"]["scan_item"]["data"]["type"] != "project"
        {
            return Err("Snyk project identity changed".into());
        }
    }
    if let Some(org) = origin.tenant_id.as_deref() {
        if issue["data"]["relationships"]["organization"]["data"]["id"].as_str() != Some(org) {
            return Err("Snyk organization identity changed".into());
        }
    }
    Ok(())
}

fn matches_asset(policy: &Value, key: &str) -> bool {
    policy["attributes"]["conditions_group"]["conditions"]
        .as_array()
        .is_some_and(|conditions| {
            conditions.iter().any(|c| {
                c["field"].as_str() == Some("snyk/asset/finding/v1")
                    && c["operator"].as_str() == Some("includes")
                    && c["value"].as_str() == Some(key)
            })
        })
}

fn exact_ignore(policy: &Value, key: &str) -> bool {
    let attributes = &policy["attributes"];
    attributes["action_type"] == "ignore"
        && attributes["conditions_group"]["logical_operator"] == "and"
        && attributes["conditions_group"]["conditions"]
            .as_array()
            .is_some_and(|c| c.len() == 1)
        && matches_asset(policy, key)
}

fn policy_status(policy: &Value) -> Result<&'static str, String> {
    match policy["data"]["attributes"]["review"].as_str() {
        Some("pending") => Ok("awaiting_approval"),
        Some("approved" | "not-required") => Ok("awaiting_provider_retest"),
        Some("rejected") => Ok("rejected"),
        _ => Err("Snyk policy review state missing or unsupported".into()),
    }
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
        .ok_or_else(|| PublishError::new("invalid Snyk resource identifier"))
}

pub(super) async fn read(
    client: &PublishClient,
    origin: &ProviderOrigin,
) -> Result<Value, PublishError> {
    let org = segment(origin.tenant_id.as_deref())?;
    let id = segment(origin.native_ids.issue_id.as_deref())?;
    let issue = client
        .get(&format!("/rest/orgs/{org}/issues/{id}?version={VERSION}"))
        .await?;
    validate_issue(&issue, origin).map_err(PublishError::new)?;
    let key = origin
        .native_ids
        .asset_finding_id
        .as_deref()
        .expect("validated key");
    let base_path = format!("/rest/orgs/{org}/policies");
    let mut path = format!("{base_path}?version={VERSION}&limit=100");
    let mut policies = Vec::new();
    let mut visited = std::collections::BTreeSet::new();
    for _ in 0..100 {
        if !visited.insert(path.clone()) {
            return Err(PublishError::new("Snyk policy pagination loop"));
        }
        let page = client.get(&path).await?;
        let data = page["data"]
            .as_array()
            .ok_or_else(|| PublishError::new("Snyk policy inventory missing data array"))?;
        if data.len() > 100 {
            return Err(PublishError::new(
                "Snyk policy page exceeded requested bound",
            ));
        }
        policies.extend(data.iter().filter(|p| matches_asset(p, key)).cloned());
        let next = &page["links"]["next"];
        if next.is_null() || next.as_str() == Some("") {
            policies.sort_by_key(|p| p["id"].as_str().unwrap_or_default().to_owned());
            // Preserve issue data including coordinates and current suppression state.
            let commits: std::collections::BTreeSet<_> = issue["data"]["attributes"]["coordinates"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|c| c["representations"].as_array().into_iter().flatten())
                .filter_map(|r| r["sourceLocation"]["commit_id"].as_str())
                .filter(|s| !s.is_empty())
                .collect();
            if commits.len() > 1 {
                return Err(PublishError::new(
                    "Snyk issue has conflicting source revisions",
                ));
            }
            let source_revision = commits.first().copied();
            return Ok(
                json!({"issue":issue["data"],"policies":policies,"source_revision":source_revision}),
            );
        }
        let href = next
            .as_str()
            .or_else(|| next["href"].as_str())
            .ok_or_else(|| PublishError::new("malformed Snyk next link"))?;
        // Extract only the opaque cursor; never follow a provider-supplied host/path.
        let url = reqwest::Url::parse("https://query.invalid/")
            .expect("constant URL")
            .join(href)
            .map_err(|_| PublishError::new("invalid Snyk next link"))?;
        let cursor = url
            .query_pairs()
            .find(|(k, _)| k == "starting_after")
            .map(|(_, v)| v.into_owned())
            .filter(|s| !s.is_empty() && s.len() <= 4096)
            .ok_or_else(|| PublishError::new("Snyk next link missing bounded cursor"))?;
        let mut query = reqwest::Url::parse("https://query.invalid/").expect("constant URL");
        query
            .query_pairs_mut()
            .append_pair("version", VERSION)
            .append_pair("limit", "100")
            .append_pair("starting_after", &cursor);
        path = format!("{base_path}?{}", query.query().unwrap_or_default());
    }
    Err(PublishError::new("Snyk policy pagination cap reached"))
}

pub(super) async fn write(
    client: &PublishClient,
    origin: &ProviderOrigin,
    action: &ApprovedAction,
    expected: &Value,
) -> Result<WriteResult, PublishError> {
    if !matches!(action, ApprovedAction::FalsePositive { .. }) {
        return Err(PublishError::new(
            "Snyk Code supports only false-positive ignore publication",
        ));
    }
    let org = segment(origin.tenant_id.as_deref())?;
    let key = origin
        .native_ids
        .asset_finding_id
        .as_deref()
        .filter(|s| !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control))
        .ok_or_else(|| PublishError::new("missing or invalid Snyk asset fingerprint"))?;
    if action.reason().is_empty() || action.reason().chars().count() > 10000 {
        return Err(PublishError::new(
            "Snyk reason must contain 1 to 10000 characters",
        ));
    }
    let before = read(client, origin).await?;
    if &before != expected {
        return Err(PublishError::new(
            "Provider baseline changed before mutation",
        ));
    }
    // An ignore can come from a group policy or legacy rule absent from the
    // exact org-policy list. Never overlay an existing human suppression.
    let issue = &before["issue"];
    if issue["attributes"]["status"].as_str() != Some("open")
        || issue["attributes"]["ignored"].as_bool() != Some(false)
        || !issue["relationships"]["ignore"].is_null()
    {
        return Err(PublishError::new(
            "Snyk issue has existing triage or incomplete current state",
        ));
    }
    if before["policies"].as_array().is_none_or(|p| !p.is_empty()) {
        return Err(PublishError::new(
            "existing Snyk asset policy requires reconciliation; refusing duplicate ignore",
        ));
    }
    let body = json!({"data":{"type":"policy","attributes":{"name":"BC SAST verified assessment","source":"api","conditions_group":{"logical_operator":"and","conditions":[{"field":"snyk/asset/finding/v1","operator":"includes","value":key}]},"action_type":"ignore","action":{"data":{"ignore_type":"not-vulnerable","reason":action.reason()}}}}});
    let response = client
        .send_once(
            Method::POST,
            &format!("/rest/orgs/{org}/policies?version={VERSION}"),
            &body,
        )
        .await?;
    let policy_id = match segment(response["data"]["id"].as_str()) {
        Ok(id) => id,
        Err(_) => {
            return Ok(WriteResult {
                status: WriteStatus::AcceptedUnverified,
                response: json!({"mutation":response,"readback_error":"created policy identity missing or invalid"}),
            });
        }
    };
    let after = match client
        .get(&format!(
            "/rest/orgs/{org}/policies/{policy_id}?version={VERSION}"
        ))
        .await
    {
        Ok(after) => after,
        Err(error) => {
            return Ok(WriteResult {
                status: WriteStatus::AcceptedUnverified,
                response: json!({"mutation":response,"readback_error":error.message}),
            });
        }
    };
    let status = if after["data"]["id"].as_str() != Some(policy_id)
        || !exact_ignore(&after["data"], key)
        || after["data"]["attributes"]["action"]["data"]["reason"] != action.reason()
        || after["data"]["attributes"]["action"]["data"]["ignore_type"] != "not-vulnerable"
    {
        WriteStatus::AcceptedUnverified
    } else {
        match policy_status(&after).as_deref() {
            Ok("awaiting_approval") => WriteStatus::PendingApproval,
            Ok("awaiting_provider_retest") => WriteStatus::AwaitingRetest,
            _ => WriteStatus::AcceptedUnverified,
        }
    };
    Ok(WriteResult {
        status,
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
        let expected = if matches!(action, ApprovedAction::FalsePositive { .. }) {
            read(client, origin).await?
        } else {
            Value::Null
        };
        super::write(client, origin, action, &expected).await
    }

    use super::super::Auth;
    use super::*;
    use bc_model::ProviderNativeIds;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    fn origin() -> ProviderOrigin {
        ProviderOrigin {
            tenant_id: Some("org".into()),
            native_ids: ProviderNativeIds {
                issue_id: Some("issue".into()),
                asset_finding_id: Some("asset".into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }
    fn issue() -> Value {
        json!({"data":{"id":"issue","relationships":{"organization":{"data":{"id":"org"}}},"attributes":{"type":"code","key_asset":"asset","status":"open","ignored":false}}})
    }
    fn policy(review: &str) -> Value {
        json!({"data":{"id":"policy","attributes":{"review":review,"action_type":"ignore","conditions_group":{"logical_operator":"and","conditions":[{"field":"snyk/asset/finding/v1","operator":"includes","value":"asset"}]},"action":{"data":{"ignore_type":"not-vulnerable","reason":"checked"}}}}})
    }
    async fn baseline(server: &MockServer, policies: Value) {
        Mock::given(method("GET"))
            .and(path("/rest/orgs/org/issues/issue"))
            .and(header("Authorization", "token secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(issue()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/rest/orgs/org/policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":policies})))
            .mount(server)
            .await;
    }
    #[tokio::test]
    async fn creates_exact_asset_ignore_and_reports_pending_approval() {
        let server = MockServer::start().await;
        baseline(&server, json!([])).await;
        Mock::given(method("POST"))
            .and(path("/rest/orgs/org/policies"))
            .and(body_partial_json(
                json!({"data":{"type":"policy","attributes":{"action_type":"ignore"}}}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(policy("pending")))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/rest/orgs/org/policies/policy"))
            .respond_with(ResponseTemplate::new(200).set_body_json(policy("pending")))
            .mount(&server)
            .await;
        let client = PublishClient::test(server.uri(), Auth::Token("secret".into()));
        let result = write(
            &client,
            &origin(),
            &ApprovedAction::FalsePositive {
                reason: "checked".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(result.status, WriteStatus::PendingApproval);
    }
    #[tokio::test]
    async fn existing_policy_refuses_duplicate_creation() {
        let server = MockServer::start().await;
        baseline(&server, json!([policy("approved")["data"]])).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let client = PublishClient::test(server.uri(), Auth::Token("secret".into()));
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
        .contains("duplicate"));
    }
    #[test]
    fn policy_approval_is_not_proof_of_dashboard_retest() {
        assert_eq!(
            policy_status(&policy("approved")).unwrap(),
            "awaiting_provider_retest"
        );
        assert_eq!(
            policy_status(&policy("not-required")).unwrap(),
            "awaiting_provider_retest"
        );
        assert_eq!(policy_status(&policy("rejected")).unwrap(), "rejected");
        assert!(policy_status(&policy("unknown")).is_err());
        let mut wrong = issue();
        wrong["data"]["attributes"]["key_asset"] = json!("other");
        assert!(validate_issue(&wrong, &origin()).is_err());
    }
    #[tokio::test]
    async fn accepted_policy_with_failed_readback_is_not_reported_closed() {
        let server = MockServer::start().await;
        baseline(&server, json!([])).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201).set_body_json(policy("approved")))
            .expect(1)
            .mount(&server)
            .await;
        let client = PublishClient::test(server.uri(), Auth::Token("secret".into()));
        let result = write(
            &client,
            &origin(),
            &ApprovedAction::FalsePositive {
                reason: "checked".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(result.status, WriteStatus::AcceptedUnverified);
        assert!(result.response["readback_error"].is_string());
    }
    #[tokio::test]
    async fn unsupported_snyk_actions_never_send() {
        let server = MockServer::start().await;
        let client = PublishClient::test(server.uri(), Auth::Token("secret".into()));
        assert!(write(
            &client,
            &origin(),
            &ApprovedAction::Note {
                reason: "checked".into()
            }
        )
        .await
        .is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
    }
    #[test]
    fn readback_rejects_broader_or_different_policy_conditions() {
        let mut p = policy("approved");
        assert!(exact_ignore(&p["data"], "asset"));
        p["data"]["attributes"]["conditions_group"]["logical_operator"] = json!("or");
        assert!(!exact_ignore(&p["data"], "asset"));
        p = policy("approved");
        p["data"]["attributes"]["action_type"] = json!("annotation");
        assert!(!exact_ignore(&p["data"], "asset"));
        p = policy("approved");
        let extra = p["data"]["attributes"]["conditions_group"]["conditions"][0].clone();
        p["data"]["attributes"]["conditions_group"]["conditions"]
            .as_array_mut()
            .unwrap()
            .push(extra);
        assert!(!exact_ignore(&p["data"], "asset"));
    }
    #[tokio::test]
    async fn changed_prewrite_baseline_refuses_all_mutations() {
        let server = MockServer::start().await;
        baseline(&server, json!([])).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let client = PublishClient::test(server.uri(), Auth::Token("secret".into()));
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
    #[tokio::test]
    async fn existing_suppression_or_resolution_blocks_even_without_org_policy() {
        for variant in 0..5 {
            let server = MockServer::start().await;
            let mut current = issue();
            match variant {
                0 => current["data"]["attributes"]["ignored"] = json!(true),
                1 => current["data"]["attributes"]["status"] = json!("resolved"),
                2 => {
                    current["data"]["relationships"]["ignore"] =
                        json!({"data":{"id":"legacy-ignore","type":"ignore"}})
                }
                3 => current["data"]["attributes"]["ignored"] = Value::Null,
                _ => current["data"]["attributes"]["status"] = Value::Null,
            }
            Mock::given(method("GET"))
                .and(path("/rest/orgs/org/issues/issue"))
                .respond_with(ResponseTemplate::new(200).set_body_json(current))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/rest/orgs/org/policies"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":[]})))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
            let client = PublishClient::test(server.uri(), Auth::Token("secret".into()));
            let error = write(
                &client,
                &origin(),
                &ApprovedAction::FalsePositive {
                    reason: "checked".into(),
                },
            )
            .await
            .unwrap_err();
            assert!(error.message.contains("existing triage"));
        }
    }

    #[test]
    fn native_issue_binding_checks_id_product_project_and_org() {
        let mut o = origin();
        o.native_ids.issue_id = None;
        assert!(validate_issue(&issue(), &o).is_err());
        o = origin();
        o.native_ids.asset_finding_id = None;
        assert!(validate_issue(&issue(), &o).is_err());
        o = origin();
        o.native_ids.issue_id = Some("other".into());
        assert!(validate_issue(&issue(), &o).is_err());
        let mut f = issue();
        f["data"]["attributes"]["type"] = json!("package_vulnerability");
        assert!(validate_issue(&f, &origin()).is_err());
        o = origin();
        o.project_id = Some("project".into());
        assert!(validate_issue(&issue(), &o).is_err());
        f = issue();
        f["data"]["relationships"]["scan_item"] = json!({"data":{"id":"project","type":"project"}});
        assert!(validate_issue(&f, &o).is_ok());
        o = origin();
        o.tenant_id = Some("other".into());
        assert!(validate_issue(&issue(), &o).is_err());
        o.tenant_id = None;
        assert!(validate_issue(&issue(), &o).is_ok());
    }
    #[tokio::test]
    async fn pagination_refuses_malformed_oversized_looping_or_unbounded_results() {
        for variant in 0..7 {
            let server = MockServer::start().await;
            baseline(&server, json!([])).await;
            let count = std::sync::atomic::AtomicUsize::new(0);
            Mock::given(method("GET")).and(path("/rest/orgs/org/policies"))
                .respond_with(move |_:&wiremock::Request| {
                    let number=count.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
                    let response=match variant {
                        0=>json!({}),
                        1=>json!({"data":vec![Value::Null;101]}),
                        2=>json!({"data":[],"links":{"next":false}}),
                        3=>json!({"data":[],"links":{"next":"http://["}}),
                        4=>json!({"data":[],"links":{"next":"/policies?unknown=x"}}),
                        5=>json!({"data":[],"links":{"next":"/policies?starting_after=same"}}),
                        _=>json!({"data":[],"links":{"next":format!("/policies?starting_after={number}")}}),
                    };
                    ResponseTemplate::new(200).set_body_json(response)
                }).with_priority(1).mount(&server).await;
            let client = PublishClient::test(server.uri(), Auth::Token("secret".into()));
            let message = read(&client, &origin()).await.unwrap_err().message;
            assert!(message.contains(match variant {
                0 => "array",
                1 => "bound",
                2 => "malformed",
                3 => "invalid",
                4 => "cursor",
                5 => "loop",
                _ => "cap",
            }));
        }
    }
    #[tokio::test]
    async fn cursor_never_routes_credentials_to_supplied_host_and_revision_is_preserved() {
        let server = MockServer::start().await;
        baseline(&server, json!([])).await;
        let mut current = issue();
        current["data"]["attributes"]["coordinates"] =
            json!([{"representations":[{"sourceLocation":{"commit_id":"revision"}}]}]);
        Mock::given(method("GET"))
            .and(path("/rest/orgs/org/issues/issue"))
            .respond_with(ResponseTemplate::new(200).set_body_json(current.clone()))
            .with_priority(2)
            .mount(&server)
            .await;
        Mock::given(method("GET")).and(path("/rest/orgs/org/policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":[policy("pending")["data"]],"links":{"next":{"href":"https://evil.invalid/other?starting_after=cursor"}}}))).with_priority(2).up_to_n_times(1).mount(&server).await;
        let client = PublishClient::test(server.uri(), Auth::Token("secret".into()));
        let result = read(&client, &origin()).await.unwrap();
        assert_eq!(result["source_revision"], "revision");
        assert_eq!(result["policies"].as_array().unwrap().len(), 1);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[2]
            .url
            .query_pairs()
            .any(|(k, v)| k == "starting_after" && v == "cursor"));
        current["data"]["attributes"]["coordinates"][0]["representations"]
            .as_array_mut()
            .unwrap()
            .push(json!({"sourceLocation":{"commit_id":"different"}}));
        Mock::given(method("GET"))
            .and(path("/rest/orgs/org/issues/issue"))
            .respond_with(ResponseTemplate::new(200).set_body_json(current))
            .with_priority(1)
            .mount(&server)
            .await;
        assert!(read(&client, &origin())
            .await
            .unwrap_err()
            .message
            .contains("conflicting source"));
    }
    #[tokio::test]
    async fn invalid_reason_or_asset_prevents_any_request() {
        let server = MockServer::start().await;
        let client = PublishClient::test(server.uri(), Auth::Token("secret".into()));
        for reason in [String::new(), "x".repeat(10001)] {
            assert!(super::write(
                &client,
                &origin(),
                &ApprovedAction::FalsePositive { reason },
                &Value::Null
            )
            .await
            .is_err());
        }
        let mut o = origin();
        o.native_ids.asset_finding_id = Some("bad\nkey".into());
        assert!(super::write(
            &client,
            &o,
            &ApprovedAction::FalsePositive {
                reason: "checked".into()
            },
            &Value::Null
        )
        .await
        .is_err());
        o = origin();
        o.tenant_id = Some("../other".into());
        assert!(read(&client, &o).await.is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
    }
    #[tokio::test]
    async fn accepted_policy_response_states_are_reported_conservatively() {
        for variant in 0..4 {
            let server = MockServer::start().await;
            baseline(&server, json!([])).await;
            let response = if variant == 0 {
                json!({"data":{}})
            } else {
                policy("approved")
            };
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(201).set_body_json(response))
                .expect(1)
                .mount(&server)
                .await;
            let mut after = policy(if variant == 3 { "rejected" } else { "approved" });
            if variant == 2 {
                after["data"]["attributes"]["action"]["data"]["reason"] = json!("human edited");
            }
            Mock::given(method("GET"))
                .and(path("/rest/orgs/org/policies/policy"))
                .respond_with(ResponseTemplate::new(200).set_body_json(after))
                .mount(&server)
                .await;
            let client = PublishClient::test(server.uri(), Auth::Token("secret".into()));
            let result = write(
                &client,
                &origin(),
                &ApprovedAction::FalsePositive {
                    reason: "checked".into(),
                },
            )
            .await
            .unwrap();
            assert_eq!(
                result.status,
                if variant == 1 {
                    WriteStatus::AwaitingRetest
                } else {
                    WriteStatus::AcceptedUnverified
                }
            );
        }
    }
}
