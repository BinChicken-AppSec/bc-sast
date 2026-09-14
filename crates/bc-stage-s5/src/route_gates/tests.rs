//! Every case here is either a 2026-09-07 field false positive the gate
//! exists to kill — reproduced with the four apps' real route tables,
//! real handler signatures and the exact entry points a probe read back
//! out of `bc_callgraph::evidence::emit_framework_entry_points` — or the
//! shape next door that it must NOT kill.

use super::*;
use bc_model::VulnClass;
use tempfile::TempDir;

// ── the four apps, as they are actually written ─────────────────────

const LARAVEL_ROUTES: &str = r#"<?php

use App\Http\Controllers\OpsConsoleController;
use App\Http\Controllers\ReportController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Portal routes
|--------------------------------------------------------------------------
|
| The report finder is open to anyone on the corporate network; everything
| that touches the export store or the job runner sits behind the session
| guard.
|
*/

Route::get('/reports/search', [ReportController::class, 'search'])->name('reports.search');

Route::middleware(['auth'])->group(function () {
    Route::get('/reports/export', [ReportController::class, 'export'])->name('reports.export');
    Route::get('/directory/lookup', [ReportController::class, 'lookupMember'])->name('directory.lookup');
    Route::get('/ops/console', [OpsConsoleController::class, 'index'])->name('ops.console');
    Route::post('/ops/maintenance', [OpsConsoleController::class, 'runMaintenance'])->name('ops.maintenance');
});
"#;

const LARAVEL_OPS_CONTROLLER: &str = r#"<?php

namespace App\Http\Controllers;

use App\Services\ReportingService;

class OpsConsoleController extends Controller
{
    public function __construct(private ReportingService $reporting)
    {
    }

    public function index(): View
    {
        return view('ops.console');
    }

    /**
     * Kicks off one of the nightly housekeeping jobs on demand.
     */
    public function runMaintenance(Request $request): JsonResponse
    {
        $jobTarget = (string) $request->input('target');
        $window = (string) $request->input('window', 'nightly');

        $output = $this->reporting->triggerMaintenance($jobTarget, $window);

        return response()->json(['output' => $output]);
    }
}
"#;

const LARAVEL_REPORT_CONTROLLER: &str = r#"<?php

namespace App\Http\Controllers;

class ReportController extends Controller
{
    /**
     * Report finder used by the portal landing page.
     */
    public function search(Request $request): JsonResponse
    {
        $titleFragment = (string) $request->query('q', '');
        $team = (string) $request->query('team', 'all');

        $results = $this->reporting->findReportsByTitle($titleFragment, $team);

        return response()->json(['results' => $results]);
    }
}
"#;

const LARAVEL_SERVICE: &str = r#"<?php

namespace App\Services;

class ReportingService
{
    public function triggerMaintenance(string $target, string $window): string
    {
        return shell_exec("/usr/local/bin/housekeeping --target={$target} --window={$window}");
    }
}
"#;

const KTOR_OPS_ROUTES: &str = r#"package com.internal.opsportal.routes

import io.ktor.server.auth.*
import io.ktor.server.routing.*

suspend fun rebuildSearchIndex(call: ApplicationCall, service: ReportService) {
    val scope = call.request.queryParameters["scope"] ?: "all"
    call.respondText(service.rebuildIndex(scope))
}

/**
 * Accepts a serialized console snapshot produced by the desktop ops client and
 * folds it back into the running portal state.
 */
suspend fun restoreConsoleSnapshot(call: ApplicationCall, service: ReportService) {
    val snapshotBytes = call.receive<ByteArray>()
    val summary = service.restoreSnapshot(snapshotBytes)

    call.respondText(summary)
}

fun Route.opsRoutes(service: ReportService) {
    authenticate("auth-session") {
        post("/ops/reindex") {
            rebuildSearchIndex(call, service)
        }

        post("/ops/snapshot/restore") {
            restoreConsoleSnapshot(call, service)
        }
    }
}
"#;

const KTOR_REPORT_ROUTES: &str = r#"package com.internal.opsportal.routes

import io.ktor.server.auth.*
import io.ktor.server.routing.*

suspend fun searchReports(call: ApplicationCall, service: ReportService) {
    val ownerFragment = call.request.queryParameters["owner"] ?: ""
    call.respondText(service.searchReports(ownerFragment).joinToString("\n"))
}

/** Full listing for one owner mailbox. */
suspend fun listOwnedReports(call: ApplicationCall, service: ReportService) {
    val ownerEmail = call.request.queryParameters["owner_email"] ?: ""
    call.respondText(service.reportsOwnedBy(ownerEmail).joinToString("\n"))
}

fun Route.reportRoutes(service: ReportService) {
    get("/reports/search") {
        searchReports(call, service)
    }

    authenticate("auth-session") {
        get("/reports") {
            listOwnedReports(call, service)
        }
    }
}
"#;

const RAILS_ROUTES: &str = r#"Rails.application.routes.draw do
  # Portal surface used by the reporting UI.
  get '/reports/search' => 'reports#search', as: :report_search
  get '/reports' => 'reports#index', as: :reports
  get '/reports/:id/download' => 'reports#download', as: :report_download

  # Operator console. Everything under here is admin-only.
  post '/ops/reindex' => 'ops#reindex', as: :ops_reindex
  get '/ops/summary' => 'ops#summary', as: :ops_summary
end
"#;

const RAILS_REPORTS_CONTROLLER: &str = r#"class ReportsController < ApplicationController
  before_action :authenticate_user!, except: [:search]

  # Type-ahead endpoint for the portal search box. Deliberately open so the
  # public status page can render owner suggestions without a session.
  def search
    owner_fragment = params[:owner].to_s
    matches = ReportService.matching_reports(owner_fragment)

    render json: { query: owner_fragment, count: matches.size }
  end

  # Full listing for a single owner mailbox.
  def index
    owner_email = params[:owner_email].to_s
    reports = ReportService.reports_for_owner(owner_email)

    render json: { owner_email: owner_email, count: reports.size }
  end

  # Streams a previously generated PDF/CSV bundle out of the archive volume.
  def download
    archive_name = params[:archive].to_s
    payload = ReportService.attachment_payload(params[:id], archive_name)

    send_data payload, filename: archive_name, disposition: 'attachment'
  end
end
"#;

const AXUM_MAIN: &str = r#"mod handlers;
mod service;
mod store;

use axum::middleware::{self, Next};
use axum::routing::{get, post};
use axum::Router;

/// Operator console calls carry a shared token issued by the platform team.
async fn require_operator_token(req: Request, next: Next) -> Result<Response, StatusCode> {
    let expected = std::env::var("REPORTD_OPERATOR_TOKEN").unwrap_or_default();
    let presented = req
        .headers()
        .get("x-operator-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    if expected.is_empty() || presented != expected {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(req).await)
}

fn build_router(state: AppState) -> Router {
    let operator_routes = Router::new()
        .route("/admin/reports/:slug/export", get(handlers::export_report))
        .route("/admin/jobs/rebuild", post(handlers::rebuild_index))
        .route("/admin/reports/:slug/frame", get(handlers::read_frame))
        .route_layer(middleware::from_fn(require_operator_token));

    Router::new()
        .route("/reports/search", get(handlers::search_reports))
        .merge(operator_routes)
        .with_state(state)
}
"#;

const AXUM_HANDLERS: &str = r#"use axum::extract::{Path, Query, State};

/// Team-scoped report listing used by the reporting dashboard.
pub async fn search_reports(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    let team = params.team.trim().to_string();

    match service::search_by_team(&state, &team, "created_at", None) {
        Ok(rows) => (StatusCode::OK, Json(SearchResponse { rows })).into_response(),
        Err(err) => (StatusCode::BAD_GATEWAY, err.to_string()).into_response(),
    }
}

/// Streams a previously generated export bundle straight off the spool.
pub async fn export_report(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(params): Query<ExportParams>,
) -> impl IntoResponse {
    let requested = slug.trim().to_string();
    let format = params.format.unwrap_or_else(|| "csv".to_string());

    match service::load_export_bundle(&state, &requested, &format) {
        Ok(body) => (StatusCode::OK, body).into_response(),
        Err(err) => (StatusCode::NOT_FOUND, err.to_string()).into_response(),
    }
}
"#;

// ── fixtures ────────────────────────────────────────────────────────

/// A repo on disk with `files` written into it. The gate reads real
/// lines, so every case needs one.
fn repo(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    for (rel, body) in files {
        let path = dir.path().join(rel);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, body).expect("write");
    }
    dir
}

fn ep(file: &str, function: &str, reachable_from_unauth: bool) -> EntryPoint {
    EntryPoint {
        file: file.to_string(),
        function: function.to_string(),
        kind: EntryPointKind::Framework,
        reachable_from_unauth,
    }
}

/// A "this handler has no authorization check" finding, the shape S4
/// raised in every one of the four field cases.
fn missing_authz(file: &str, line_start: i64, line_end: i64) -> Finding {
    Finding {
        provider_origins: Vec::new(),
        chunk_id: "c".to_string(),
        file: file.to_string(),
        line_start,
        line_end,
        vuln_class: VulnClass::LogicFlaw,
        cwe: Some("CWE-862".to_string()),
        title: "Missing Authorization Check".to_string(),
        impact: String::new(),
        description: "The handler performs no authorization check before acting on the request."
            .to_string(),
        exploit_scenario: String::new(),
        preconditions: Vec::new(),
        recommendation: String::new(),
        code_snippet: String::new(),
        source_ref: None,
        sink_ref: None,
        backfilled_refs: Vec::new(),
        reanchored: Vec::new(),
        compliance_requirements: Vec::new(),
        confidence: 0.9,
        votes: 1,
        duplicates: Vec::new(),
        verdict: None,
        verdict_confidence: None,
        verdict_reason: String::new(),
        cvss_vector: None,
        cvss_score: None,
        cvss_rating: None,
        verifier_reasoning: String::new(),
        vsvs_vector: None,
        vsvs_score: None,
        vsvs_rating: None,
        offensive_priority: None,
        offensive_reason: String::new(),
        related_cwes: Vec::new(),
    }
}

fn verdict(dir: &TempDir, f: &Finding, eps: &[EntryPoint]) -> Option<String> {
    let routes = RouteIndex::new(eps);
    guarded_route(f, &routes, Some(dir.path()))
}

// ── the four field cases ────────────────────────────────────────────

/// php-laravel: `OpsConsoleController::runMaintenance` sits in a
/// `Route::middleware(['auth'])->group(…)`. The entry point that knows
/// that is in `routes/web.php`, two directories away from the finding.
#[test]
fn laravel_a_handler_inside_an_auth_middleware_group_is_dropped() {
    let dir = repo(&[
        ("routes/web.php", LARAVEL_ROUTES),
        (
            "app/Http/Controllers/OpsConsoleController.php",
            LARAVEL_OPS_CONTROLLER,
        ),
    ]);
    let eps = [
        ep("routes/web.php", "ReportController@search", true),
        ep("routes/web.php", "ReportController@export", false),
        ep("routes/web.php", "ReportController@lookupMember", false),
        ep("routes/web.php", "OpsConsoleController@index", false),
        ep(
            "routes/web.php",
            "OpsConsoleController@runMaintenance",
            false,
        ),
    ];
    let f = missing_authz("app/Http/Controllers/OpsConsoleController.php", 21, 26);
    let reason = verdict(&dir, &f, &eps).expect("dropped");
    assert!(
        reason.contains("route is guarded by the framework"),
        "{reason}"
    );
    assert!(reason.contains("middleware('auth')"), "{reason}");
    assert!(reason.contains("need a bypass, none claimed"), "{reason}");
}

/// kotlin-ktor: `restoreConsoleSnapshot` is reached only from inside
/// `authenticate("auth-session")`, and its route lambda does nothing but
/// call it — so S0 names the entry point after the handler and rule 1
/// matches the finding to its own route directly.
#[test]
fn ktor_a_handler_reached_only_from_an_authenticate_block_is_dropped() {
    let dir = repo(&[("src/routes/OpsRoutes.kt", KTOR_OPS_ROUTES)]);
    let f = missing_authz("src/routes/OpsRoutes.kt", 15, 19);
    let reason = verdict(&dir, &f, &ktor_ops_eps()).expect("dropped");
    assert!(
        reason.contains(r#"authenticate("auth-session")"#),
        "{reason}"
    );
}

/// The whole-file rule, with source on disk: a finding raised on the
/// route table itself (`fun Route.opsRoutes`) is inside no handler and
/// names none on its own lines, so nothing matches by name or by line —
/// and it is dropped only because every route the file declares is
/// guarded.
#[test]
fn ktor_a_finding_on_a_fully_guarded_route_table_falls_to_the_whole_file_rule() {
    let dir = repo(&[("src/routes/OpsRoutes.kt", KTOR_OPS_ROUTES)]);
    let f = missing_authz("src/routes/OpsRoutes.kt", 22, 23);
    assert!(verdict(&dir, &f, &ktor_ops_eps()).is_some());
}

/// ruby-rails: the route is in `config/routes.rb`, the guard in the
/// controller, and the entry point id (`reports#index`) names neither
/// file — the controller half has to be matched against the file name.
#[test]
fn rails_actions_behind_a_before_action_filter_are_dropped() {
    let dir = repo(&[
        ("config/routes.rb", RAILS_ROUTES),
        (
            "app/controllers/reports_controller.rb",
            RAILS_REPORTS_CONTROLLER,
        ),
    ]);
    let eps = rails_eps();
    for (lo, hi) in [(15, 20), (23, 28)] {
        let f = missing_authz("app/controllers/reports_controller.rb", lo, hi);
        let reason = verdict(&dir, &f, &eps).expect("dropped");
        assert!(
            reason.contains("before_action :authenticate_user!"),
            "{reason}"
        );
    }
}

/// rust-axum: the route table and its `.route_layer(middleware::from_fn(
/// require_operator_token))` are in `main.rs`; the handler bodies are in
/// `handlers.rs`. The entry point id is the bare handler name, so the
/// enclosing-function match carries this one.
#[test]
fn axum_a_handler_behind_a_route_layer_is_dropped() {
    let dir = repo(&[
        ("src/main.rs", AXUM_MAIN),
        ("src/handlers.rs", AXUM_HANDLERS),
    ]);
    let eps = axum_eps();
    let f = missing_authz("src/handlers.rs", 22, 28);
    let reason = verdict(&dir, &f, &eps).expect("dropped");
    assert!(
        reason.contains("middleware::from_fn(require_operator_token)"),
        "{reason}"
    );
}

fn rails_eps() -> [EntryPoint; 5] {
    [
        ep("config/routes.rb", "reports#search", true),
        ep("config/routes.rb", "reports#index", false),
        ep("config/routes.rb", "reports#download", false),
        ep("config/routes.rb", "ops#reindex", false),
        ep("config/routes.rb", "ops#summary", false),
    ]
}

/// Both of `OpsRoutes.kt`'s lambdas are plain delegations to a
/// uniquely-named `suspend fun`, so `bc_callgraph`'s Kotlin section
/// names the entry points after the handlers rather than after the
/// paths.
fn ktor_ops_eps() -> [EntryPoint; 2] {
    [
        ep("src/routes/OpsRoutes.kt", "rebuildSearchIndex", false),
        ep("src/routes/OpsRoutes.kt", "restoreConsoleSnapshot", false),
    ]
}

fn axum_eps() -> [EntryPoint; 4] {
    [
        ep("src/main.rs", "export_report", false),
        ep("src/main.rs", "rebuild_index", false),
        ep("src/main.rs", "read_frame", false),
        ep("src/main.rs", "search_reports", true),
    ]
}

// ── route-table anchors ─────────────────────────────────────────────

/// A finding anchored on the route table itself is a finding about the
/// route that line declares — and the line decides it, not the file:
/// `main.rs:29` declares a guarded route, `main.rs:35` the open one.
#[test]
fn a_route_table_line_is_judged_by_the_route_it_declares() {
    let dir = repo(&[
        ("src/main.rs", AXUM_MAIN),
        ("src/handlers.rs", AXUM_HANDLERS),
    ]);
    let eps = axum_eps();
    let guarded = missing_authz("src/main.rs", 29, 29);
    assert!(verdict(&dir, &guarded, &eps).is_some());
    let open = missing_authz("src/main.rs", 35, 35);
    assert_eq!(verdict(&dir, &open, &eps), None);
}

#[test]
fn a_rails_route_table_line_naming_a_guarded_action_is_dropped() {
    let dir = repo(&[
        ("config/routes.rb", RAILS_ROUTES),
        (
            "app/controllers/reports_controller.rb",
            RAILS_REPORTS_CONTROLLER,
        ),
    ]);
    let f = missing_authz("config/routes.rb", 4, 4);
    assert!(verdict(&dir, &f, &rails_eps()).is_some());
}

/// A range spanning both the open and the guarded routes keeps the
/// finding: one entry point reachable without auth vetoes the drop.
#[test]
fn a_route_table_range_covering_an_open_route_keeps_the_finding() {
    let dir = repo(&[
        ("config/routes.rb", RAILS_ROUTES),
        (
            "app/controllers/reports_controller.rb",
            RAILS_REPORTS_CONTROLLER,
        ),
    ]);
    let f = missing_authz("config/routes.rb", 3, 5);
    assert_eq!(verdict(&dir, &f, &rails_eps()), None);
}

/// The word boundary that keeps `reports#index` from matching the line
/// declaring `ops#reindex`.
#[test]
fn a_route_table_match_is_word_bounded() {
    assert!(mentions_ident("get '/reports' => 'reports#index'", "index"));
    assert!(!mentions_ident(
        "post '/ops/reindex' => 'ops#reindex'",
        "index"
    ));
    assert!(!mentions_ident("indexing", "index"));
    assert!(!mentions_ident("anything", ""));
}

// ── negatives ───────────────────────────────────────────────────────

/// An open route keeps its finding — in all three of the shapes the
/// matcher can take.
#[test]
fn an_open_route_keeps_its_finding() {
    let laravel = repo(&[
        ("routes/web.php", LARAVEL_ROUTES),
        (
            "app/Http/Controllers/ReportController.php",
            LARAVEL_REPORT_CONTROLLER,
        ),
    ]);
    let laravel_eps = [
        ep("routes/web.php", "ReportController@search", true),
        ep(
            "routes/web.php",
            "OpsConsoleController@runMaintenance",
            false,
        ),
    ];
    let f = missing_authz("app/Http/Controllers/ReportController.php", 10, 16);
    assert_eq!(verdict(&laravel, &f, &laravel_eps), None);

    let rails = repo(&[
        ("config/routes.rb", RAILS_ROUTES),
        (
            "app/controllers/reports_controller.rb",
            RAILS_REPORTS_CONTROLLER,
        ),
    ]);
    let f = missing_authz("app/controllers/reports_controller.rb", 6, 11);
    assert_eq!(verdict(&rails, &f, &rails_eps()), None);

    let axum = repo(&[
        ("src/main.rs", AXUM_MAIN),
        ("src/handlers.rs", AXUM_HANDLERS),
    ]);
    let f = missing_authz("src/handlers.rs", 4, 13);
    assert_eq!(verdict(&axum, &f, &axum_eps()), None);
}

/// The gate exists to make the verifier ask for a bypass, so a finding
/// that already claims one is exactly what it must not touch.
#[test]
fn a_guarded_route_with_a_bypass_claim_keeps_its_finding() {
    let dir = repo(&[
        ("routes/web.php", LARAVEL_ROUTES),
        (
            "app/Http/Controllers/OpsConsoleController.php",
            LARAVEL_OPS_CONTROLLER,
        ),
    ]);
    let eps = [ep(
        "routes/web.php",
        "OpsConsoleController@runMaintenance",
        false,
    )];
    for claim in [
        "The auth middleware can be bypassed by sending the request with a trailing slash.",
        "The session guard is misconfigured and accepts an empty token.",
        "The guard uses a hardcoded shared secret, so anyone can authenticate.",
        "The route is missing its middleware registration in the production kernel.",
        "The token is predictable, so an attacker can forge a session.",
    ] {
        let mut f = missing_authz("app/Http/Controllers/OpsConsoleController.php", 21, 26);
        f.description = claim.to_string();
        assert_eq!(verdict(&dir, &f, &eps), None, "{claim}");
    }
}

/// A finding in a service class no route names keeps its finding: the
/// gate never guesses that an un-routed file is behind auth.
#[test]
fn a_service_layer_finding_with_no_entry_point_keeps_its_finding() {
    let dir = repo(&[
        ("routes/web.php", LARAVEL_ROUTES),
        ("app/Services/ReportingService.php", LARAVEL_SERVICE),
    ]);
    let eps = [ep(
        "routes/web.php",
        "OpsConsoleController@runMaintenance",
        false,
    )];
    let f = missing_authz("app/Services/ReportingService.php", 7, 10);
    assert_eq!(verdict(&dir, &f, &eps), None);
}

/// What used to be the documented limit of the whole-file rule, and is
/// now rule 1's job. `ReportRoutes.kt` declares an open
/// `/reports/search` alongside the authenticated `/reports`, so
/// unanimity is out — but both lambdas are pure delegations, so
/// `bc_callgraph`'s Kotlin section names the entry points
/// `searchReports` and `listOwnedReports` and each handler is matched to
/// its OWN route. The guarded one is dropped; the open one, in the same
/// file, is still kept.
#[test]
fn ktor_a_guarded_handler_is_dropped_by_name_while_its_open_neighbour_is_kept() {
    let dir = repo(&[("src/routes/ReportRoutes.kt", KTOR_REPORT_ROUTES)]);
    let eps = [
        ep("src/routes/ReportRoutes.kt", "searchReports", true),
        ep("src/routes/ReportRoutes.kt", "listOwnedReports", false),
    ];
    let guarded = missing_authz("src/routes/ReportRoutes.kt", 12, 15);
    let reason = verdict(&dir, &guarded, &eps).expect("dropped");
    assert!(
        reason.contains(r#"authenticate("auth-session")"#),
        "{reason}"
    );

    let open = missing_authz("src/routes/ReportRoutes.kt", 6, 9);
    assert_eq!(verdict(&dir, &open, &eps), None);
}

/// Only S0's framework plane sets `reachable_from_unauth` from evidence.
/// Every other kind carries the `#[serde(default)]` `false`, which means
/// "unknown", and must never gate a drop.
#[test]
fn a_non_framework_entry_point_never_gates_a_drop() {
    let dir = repo(&[
        ("src/main.rs", AXUM_MAIN),
        ("src/handlers.rs", AXUM_HANDLERS),
    ]);
    let eps = [EntryPoint {
        file: "src/main.rs".to_string(),
        function: "export_report".to_string(),
        kind: EntryPointKind::Network,
        reachable_from_unauth: false,
    }];
    let f = missing_authz("src/handlers.rs", 22, 28);
    assert_eq!(verdict(&dir, &f, &eps), None);
    assert!(RouteIndex::new(&eps).is_empty());
}

/// An entry point with no file at all is not an anchor for anything.
#[test]
fn an_entry_point_without_a_file_is_ignored() {
    let eps = [ep("", "export_report", false)];
    assert!(RouteIndex::new(&eps).is_empty());
}

/// Nothing but a missing-authorization claim is in scope: the same
/// handler's SQL injection still goes to the verifier.
#[test]
fn a_finding_that_is_not_about_authorization_is_out_of_scope() {
    let dir = repo(&[
        ("src/main.rs", AXUM_MAIN),
        ("src/handlers.rs", AXUM_HANDLERS),
    ]);
    let mut f = missing_authz("src/handlers.rs", 22, 28);
    f.cwe = Some("CWE-89".to_string());
    f.vuln_class = VulnClass::Injection;
    f.title = "SQL injection in the export lookup".to_string();
    f.description = "The slug is concatenated into the query.".to_string();
    assert_eq!(verdict(&dir, &f, &axum_eps()), None);
}

/// With no repo on disk the gate cannot read a line, so it cannot match
/// by name or by route-table line — but the whole-file rule still holds,
/// because it needs no source at all.
#[test]
fn without_a_repo_root_only_the_whole_file_rule_can_fire() {
    let f = missing_authz("src/handlers.rs", 22, 28);
    let eps = axum_eps();
    assert_eq!(guarded_route(&f, &RouteIndex::new(&eps), None), None);

    let on_the_route_file = missing_authz("src/routes/OpsRoutes.kt", 15, 19);
    let ktor = ktor_ops_eps();
    let reason = guarded_route(&on_the_route_file, &RouteIndex::new(&ktor), None).expect("dropped");
    assert!(reason.contains("framework auth guard"), "{reason}");
}

/// A file the jail rejects, and one that is not there, both read as "no
/// source" rather than panicking.
#[test]
fn an_unreadable_file_falls_back_to_no_source() {
    let dir = repo(&[("src/main.rs", AXUM_MAIN)]);
    assert_eq!(read_file(Some(dir.path()), "../outside.rs"), None);
    assert_eq!(read_file(Some(dir.path()), "src/missing.rs"), None);
    assert_eq!(read_file(None, "src/main.rs"), None);
}

// ── the pieces, directly ────────────────────────────────────────────

#[test]
fn the_missing_authorization_claim_is_recognised_by_cwe_or_by_wording() {
    let mut f = missing_authz("a.rb", 1, 1);
    for cwe in [
        "CWE-284", "CWE-285", "CWE-287", "CWE-306", "CWE-862", "CWE-863",
    ] {
        f.cwe = Some(cwe.to_string());
        f.title = "t".to_string();
        f.description = "d".to_string();
        assert!(claims_missing_authz(&f), "{cwe}");
    }
    // The same claim filed under a neighbouring CWE, or none at all.
    f.cwe = Some("CWE-639".to_string());
    f.title = "Unauthenticated access to the operator console".to_string();
    assert!(claims_missing_authz(&f));
    f.cwe = None;
    f.title = "Endpoint is reachable without authentication".to_string();
    assert!(claims_missing_authz(&f));
    f.title = "No authorization check on the admin route".to_string();
    assert!(claims_missing_authz(&f));
    // And a finding about something else entirely.
    f.cwe = Some("CWE-22".to_string());
    f.title = "Path traversal in the export bundle name".to_string();
    f.description = "The slug is joined onto the spool directory.".to_string();
    assert!(!claims_missing_authz(&f));
}

#[test]
fn cwe_number_reads_the_spellings_a_model_produces() {
    assert_eq!(cwe_number(Some("CWE-862")), Some(862));
    assert_eq!(cwe_number(Some(" cwe-306 ")), Some(306));
    assert_eq!(cwe_number(Some("862")), Some(862));
    assert_eq!(cwe_number(Some("CWE-")), None);
    assert_eq!(cwe_number(Some("CWE-8x2")), None);
    assert_eq!(cwe_number(Some("nope")), None);
    assert_eq!(cwe_number(None), None);
}

#[test]
fn a_handler_id_splits_into_its_controller_and_its_action() {
    assert_eq!(
        split_handler("OpsConsoleController@runMaintenance"),
        (Some("OpsConsoleController"), "runMaintenance")
    );
    assert_eq!(split_handler("reports#index"), (Some("reports"), "index"));
    assert_eq!(split_handler("export_report"), (None, "export_report"));
    // Degenerate halves are not a qualification.
    assert_eq!(split_handler("@index"), (None, "@index"));
    assert_eq!(split_handler("reports#"), (None, "reports#"));
}

#[test]
fn a_controller_qualifier_matches_its_source_file_across_conventions() {
    assert!(qualifier_matches_file(
        "OpsConsoleController",
        "app/Http/Controllers/OpsConsoleController.php"
    ));
    assert!(qualifier_matches_file(
        "reports",
        "app/controllers/reports_controller.rb"
    ));
    // Rails namespaces the controller, the file system does not.
    assert!(qualifier_matches_file(
        "admin/users",
        "app/controllers/admin/users_controller.rb"
    ));
    assert!(!qualifier_matches_file(
        "reports",
        "app/controllers/ops_controller.rb"
    ));
    assert!(!qualifier_matches_file("", "app/controllers/x.rb"));
}

#[test]
fn file_stem_drops_directories_and_every_extension() {
    assert_eq!(
        file_stem("app/controllers/reports_controller.rb"),
        "reports_controller"
    );
    assert_eq!(file_stem("main.rs"), "main");
    assert_eq!(file_stem("views/index.html.erb"), "index");
    assert_eq!(file_stem("Makefile"), "Makefile");
}

#[test]
fn the_enclosing_function_is_found_in_every_language_that_carries_routes() {
    for (src, line, expected) in [
        (LARAVEL_OPS_CONTROLLER, 21, "runMaintenance"),
        (KTOR_OPS_ROUTES, 16, "restoreConsoleSnapshot"),
        (RAILS_REPORTS_CONTROLLER, 16, "index"),
        (AXUM_HANDLERS, 23, "export_report"),
    ] {
        assert_eq!(
            enclosing_function(src, line).as_deref(),
            Some(expected),
            "line {line}"
        );
    }
    // Java/C# have no keyword, so the modifier-led alternative carries
    // them — and a bare block opener must not pose as a definition.
    assert_eq!(
        enclosing_function(
            "public JsonResponse runMaintenance(Request r) {\n  x();\n",
            2
        )
        .as_deref(),
        Some("runMaintenance")
    );
    assert_eq!(enclosing_function("if (x) {\n  y();\n", 2), None);
    // Above the first definition, and past the end of the file.
    assert_eq!(enclosing_function(AXUM_HANDLERS, 1), None);
    assert_eq!(
        enclosing_function(AXUM_HANDLERS, 9_999).as_deref(),
        Some("export_report")
    );
}

/// The scan is bounded: a definition further above than
/// [`ENCLOSING_SCAN_LINES`] is out of reach.
#[test]
fn the_enclosing_function_scan_is_bounded() {
    let mut src = String::from("def handler\n");
    for _ in 0..ENCLOSING_SCAN_LINES + 5 {
        src.push_str("  # filler\n");
    }
    assert_eq!(enclosing_function(&src, 3).as_deref(), Some("handler"));
    assert_eq!(
        enclosing_function(&src, ENCLOSING_SCAN_LINES as i64 + 4),
        None
    );
}

#[test]
fn own_lines_clamps_a_range_the_model_got_wrong() {
    let mut f = missing_authz("a.rb", 2, 3);
    assert_eq!(own_lines("one\ntwo\nthree\nfour\n", &f), "two\nthree");
    // A zero start, an inverted range, and a range past the end.
    f.line_start = 0;
    f.line_end = 1;
    assert_eq!(own_lines("one\ntwo\n", &f), "one");
    f.line_start = 9;
    f.line_end = 9;
    assert_eq!(own_lines("one\ntwo\n", &f), "");
    assert_eq!(own_lines("", &f), "");
}

#[test]
fn the_guard_label_names_each_frameworks_own_spelling() {
    assert_eq!(
        guard_label(None, Some(LARAVEL_ROUTES)),
        "middleware('auth')"
    );
    assert_eq!(
        guard_label(
            Some("Route::group(['middleware' => 'auth'], function () {"),
            None
        ),
        "middleware('auth')"
    );
    assert_eq!(
        guard_label(Some(KTOR_OPS_ROUTES), None),
        "authenticate(\"auth-session\")"
    );
    assert_eq!(
        guard_label(Some(RAILS_REPORTS_CONTROLLER), None),
        "before_action :authenticate_user!"
    );
    assert_eq!(
        guard_label(None, Some(AXUM_MAIN)),
        "middleware::from_fn(require_operator_token)"
    );
    assert_eq!(
        guard_label(Some("@PreAuthorize(\"hasRole('ADMIN')\")"), None),
        "@PreAuthorize"
    );
    // The handler's own file wins over the route table.
    assert_eq!(
        guard_label(Some(RAILS_REPORTS_CONTROLLER), Some(LARAVEL_ROUTES)),
        "before_action :authenticate_user!"
    );
    // And nothing recognisable falls back to the generic label.
    assert_eq!(guard_label(Some("nothing here"), None), GENERIC_GUARD);
    assert_eq!(guard_label(None, None), GENERIC_GUARD);
}

#[test]
fn could_apply_is_false_without_any_framework_entry_point() {
    let f = missing_authz("src/handlers.rs", 22, 28);
    assert!(!could_apply(&f, &RouteIndex::new(&[])));
    assert!(could_apply(&f, &RouteIndex::new(&axum_eps())));
}

#[test]
fn normalize_ident_keeps_only_the_last_segment_and_its_letters() {
    assert_eq!(normalize_ident("Admin/Users_Controller"), "userscontroller");
    assert_eq!(normalize_ident("reports"), "reports");
    assert_eq!(normalize_ident("--"), "");
}

#[test]
fn counts_report_the_indexed_framework_routes_and_how_many_are_guarded() {
    let eps = [
        ep("routes/web.php", "Ctl@open", true),
        ep("routes/web.php", "Ctl@guarded", false),
        ep("routes/web.php", "Ctl@also_guarded", false),
    ];
    let index = RouteIndex::new(&eps);
    assert_eq!(index.counts(), (3, 2));
    assert_eq!(RouteIndex::new(&[]).counts(), (0, 0));
}

/// Live Rails shape: the finding's range starts on the previous action's
/// `end` line, so the first line's enclosing function is the OPEN
/// `search`; the midpoint sits inside the guarded `index`.
#[test]
fn a_range_that_starts_on_the_previous_actions_end_line_is_judged_by_its_midpoint() {
    let ctl = "class ReportsController < ApplicationController\n\
               before_action :authenticate_user!, except: [:search]\n\
               def search\n\
                 Report.find_by_title(params[:q])\n\
               end\n\
               \n\
               def index\n\
                 Report.where(owner: params[:owner])\n\
                 render json: @reports\n\
               end\n\
             end\n";
    let rails = repo(&[("app/controllers/reports_controller.rb", ctl)]);
    let eps = [
        ep("config/routes.rb", "reports#search", true),
        ep("config/routes.rb", "reports#index", false),
    ];
    // Range 5-10: line 5 is `search`'s `end`, the body is `index`.
    let f = missing_authz("app/controllers/reports_controller.rb", 5, 10);
    assert!(verdict(&rails, &f, &eps).is_some());
    // Range 3-5 is genuinely the open action: kept.
    let g = missing_authz("app/controllers/reports_controller.rb", 3, 5);
    assert_eq!(verdict(&rails, &g, &eps), None);
}
