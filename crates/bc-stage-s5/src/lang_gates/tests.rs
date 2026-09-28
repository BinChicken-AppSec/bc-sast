//! Every case here is either a 2026-09-06 field false positive the gate
//! exists to kill, or the shape next door that it must NOT kill.

use super::*;
use bc_model::VulnClass;

fn finding(file: &str, cwe: Option<&str>, class: VulnClass) -> Finding {
    Finding {
        provider_origins: Vec::new(),
        chunk_id: "c".to_string(),
        file: file.to_string(),
        line_start: 10,
        line_end: 12,
        vuln_class: class,
        cwe: cwe.map(str::to_string),
        title: "t".to_string(),
        impact: String::new(),
        description: "d".to_string(),
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

fn race(file: &str) -> Finding {
    finding(file, Some("CWE-362"), VulnClass::RaceCondition)
}

fn xss(file: &str) -> Finding {
    finding(file, Some("CWE-79"), VulnClass::Injection)
}

fn drops_race(file: &str, code: &str) -> bool {
    synchronous_js_race(&race(file), &SourceWindow::from_text(code)).is_some()
}

fn drops_xss(file: &str, code: &str) -> bool {
    template_autoescaped(&xss(file), &SourceWindow::from_text(code)).is_some()
}

// ── Field case 1: routes/captcha.ts:11 ──────────────────────────────

/// `req.app.locals.captchaId++` — a read-modify-write on a plain object
/// property, with no suspension point anywhere near it. Node runs one
/// JavaScript thread to completion between suspension points, so this
/// cannot interleave with another request. Verified TRUE_POSITIVE at
/// 8/10 by the 2026-09-06 scan.
#[test]
fn field_case_captcha_ts_11_synchronous_increment_is_dropped() {
    assert!(drops_race(
        "routes/captcha.ts",
        "  const captchaId = req.app.locals.captchaId++\n  res.json({ captchaId })"
    ));
}

// ── Field cases 2 and 3: routes/2fa.ts:19-20 and :115-116 ───────────

/// Check-then-act with nothing between the halves.
#[test]
fn field_case_2fa_ts_19_20_check_then_act_with_no_await_is_dropped() {
    assert!(drops_race(
        "routes/2fa.ts",
        "  if (!tmpTokenPayload) {\n    res.status(401).send()\n    return\n  }"
    ));
}

#[test]
fn field_case_2fa_ts_115_116_second_check_then_act_is_dropped() {
    assert!(drops_race(
        "routes/2fa.ts",
        "  const isSetUp = user.totpSecret !== ''\n  if (isSetUp) { user.totpSecret = '' }"
    ));
}

// ── Field case 4: lib/challengeUtils.ts:71-76 ───────────────────────

#[test]
fn field_case_challenge_utils_ts_71_76_synchronous_flag_update_is_dropped() {
    assert!(drops_race(
        "lib/challengeUtils.ts",
        "  if (!challenge.solved) {\n    challenge.solved = true\n    notify(challenge)\n  }"
    ));
}

// ── Field case 5: lib/startup/registerWebsocketEvents.ts:22-50 ──────

/// The one of the five this gate deliberately does NOT settle. Its
/// reported range spans the socket handler registrations themselves, so
/// the window contains callback-shaped calls — and this gate cannot tell
/// "the check and the act are on opposite sides of that callback" (a real
/// TOCTOU) from "both are inside one handler body" (this case) without
/// parsing. Keeping it is the safe direction: S6 gets it, now carrying
/// the event-loop rule in its prompt.
#[test]
fn field_case_register_websocket_events_is_left_to_the_verifier_not_dropped() {
    assert!(!drops_race(
        "lib/startup/registerWebsocketEvents.ts",
        "  socket.on('verifyLocalXssChallenge', (data: string) => {\n    \
         challengeUtils.solveIf(challenges.localXssChallenge, () => { return true })\n  })"
    ));
}

// ── The 11 that must keep flowing ───────────────────────────────────

#[test]
fn an_await_between_the_check_and_the_act_is_a_real_toctou_and_is_kept() {
    assert!(!drops_race(
        "routes/order.ts",
        "  const basket = await BasketModel.findOne({ where: { id } })\n  \
         if (basket.total > 0) { basket.total = 0 }"
    ));
}

#[test]
fn every_asynchronous_boundary_form_keeps_the_finding() {
    for code in [
        "if (x) { await save(x) }",
        "if (x) { yield x }",
        "read().then(v => { cache[k] = v })",
        "read().catch(e => {})",
        "read().finally(() => {})",
        "if (!cache[k]) { Promise.resolve(1) }",
        "setTimeout(() => { cache[k] = 1 }, 0)",
        "setInterval(tick, 10)",
        "setImmediate(done)",
        "process.nextTick(done)",
        "queueMicrotask(done)",
        "Atomics.add(view, 0, 1)",
        "const b = new SharedArrayBuffer(8)",
        "const { Worker } = require('worker_threads')",
        "const w = new Worker('./x.js')",
        "if (cluster.isPrimary) { n += 1 }",
    ] {
        assert!(!drops_race("a.ts", code), "should not drop: {code}");
    }
}

/// `async` on its own is not a suspension point — an `async function`
/// with no `await` runs to completion exactly like a synchronous one.
#[test]
fn an_async_function_with_no_await_in_it_is_still_synchronous() {
    assert!(drops_race(
        "a.ts",
        "async function bump() {\n  counter += 1\n}"
    ));
}

#[test]
fn a_declaration_is_not_a_callback_shaped_call() {
    // `function handler(...)` and `const cb = (a) => a` both put the
    // marker OUTSIDE any call's argument list, so neither counts.
    assert!(drops_race(
        "a.ts",
        "function handler(req, res) {\n  counter += 1\n}"
    ));
    assert!(drops_race("a.ts", "const cb = (a) => a;\n  counter += 1"));
}

/// A keyword taking a parenthesized operand is not a call taking a
/// callback. `return (req, res) => { … }` is how an Express middleware
/// factory is written, and it wraps the actual field case
/// (`routes/captcha.ts:11`) — reading it as a callback-shaped call would
/// have kept every finding inside one.
#[test]
fn a_keyword_taking_a_parenthesized_operand_is_not_a_call() {
    assert!(drops_race(
        "routes/captcha.ts",
        "  return (req, res) => {\n    req.app.locals.captchaId++\n  }"
    ));
    for line in [
        "if (ok) { n += 1 }",
        "for (const k of ks) { n += 1 }",
        "while (n < 3) { n += 1 }",
        "switch (k) { default: n += 1 }",
        "throw (new Error('x'))",
    ] {
        assert!(drops_race("a.ts", line), "should drop: {line}");
    }
}

#[test]
fn a_callback_passed_into_an_asynchronous_call_keeps_the_finding() {
    assert!(!drops_race(
        "a.ts",
        "fs.readFile(p, function (e, d) { cache[k] = d })"
    ));
    // A callback alone is not a boundary: `Array.prototype.map` runs it to
    // completion before returning, so nothing can interleave. Reversed on
    // 2026-09-06 after a live scan kept a `.some(...)` race for this reason.
    assert!(drops_race("a.ts", "arr.map(x => x * 2)"));
}

// ── Scope of the race gate ──────────────────────────────────────────

#[test]
fn the_race_gate_only_applies_to_javascript_and_typescript() {
    // The identical code in a language with real threads is a real race.
    assert!(!drops_race("app.py", "counter += 1"));
    assert!(!drops_race("Main.java", "counter += 1"));
    assert!(!drops_race("main.go", "counter += 1"));
    for ext in ["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"] {
        assert!(drops_race(&format!("a.{ext}"), "counter += 1"), "{ext}");
    }
    // Case-insensitively, since a repo may spell it `.TS`.
    assert!(drops_race("A.TS", "counter += 1"));
}

#[test]
fn the_race_gate_only_applies_to_a_finding_that_actually_claims_a_race() {
    let sqli = finding("a.ts", Some("CWE-89"), VulnClass::Injection);
    assert!(synchronous_js_race(&sqli, &SourceWindow::from_text("counter += 1")).is_none());
    // Either signal is enough on its own.
    let by_class = finding("a.ts", None, VulnClass::RaceCondition);
    assert!(synchronous_js_race(&by_class, &SourceWindow::from_text("counter += 1")).is_some());
    for cwe in ["CWE-362", "cwe-0367", "366"] {
        let by_cwe = finding("a.ts", Some(cwe), VulnClass::Injection);
        assert!(
            synchronous_js_race(&by_cwe, &SourceWindow::from_text("counter += 1")).is_some(),
            "{cwe}"
        );
    }
}

#[test]
fn no_code_to_read_is_not_evidence_of_anything() {
    assert!(!drops_race("a.ts", ""));
    assert!(!drops_race("a.ts", "   \n  "));
}

// ── Template auto-escaping: the three field cases ───────────────────

/// `views/dataErasureForm.hbs:38` — `{{ }}` HTML-escapes `=` as well as
/// the angle brackets, so even an unquoted attribute value is safe.
/// Verified TRUE_POSITIVE at 8-9/10 by the 2026-09-06 scan.
#[test]
fn field_case_data_erasure_form_hbs_38_escaped_handlebars_is_dropped() {
    assert!(drops_xss(
        "views/dataErasureForm.hbs",
        "<input type=text name=email value={{userEmail}}>"
    ));
}

/// `views/userProfile.pug:42` — Pug escapes attribute values.
#[test]
fn field_case_user_profile_pug_42_escaped_attribute_is_dropped() {
    assert!(drops_xss(
        "views/userProfile.pug",
        "  img(src=profileImage)"
    ));
}

/// `views/userProfile.pug:60` — an attribute built by concatenation is
/// still an attribute, and still escaped.
#[test]
fn field_case_user_profile_pug_60_concatenated_attribute_is_dropped() {
    assert!(drops_xss(
        "views/userProfile.pug",
        "  input(placeholder='Image URL ' + imageUrl)"
    ));
}

// ── Escaped vs raw, per engine ──────────────────────────────────────

#[test]
fn handlebars_escaped_is_dropped_and_raw_is_kept() {
    assert!(drops_xss("v.hbs", "<p>{{ name }}</p>"));
    assert!(drops_xss("v.handlebars", "<p>{{name}}</p>"));
    assert!(drops_xss("v.mustache", "<p>{{name}}</p>"));
    assert!(!drops_xss("v.hbs", "<p>{{{ name }}}</p>"));
    assert!(!drops_xss("v.hbs", "<p>{{& name }}</p>"));
    // A block helper or comment is not output at all, so there is no
    // escaped construct to lean on.
    assert!(!drops_xss("v.hbs", "<p>{{#if name}}hi{{/if}}</p>"));
    assert!(!drops_xss("v.hbs", "<p>{{! a comment }}</p>"));
    assert!(!drops_xss("v.hbs", "<p>{{> partial}}</p>"));
}

#[test]
fn pug_escaped_is_dropped_and_raw_is_kept() {
    assert!(drops_xss("v.pug", "p #{name}"));
    assert!(drops_xss("v.jade", "p= name"));
    assert!(!drops_xss("v.pug", "p !{name}"));
    assert!(!drops_xss("v.pug", "p!= name"));
    assert!(!drops_xss("v.pug", "p unescaped(name)"));
}

#[test]
fn ejs_escaped_is_dropped_and_raw_is_kept() {
    assert!(drops_xss("v.ejs", "<p><%= name %></p>"));
    assert!(!drops_xss("v.ejs", "<p><%- name %></p>"));
}

#[test]
fn jinja_and_twig_escaped_is_dropped_and_raw_is_kept() {
    for file in ["v.jinja", "v.jinja2", "v.j2", "v.twig"] {
        assert!(drops_xss(file, "<p>{{ name }}</p>"), "{file}");
    }
    assert!(!drops_xss("v.j2", "<p>{{ name | safe }}</p>"));
    assert!(!drops_xss("v.twig", "<p>{{ name|raw }}</p>"));
    assert!(!drops_xss(
        "v.j2",
        "{% autoescape false %}{{ name }}{% endautoescape %}"
    ));
    assert!(!drops_xss("v.j2", "<p>{{ Markup(name) }}</p>"));
}

#[test]
fn erb_escaped_is_dropped_and_raw_is_kept() {
    assert!(drops_xss("v.html.erb", "<p><%= name %></p>"));
    assert!(!drops_xss("v.html.erb", "<p><%== name %></p>"));
    assert!(!drops_xss("v.erb", "<p><%= name.html_safe %></p>"));
    assert!(!drops_xss("v.erb", "<p><%= raw(name) %></p>"));
}

#[test]
fn razor_escaped_is_dropped_and_raw_is_kept() {
    assert!(drops_xss("v.cshtml", "<p>@Model.Name</p>"));
    assert!(drops_xss("v.razor", "<p>@name</p>"));
    assert!(!drops_xss("v.cshtml", "<p>@Html.Raw(Model.Name)</p>"));
    assert!(!drops_xss("v.cshtml", "<p>@(new HtmlString(name))</p>"));
}

#[test]
fn blade_escaped_is_dropped_and_raw_is_kept() {
    assert!(drops_xss("v.blade.php", "<p>{{ $name }}</p>"));
    assert!(!drops_xss("v.blade.php", "<p>{!! $name !!}</p>"));
}

#[test]
fn vue_escaped_is_dropped_and_raw_is_kept() {
    assert!(drops_xss("v.vue", "<p>{{ name }}</p>"));
    assert!(drops_xss("v.vue", "<img :src=\"image\">"));
    assert!(!drops_xss("v.vue", "<p v-html=\"name\"></p>"));
    assert!(!drops_xss("v.vue", "<p>el.innerHTML = name</p>"));
}

// ── Contexts where escaping does not save you ───────────────────────

#[test]
fn a_default_escaped_construct_in_a_non_html_context_is_kept() {
    for code in [
        "<script>var x = '{{name}}';</script>",
        "<style>body { color: {{name}} }</style>",
        "<a href=\"{{url}}\">go</a>",
        "<a href=\"javascript:{{name}}\">go</a>",
        "<div onclick=\"{{name}}\">x</div>",
        "<div style=\"color:{{name}}\">x</div>",
        "<iframe srcdoc=\"{{name}}\"></iframe>",
        "<img src=\"data:{{name}}\">",
    ] {
        assert!(!drops_xss("v.hbs", code), "should not drop: {code}");
    }
    // Pug's block forms of the same two elements.
    assert!(!drops_xss("v.pug", "  script.\n    var x = #{name}"));
    assert!(!drops_xss("v.pug", "  style.\n    body { color: #{name} }"));
}

#[test]
fn an_escaped_construct_inside_an_open_script_element_is_kept() {
    let mut window = SourceWindow::from_text("var greeting = '{{ name }}';");
    // As if the real file had an unclosed `<script>` above this line.
    window.in_script_or_style = true;
    assert!(template_autoescaped(&xss("v.hbs"), &window).is_none());
}

#[test]
fn inside_open_element_counts_opens_against_closes() {
    assert!(inside_open_element("<html><body><script>", None));
    assert!(!inside_open_element("<html><body><script></script>", None));
    assert!(inside_open_element("<STYLE>", None));
    assert!(!inside_open_element("<html><body>", None));
}

// ── Scope of the template gate ──────────────────────────────────────

#[test]
fn the_template_gate_only_applies_to_an_xss_cwe() {
    let sqli = finding("v.hbs", Some("CWE-89"), VulnClass::Injection);
    assert!(template_autoescaped(&sqli, &SourceWindow::from_text("<p>{{n}}</p>")).is_none());
    let no_cwe = finding("v.hbs", None, VulnClass::Injection);
    assert!(template_autoescaped(&no_cwe, &SourceWindow::from_text("<p>{{n}}</p>")).is_none());
    let cwe80 = finding("v.hbs", Some("CWE-80"), VulnClass::Injection);
    assert!(template_autoescaped(&cwe80, &SourceWindow::from_text("<p>{{n}}</p>")).is_some());
}

/// `{expr}` in JSX is indistinguishable by regex from a `${}` template
/// literal or an ordinary block, and `.html` names no engine at all — so
/// neither is claimed here. React/Vue/Angular knowledge lives in the S4
/// hints and the S6 verifier prompt instead.
#[test]
fn jsx_tsx_and_plain_html_name_no_engine_and_are_left_to_the_verifier() {
    for file in ["App.jsx", "App.tsx", "page.html", "a.txt", "styles.liquid"] {
        assert!(!drops_xss(file, "<p>{name}</p>"), "{file}");
        assert!(!drops_xss(file, "<p>{{name}}</p>"), "{file}");
    }
}

#[test]
fn a_template_with_no_interpolation_at_all_is_kept() {
    assert!(!drops_xss("v.hbs", "<p>static text</p>"));
    assert!(!drops_xss("v.ejs", "<p>static text</p>"));
    assert!(!drops_xss("v.hbs", ""));
}

#[test]
fn engine_name_is_reported_in_the_drop_reason() {
    let reason =
        template_autoescaped(&xss("v.pug"), &SourceWindow::from_text("p #{name}")).unwrap();
    assert_eq!(
        reason,
        "template engine escapes this construct by default (pug)"
    );
    for (file, code, name) in [
        ("v.hbs", "<p>{{n}}</p>", "handlebars"),
        ("v.ejs", "<p><%= n %></p>", "ejs"),
        ("v.j2", "<p>{{ n }}</p>", "jinja/twig"),
        ("v.erb", "<p><%= n %></p>", "erb"),
        ("v.cshtml", "<p>@n</p>", "razor"),
        ("v.blade.php", "<p>{{ $n }}</p>", "blade"),
        ("v.vue", "<p>{{ n }}</p>", "vue"),
    ] {
        let reason =
            template_autoescaped(&xss(file), &SourceWindow::from_text(code)).unwrap_or_default();
        assert!(reason.ends_with(&format!("({name})")), "{file}: {reason}");
    }
}

// ── could_apply, the cheap pre-check ────────────────────────────────

#[test]
fn could_apply_admits_exactly_the_findings_a_gate_can_settle() {
    assert!(could_apply(&race("a.ts")));
    assert!(could_apply(&xss("v.hbs")));
    assert!(!could_apply(&race("a.py")));
    assert!(!could_apply(&xss("app.py")));
    assert!(!could_apply(&finding(
        "a.ts",
        Some("CWE-89"),
        VulnClass::Injection
    )));
}

// ── SourceWindow, reading real files ────────────────────────────────

#[test]
fn a_window_reads_the_findings_own_lines_plus_context_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let body: String = (1..=20).map(|i| format!("line{i}\n")).collect();
    std::fs::write(dir.path().join("a.ts"), body).unwrap();
    let mut f = race("a.ts");
    f.line_start = 10;
    f.line_end = 12;
    let window = SourceWindow::read(&f, Some(dir.path()));
    // 10-12 widened by CONTEXT_LINES either side.
    assert_eq!(
        window.text,
        "line8\nline9\nline10\nline11\nline12\nline13\nline14"
    );
    assert!(!window.in_script_or_style);
}

#[test]
fn a_window_clamps_a_range_that_starts_before_the_file_does() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.ts"), "line1\nline2\nline3\n").unwrap();
    let mut f = race("a.ts");
    f.line_start = 1;
    f.line_end = 1;
    assert_eq!(
        SourceWindow::read(&f, Some(dir.path())).text,
        "line1\nline2\nline3"
    );
    // A finding the model never located at all.
    f.line_start = 0;
    f.line_end = 0;
    assert_eq!(
        SourceWindow::read(&f, Some(dir.path())).text,
        "line1\nline2"
    );
}

#[test]
fn a_window_falls_back_to_the_snippet_when_the_file_cannot_be_read() {
    let dir = tempfile::tempdir().unwrap();
    let mut f = race("does-not-exist.ts");
    f.code_snippet = "counter += 1".to_string();
    assert_eq!(
        SourceWindow::read(&f, Some(dir.path())).text,
        "counter += 1"
    );
    // No repo root at all.
    assert_eq!(SourceWindow::read(&f, None).text, "counter += 1");
    // And a path that escapes the root is inaccessible, not a way out.
    let mut escaping = race("../outside.ts");
    escaping.code_snippet = "snippet".to_string();
    assert_eq!(
        SourceWindow::read(&escaping, Some(dir.path())).text,
        "snippet"
    );
}

#[test]
fn a_window_falls_back_to_the_snippet_when_the_range_is_past_the_end() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.ts"), "line1\n").unwrap();
    let mut f = race("a.ts");
    f.line_start = 500;
    f.line_end = 502;
    f.code_snippet = "counter += 1".to_string();
    assert_eq!(
        SourceWindow::read(&f, Some(dir.path())).text,
        "counter += 1"
    );
}

#[test]
fn a_window_sees_an_enclosing_script_element_from_the_real_file() {
    let dir = tempfile::tempdir().unwrap();
    // The `<script>` sits far enough above the finding to fall OUTSIDE
    // the window, so only the whole-file scan can see it — which is the
    // point of tracking it separately from the line-level check.
    std::fs::write(
        dir.path().join("v.hbs"),
        "<html>\n<script>\nvar a = 1;\nvar b = 2;\nvar c = 3;\nvar d = 4;\n\
         var greeting = '{{ name }}';\n</script>\n",
    )
    .unwrap();
    let mut f = xss("v.hbs");
    f.line_start = 7;
    f.line_end = 7;
    let window = SourceWindow::read(&f, Some(dir.path()));
    assert!(window.in_script_or_style);
    assert!(template_autoescaped(&f, &window).is_none());
}

#[test]
fn cwe_number_normalizes_the_spellings_the_model_uses() {
    assert_eq!(cwe_number(Some("CWE-79")), Some(79));
    assert_eq!(cwe_number(Some("cwe-0079")), Some(79));
    assert_eq!(cwe_number(Some(" 79 ")), Some(79));
    for raw in [None, Some(""), Some("CWE-"), Some("CWE-xx"), Some("Ω")] {
        assert_eq!(cwe_number(raw), None, "{raw:?}");
    }
}

// ---- 2026-09-06 Juice Shop re-run: two synchronous races the gate KEPT ----

#[test]
fn field_case_captcha_id_increment_inside_an_async_arrow_handler_is_dropped() {
    // routes/captcha.ts:9-14 verbatim. The `async (req, res) => {` on the
    // line above is the handler's own definition; nothing here can yield.
    let code = "export function captchas () {\n  return async (req: Request, res: Response) => {\n    const captchaId = req.app.locals.captchaId++\n    const operators = ['*', '+', '-']\n\n    const firstTerm = Math.floor((Math.random() * 10) + 1)";
    assert!(drops_race("routes/captcha.ts", code));
}

#[test]
fn field_case_notification_push_after_a_synchronous_some_is_dropped() {
    // lib/challengeUtils.ts:71-76 verbatim. `Array.prototype.some` runs
    // its callback to completion before returning.
    let code = "  const wasPreviouslyShown = notifications.some(({ key }) => key === challenge.key)\n  notifications.push(notification)\n\n  if (globalWithSocketIO.io && (isRestore || !wasPreviouslyShown)) {\n    globalWithSocketIO.io.emit('challenge solved', notification)\n  }";
    assert!(drops_race("lib/challengeUtils.ts", code));
}

#[test]
fn a_genuine_asynchronous_callback_still_keeps_the_race() {
    for code in [
        "if (!cache[id]) {\n  fs.readFile(p, (err, data) => { cache[id] = data })\n}",
        "if (!lock) { setTimeout(() => { lock = true }, 0) }",
        "if (!seen) { fetch(url).then(r => { seen = true }) }",
        "db.get(id, function (err, row) { if (!row) db.insert(id) })",
    ] {
        assert!(!drops_race("routes/x.ts", code), "kept: {code}");
    }
}

#[test]
fn every_synchronous_higher_order_method_is_not_a_boundary() {
    for m in [
        "map",
        "filter",
        "forEach",
        "reduce",
        "find",
        "findIndex",
        "flatMap",
        "sort",
        "every",
    ] {
        let code =
            format!("const hit = items.{m}(x => x.id === id)\nif (!hit) {{ items.push(id) }}");
        assert!(
            drops_race("routes/x.ts", &code),
            "{m} should not keep the race"
        );
    }
}

// ---- Pug has no closing tags: block tracking by indentation ----

#[test]
fn a_pug_style_block_at_the_top_of_the_template_does_not_swallow_the_rest() {
    // views/userProfile.pug shape: script(...) and style. nested under head,
    // then a dedented body; line 60 is NOT inside either block.
    // Includes a blank line inside the style block, as real templates do;
    // blank lines carry no indentation and must not close the block.
    let before = "html\n  head\n    block head\n      meta(charset='utf-8')\n      script(type='module', src='/vendor/beercss/beer.min.js')\n      style.\n        body { margin: 0 }\n\n        .img-rounded { border-radius: 8px }\n  body\n    div.container\n      form(action='/profile', method='POST')\n";
    assert!(!inside_open_element(before, Some(Engine::Pug)));
}

#[test]
fn a_pug_finding_indented_inside_a_script_block_is_inside_it() {
    let before = "html\n  body\n    script.\n      var x = 1;\n";
    assert!(inside_open_element(before, Some(Engine::Pug)));
}

#[test]
fn pug_block_detection_requires_the_tag_to_start_the_line() {
    // `scripted` is a word, `description` is a word — neither opens a block.
    let before = "p scripted content\n  span description here\n";
    assert!(!inside_open_element(before, Some(Engine::Pug)));
}

#[test]
fn html_engines_keep_the_tag_counting_rule() {
    assert!(inside_open_element(
        "<div><script>\nvar x;",
        Some(Engine::Handlebars)
    ));
    assert!(!inside_open_element(
        "<script>x</script>\n<p>",
        Some(Engine::Handlebars)
    ));
    assert!(inside_open_element("<style>", None));
}

#[test]
fn the_userprofile_pug_field_case_is_now_dropped_by_the_escaping_gate() {
    // views/userProfile.pug:60 — an attribute value; Pug escapes attribute
    // interpolation and this window contains no raw construct.
    let code = "      input#url(type='text', name='imageUrl', placeholder='e.g. https://www.gravatar.com/avatar/' + imageUrl, required)";
    assert!(drops_xss("views/userProfile.pug", code));
}

#[test]
fn a_callback_to_an_unknown_or_synchronous_callee_is_not_a_boundary() {
    for code in [
        "const hit = items.some(x => x.id === id)\nif (!hit) { items.push(id) }",
        "const out = items.map(x => x * 2)\ncounter++",
        "items.forEach(function (x) { total += x })\nif (total > 9) { total = 0 }",
        // routes/nftMint.ts:38-52 shape: a project helper taking a callback,
        // entirely synchronous — kept as a race by the old "any callback"
        // rule on 2026-09-06.
        "if (addressesMinted.has(metamaskAddress)) {\n  addressesMinted.delete(metamaskAddress)\n  challengeUtils.solveIf(challenges.nftMintChallenge, () => true)\n}",
    ] {
        assert!(drops_race("routes/x.ts", code), "should drop: {code}");
    }
}

#[test]
fn a_callback_to_a_known_suspending_callee_is_a_boundary() {
    for code in [
        "if (!cache[id]) { fs.readFile(p, (err, d) => { cache[id] = d }) }",
        "if (!lock) { setTimeout(() => { lock = true }, 0) }",
        "socket.on('msg', () => { if (!seen) { seen = true } })",
        "db.query(sql, function (err, rows) { if (!rows.length) { db.insert(id) } })",
        "if (!p) { p = new Promise((resolve) => { resolve(1) }) }",
    ] {
        assert!(!drops_race("routes/x.ts", code), "should keep: {code}");
    }
}

// ---- attribute-local context (2026-09-06 field case userProfile.pug:42) ----

#[test]
fn field_case_img_src_with_a_literal_style_attribute_is_dropped() {
    // views/userProfile.pug:42 verbatim: the value is in `src` on an <img>;
    // the `style='...'` on the same line is a literal and not where the
    // value goes.
    let code = "                  img.img-rounded(src=profileImage, alt='profile picture', width='90%', height='236', style='margin-right: 5%; margin-left: 5%;')";
    assert!(drops_xss("views/userProfile.pug", code));
}

#[test]
fn a_value_in_a_url_css_or_handler_attribute_is_kept_for_the_verifier() {
    for code in [
        "a(href=url) link",
        "div(style=userCss) x",
        "button(onclick=handler) go",
        "form(action=target)",
        "<a href=\"{{url}}\">x</a>",
        "<div style=\"{{css}}\"></div>",
        "<img src=\"x.png\" onerror=\"{{h}}\">",
    ] {
        let file = if code.starts_with('<') {
            "views/t.hbs"
        } else {
            "views/t.pug"
        };
        assert!(!drops_xss(file, code), "should keep: {code}");
    }
}

#[test]
fn src_is_dangerous_only_on_an_element_that_executes_it() {
    assert!(!drops_xss("views/t.pug", "script(src=lib)"));
    assert!(!drops_xss("views/t.pug", "iframe(src=page)"));
    assert!(drops_xss("views/t.pug", "img(src=pic)"));
    assert!(!drops_xss(
        "views/t.hbs",
        "<script src=\"{{lib}}\"></script>"
    ));
    assert!(drops_xss(
        "views/t.hbs",
        "<img src=\"{{pic}}\" style=\"width: 1px\">"
    ));
}

#[test]
fn a_literal_scheme_anywhere_in_the_window_still_vetoes() {
    assert!(!drops_xss(
        "views/t.hbs",
        "<img src=\"{{pic}}\"> <!-- javascript: -->"
    ));
}

#[test]
fn an_escaped_construct_with_no_attribute_around_it_is_text_context() {
    assert!(drops_xss("views/t.hbs", "<p>Hello {{name}}</p>"));
    assert!(drops_xss("views/t.pug", "p Hello #{name}"));
}

#[test]
fn a_computed_or_chained_callee_is_never_a_boundary() {
    // `handlers[0](…)` and `make()(…)` open a call without a named
    // callee, so there is nothing to look up in the allowlist.
    assert!(!has_asynchronous_callback(
        "handlers[0](x => x); make()(function () {}); local(y => y)"
    ));
    assert!(has_asynchronous_callback(
        "handlers[0](x => x); setTimeout(() => act(), 0)"
    ));
}

#[test]
fn a_pug_interpolation_is_judged_by_the_attribute_it_sits_in() {
    // `#{…}` names no attribute itself; the enclosing `href="` does, and
    // a URL attribute is where escaping is not enough.
    assert!(!drops_xss("views/t.pug", "a(href=\"/go/#{target}\") link"));
    assert!(!drops_xss("views/t.pug", "div(style='color: #{c}') x"));
    // ...while a harmless attribute, or plain text, still drops.
    assert!(drops_xss("views/t.pug", "img(alt=\"#{name}\")"));
    assert!(drops_xss("views/t.pug", "p.note #{name}"));
}
