use std::sync::LazyLock;

use regex::Regex;

mod languages;
mod specialists;

use languages::*;
use specialists::*;

pub fn specialist_hint(specialist: &str) -> &'static str {
    match specialist {
        "crypto" => CRYPTO_SPECIALIST,
        "logic-bug" => LOGIC_BUG_SPECIALIST,
        "access-control" => ACCESS_CONTROL_SPECIALIST,
        "deserialization" => DESERIALIZATION_SPECIALIST,
        "batch-etl" => BATCH_ETL_SPECIALIST,
        "iac" => IAC_SPECIALIST,
        other => crate::lens_hints::specialist_lens_hint(other).unwrap_or(""),
    }
}

const C_HINT: &str = r#"Memory safety is the primary risk class here. Classify precisely —
use-after-free, double-free, heap-overflow, stack-overflow, format-string,
integer-overflow, type-confusion — not as a generic "buffer issue".

Untrusted input enters through `argv`/`getenv`, `recv`/`recvfrom`/`read` on a
socket, `fgets`/`gets`/`scanf`/`getline` on stdin, and every file or wire
parser that reads a length, count, offset or tag it then trusts. Trace from
one of those to a sink below — a fixed-size copy between two fixed-size
locals is not a finding.

Where to look first (non-exhaustive — reason beyond this list):
- Unbounded string sinks: `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets`,
  and `scanf("%s")` / `scanf("%[^\n]")` with no field width. The destination
  size never reaches the call, so any oversized source overflows it —
  stack-overflow into a local array, heap-overflow into a malloc'd block.
- `memcpy`/`memmove`/`strncpy`/`snprintf` where the LENGTH argument comes
  from the SOURCE data (a header field, a `strlen` of the input) while the
  destination's size is a constant declared somewhere else.
- `strncpy` does NOT NUL-terminate when the source is >= n — the following
  `strlen`/`printf`/`strcat` reads off the end. `strncat`'s n is the space
  REMAINING, not the buffer size: the classic off-by-one.
- Format strings: `printf(buf)`, `fprintf(f, buf)`, `syslog(pri, buf)`,
  `snprintf(dst, n, buf)` where `buf` is external. `%n` writes memory,
  `%s`/`%x` read it. A literal format with user data in the ARGS is fine.
- Allocation arithmetic: `malloc(n * size)`, `malloc(count + 1)`,
  `realloc(p, n * 2)`, `alloca(n)` with an input-derived `n` — the multiply
  or the increment wraps, the allocation succeeds undersized, and the loop
  that fills it writes past the end. `len - hdr` on unsigned types when
  `len < hdr` yields a huge positive length the same way.
- Bounds checks with the wrong types: an `int`/`short` length compared
  against a `size_t` capacity is promoted, so a NEGATIVE length passes
  `len < cap` and converts to an enormous `size_t` at the `memcpy`. Also
  `<` vs `<=` on the last index, and a check on a variable the sink does
  not actually use.
- Every `free()`: walk the pointer's whole lifetime — who else holds it,
  which error paths also free it, is it set to NULL after release, does a
  shared `goto cleanup` label free what an earlier branch already freed?
  A later read or write through it is a use-after-free; a second `free` is
  a double-free, and gives the same allocator primitive. Report either at
  that later use — the dereference, or the second `free` — not at the
  `free` that set it up.
- Uninitialized memory: a stack struct or array declared, only partially
  filled by a parser that returned early, then branched on or copied out to
  the caller/network — stale stack contents leak.
- TOCTOU: `access`/`stat`/`lstat` then `open`/`fopen` on the same path,
  `mktemp`/`tmpnam` then create, chmod-after-create. A local attacker swaps
  the path for a symlink between the two syscalls; the fix is `open` plus
  `fstat` on the fd, or `O_NOFOLLOW`/`O_EXCL`.
- Command execution: `system`, `popen`, `execl`/`execlp`/`execvp` on a
  `sh -c` string or a PATH-relative program name — anything sprintf'd from
  user data into a command line is injectable.
- Path traversal: `fopen`/`open`/`unlink`/`rename` on a path assembled from
  input with no `realpath()` and prefix check back to the base directory;
  `..` segments and a leading `/` both escape a plain concatenation.

Easy to miss:
- A product of input-derived dimensions (n * elemSize, w * h * bpp) wraps
  32-bit, allocation succeeds undersized, later writes overflow.
- One pointer freed on the error branch AND again in a shared cleanup label /
  caller destructor — map every route to free(), not just the happy path.
- Shallow struct copy (`a = *b`) where the struct owns heap pointers — both
  copies' destructors release the same block.
- A stale alias: object freed through one handle while another cached
  reference (list node, callback context, global) is still used afterward.
- memset/memcpy with a hard-coded byte count that no longer matches the
  field's actual size after a struct change.
- `sizeof(ptr)` where `sizeof(array)` was meant — once a parameter has
  decayed to a pointer, `sizeof` is the word size, not the buffer size.
- Signed overflow and shifting into the sign bit are undefined behavior, so
  a self-referential check like `if (a + b < a)` may be deleted outright by
  the optimizer."#;

const CPP_EXTRA: &str = r#"C++ additions (every C hazard above still applies):
- Iterator / reference / pointer invalidation: a `push_back`, `insert`,
  `erase`, `resize` or `clear` on a `vector`/`string`/`deque`/
  `unordered_map` while an iterator, reference or `.data()` pointer into it
  is still live — the next use is a use-after-free. Erasing inside a
  range-for over the same container is the standard shape.
- Dangling `c_str()` / `data()` / `string_view`: `const char *p =
  make_name().c_str();` or `std::string_view sv = a + b;` — the temporary
  dies at the end of the full expression and the handle dangles. Same for
  a `string_view` or `span` stored in a member that outlives its backing
  buffer.
- `reinterpret_cast`, C-style casts, and `union` punning of bytes that came
  off the wire into a struct: neither alignment nor layout is checked and
  the result is a type-confusion. A `static_cast` down a hierarchy with no
  discriminator check is the same bug — `dynamic_cast` returns null/throws,
  so check its result.
- Ownership: a raw pointer taken from `unique_ptr::get()` and stored past
  the owner's scope; two `shared_ptr`s constructed from the SAME raw
  pointer (two control blocks, hence a double-free); `shared_ptr` cycles;
  a `std::move`d-from object read afterwards.
- Exception safety: an acquire/release pair with a call that can throw
  between them and no RAII guard leaks or double-releases during unwinding;
  a destructor that throws while unwinding terminates the process.
- `operator[]` does NOT bounds-check on `vector`/`string`/`array` (and on
  `map` it silently INSERTS) — `.at()` does. An index derived from input
  reaching `[]` is an out-of-bounds access.
- The C rules are not escaped by using the standard library: `&v[0]`,
  `.data()`, `strcpy` into `&s[0]`, `memcpy` into a `resize`d vector, and
  `std::copy` with a hand-computed count are all raw-buffer writes."#;

static CPP_HINT: LazyLock<String> = LazyLock::new(|| format!("{C_HINT}\n\n{CPP_EXTRA}"));

pub fn lang_hint(lang: &str) -> Option<&'static str> {
    Some(match lang {
        "c" => C_HINT,
        "cpp" | "c-cpp" => CPP_HINT.as_str(),
        "rust" => RUST_HINT,
        "go" => GO_HINT,
        "python" => PYTHON_HINT,
        "java" => JAVA_HINT,
        "javascript" => JAVASCRIPT_HINT,
        "php" => PHP_HINT,
        "ruby" => RUBY_HINT,
        "objective-c" => OBJECTIVE_C_HINT,
        "kotlin" => KOTLIN_HINT,
        "csharp" => CSHARP_HINT,
        "perl" => PERL_HINT,
        "swift" => SWIFT_HINT,
        "scala" => SCALA_HINT,
        "cobol" => COBOL_HINT,
        "jcl" => JCL_HINT,
        "web-template" => WEB_TEMPLATE_HINT,
        "dart" => DART_HINT,
        "elixir" => ELIXIR_HINT,
        "erlang" => ERLANG_HINT,
        "groovy" => GROOVY_HINT,
        "lua" => LUA_HINT,
        "r" => R_HINT,
        "powershell" => POWERSHELL_HINT,
        "batch" => BATCH_HINT,
        "ansible" => ANSIBLE_HINT,
        "shell" => SHELL_HINT,
        "typescript" => TYPESCRIPT_HINT,
        "sql" => SQL_HINT,
        "terraform" => TERRAFORM_HINT,
        "vbnet" => VBNET_HINT,
        "abap" => ABAP_HINT,
        "clojure" => CLOJURE_HINT,
        "haskell" => HASKELL_HINT,
        "ocaml" => OCAML_HINT,
        "fsharp" => FSHARP_HINT,
        "julia" => JULIA_HINT,
        "solidity" => SOLIDITY_HINT,
        "assembly" => ASSEMBLY_HINT,
        "zig" => ZIG_HINT,
        "nim" => NIM_HINT,
        "crystal" => CRYSTAL_HINT,
        _ => return None,
    })
}

pub fn hint_key_for_path(path: &str) -> Option<&'static str> {
    let ext = appsec_repo_analysis::suffix_lower(path);
    let key = appsec_repo_analysis::ext_to_lang(&ext)?;
    Some(match (key, ext.as_str()) {
        ("c-cpp", ".c" | ".h") => "c",
        ("c-cpp", _) => "cpp",
        _ => key,
    })
}

static SPRING_BOOT_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"org\.springframework|@SpringBootApplication|@RestController|@Controller\b|@Autowired",
    )
    .unwrap()
});
static JAX_RS_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"javax\.ws\.rs|jakarta\.ws\.rs|@Path\b|@Produces\b|io\.quarkus|io\.micronaut")
        .unwrap()
});
static JPA_HIBERNATE_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"javax\.persistence|jakarta\.persistence|org\.hibernate|EntityManager|@Entity\b|@Repository\b").unwrap()
});
static MYBATIS_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"org\.apache\.ibatis|org\.mybatis|@Mapper\b|<mapper\b").unwrap());
static STRUTS2_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"org\.apache\.struts|com\.opensymphony\.xwork|struts\.xml|ActionSupport").unwrap()
});
static SERVLET_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"javax\.servlet|jakarta\.servlet|HttpServlet\b|doGet\(|doPost\(").unwrap()
});
static ANDROID_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bandroid\.|\bandroidx\.|AndroidManifest|ContentProvider\b|BroadcastReceiver\b")
        .unwrap()
});

const SPRING_BOOT_BODY: &str = r##"- Missing authz: @RequestMapping/@GetMapping/@PostMapping handlers WITHOUT a
  matching @PreAuthorize/@Secured/@RolesAllowed — or service methods called
  from multiple controllers where only some callers check authz
- Mass assignment: @ModelAttribute / @RequestBody bound directly to a JPA
  @Entity (caller can set id, role, isAdmin, tenantId, ownerId)
- SpEL injection: user input inside @Value("#{...}"), @Query("... ?#{...}"),
  @PreAuthorize("... #param ..."), SpelExpressionParser.parseExpression(x)
- SSRF: RestTemplate / WebClient / RestClient .getForObject/exchange where the
  URL or UriComponentsBuilder host is request-derived
- Actuator exposure: management.endpoints.web.exposure.include=* or env,
  heapdump, jolokia, gateway exposed without auth
- Path traversal: ResourceUtils.getFile / ClassPathResource / ResourceLoader
  .getResource on request input
- Request-scoped state on singletons: @Autowired @Component holding mutable
  fields written from handler threads (cross-request bleed)
- @Transactional on private/final/self-invoked methods (silently no-op →
  partial writes survive on exception)"##;
const JAX_RS_BODY: &str = r"- @Path methods without a ContainerRequestFilter / @RolesAllowed guard
- @PathParam/@QueryParam flowing into File, exec, or query without validation
- @Consumes(APPLICATION_XML) hitting a JAXB unmarshaller with DTDs enabled
- Providers (MessageBodyReader) that deserialize arbitrary types";
const JPA_HIBERNATE_BODY: &str = r#"- em.createQuery("... " + x) / createNativeQuery with string concat (JPQL/HQL
  injection — parameters via setParameter only)
- Spring Data @Query(nativeQuery=true, value="..."+...) or SpEL ?#{} on input
- findById(request.id) without owner/tenant check before update/delete (IDOR)
- @Formula / @Where with concatenated input"#;
const MYBATIS_BODY: &str = r"- ${param} (text substitution → SQLi) vs #{param} (bind) in mapper XML and
  @Select/@Update annotations — every ${} on a request-derived value is SQLi
- <if>/<foreach> building ORDER BY / column names from input";
const STRUTS2_BODY: &str = r"- OGNL evaluation on request params (forced double evaluation, %{...} in
  results, redirect:/redirectAction: with ${}) — historic RCE class
- ParametersInterceptor reaching setters on the Action that mutate auth state";
const SERVLET_BODY: &str = r"- request.getParameter/getHeader flowing unencoded into response.getWriter()
  .print (reflected XSS) or into File/Runtime/SQL
- getRequestDispatcher(param).forward / include (LFI via JSP path)
- response.sendRedirect(request.getParameter(...)) (open redirect)";
const ANDROID_BODY: &str = r#"- Exported Activity/Service/Receiver/Provider (android:exported="true" or
  intent-filter present) without permission gate — intent injection
- WebView: setJavaScriptEnabled(true) + addJavascriptInterface, or
  loadUrl/loadData on Intent extras
- ContentProvider.openFile with caller-supplied Uri (path traversal)
- PendingIntent without FLAG_IMMUTABLE; implicit Intents carrying extras"#;

static JAVA_FRAMEWORK_ENTRIES: &[(&LazyLock<Regex>, &str, &str)] = &[
    (&SPRING_BOOT_RX, "Spring / Spring Boot", SPRING_BOOT_BODY),
    (&JAX_RS_RX, "JAX-RS / Jakarta REST", JAX_RS_BODY),
    (&JPA_HIBERNATE_RX, "JPA / Hibernate", JPA_HIBERNATE_BODY),
    (&MYBATIS_RX, "MyBatis", MYBATIS_BODY),
    (&STRUTS2_RX, "Struts 2", STRUTS2_BODY),
    (&SERVLET_RX, "Servlet (raw)", SERVLET_BODY),
    (&ANDROID_RX, "Android", ANDROID_BODY),
];

fn framework_entries(
    lang: &str,
) -> &'static [(&'static LazyLock<Regex>, &'static str, &'static str)] {
    match lang {
        "java" => JAVA_FRAMEWORK_ENTRIES,
        _ => &[],
    }
}

fn char_boundary(s: &str, max_chars: usize) -> usize {
    s.char_indices()
        .nth(max_chars)
        .map(|(i, _)| i)
        .unwrap_or(s.len())
}

pub fn framework_blocks(languages: &[&str], code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let sample = &code[..char_boundary(code, 200_000)];
    for lang in languages.iter().take(3) {
        for (rx, name, body) in framework_entries(lang) {
            if rx.is_match(sample) {
                out.push(format!("── {name} (detected) ──\n{body}"));
            }
        }
    }
    out
}

pub fn hints_for(languages: &[&str], specialist: Option<&str>, code: Option<&str>) -> String {
    if let Some(specialist) = specialist {
        return specialist_hint(specialist).to_string();
    }

    let mut parts: Vec<String> = Vec::new();
    for lang in languages.iter().take(3) {
        if let Some(block) = lang_hint(lang) {
            let name = appsec_repo_analysis::lang_display(lang);
            parts.push(format!("── {name} ──\n{block}"));
        }
    }
    if let Some(code) = code {
        if !code.is_empty() {
            parts.extend(framework_blocks(languages, code));
        }
    }
    parts.join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPECIALIST_KEYS: &[&str] = &[
        "crypto",
        "logic-bug",
        "access-control",
        "deserialization",
        "batch-etl",
        "iac",
        "injection",
        "csrf",
        "sensitive-data",
        "hardcoded-creds",
        "log-injection",
    ];
    const LANG_KEYS: &[&str] = &[
        "c-cpp",
        "rust",
        "go",
        "python",
        "java",
        "javascript",
        "php",
        "ruby",
        "objective-c",
        "kotlin",
        "csharp",
        "perl",
        "swift",
        "scala",
        "cobol",
        "jcl",
        "web-template",
        "dart",
        "elixir",
        "erlang",
        "groovy",
        "lua",
        "r",
        "powershell",
        "batch",
        "ansible",
        "shell",
        "typescript",
        "sql",
        "terraform",
        "vbnet",
        "abap",
        "clojure",
        "haskell",
        "ocaml",
        "fsharp",
        "julia",
        "solidity",
        "assembly",
        "zig",
        "nim",
        "crystal",
    ];

    #[test]
    fn specialist_hint_covers_every_key_with_a_non_empty_distinctive_body() {
        for key in SPECIALIST_KEYS {
            let body = specialist_hint(key);
            assert!(!body.is_empty(), "missing specialist hint for {key}");
        }
        assert_eq!(SPECIALIST_KEYS.len(), 11);

        assert!(specialist_hint("crypto").contains("cryptography, key-handling"));
        assert!(specialist_hint("logic-bug").contains("behavioural / state-machine defects"));
        assert!(specialist_hint("access-control").contains("IDOR (BOLA)"));
        assert!(specialist_hint("deserialization").contains("Unsafe-deserialization expert"));
        assert!(specialist_hint("batch-etl").contains("Batch / ETL data-pipeline expert"));
        assert!(specialist_hint("iac").contains("Infrastructure-as-Code / cloud-config"));
    }

    #[test]
    fn specialist_hint_unknown_key_is_empty() {
        assert_eq!(specialist_hint("totally-unknown-specialist"), "");
        assert_eq!(specialist_hint(""), "");
    }

    #[test]
    fn javascript_and_typescript_hints_state_the_event_loop_rule() {
        for lang in ["javascript", "typescript"] {
            let hint = lang_hint(lang).unwrap();
            assert!(hint.contains("SINGLE-THREADED event loop"), "{lang}");
            assert!(hint.contains("CWE-362/367"), "{lang}");
            assert!(hint.contains("NOT races"), "{lang}");
            assert!(hint.contains("worker_threads"), "{lang}");
        }
    }

    #[test]
    fn the_web_template_hint_separates_escaped_constructs_from_raw_ones() {
        let hint = lang_hint("web-template").unwrap();
        assert!(hint.contains("HTML-escape by default"));
        assert!(hint.contains("even an unquoted attribute value is safe"));
        assert!(hint.contains("ONLY these are raw"));
        assert!(hint.contains("is a FALSE POSITIVE"));
        for raw in ["{{{ }}}", "!{ }", "<%- %>", "|safe", "{!! !!}", "v-html"] {
            assert!(hint.contains(raw), "missing {raw}");
        }
    }

    #[test]
    fn the_c_hint_names_the_memory_safety_classes_and_the_c_only_sinks() {
        let hint = lang_hint("c").unwrap();
        for class in [
            "use-after-free",
            "double-free",
            "heap-overflow",
            "stack-overflow",
            "format-string",
            "integer-overflow",
            "type-confusion",
        ] {
            assert!(hint.contains(class), "missing vuln class {class}");
        }
        for sink in [
            "`strcpy`",
            "`strcat`",
            "`sprintf`",
            "`gets`",
            "scanf(\"%s\")",
            "`memcpy`",
            "`printf(",
            "`alloca(",
            "`strncpy`",
            "`strncat`",
            "TOCTOU",
            "`system`",
            "`popen`",
            "`execl`",
            "realpath()",
            "`argv`",
            "`getenv`",
            "`recv`",
            "`fgets`",
            "Uninitialized memory",
            "sizeof(ptr)",
        ] {
            assert!(hint.contains(sink), "missing C sink/source {sink}");
        }
    }

    #[test]
    fn the_c_hint_says_to_report_a_use_after_free_at_the_later_use() {
        let hint = lang_hint("c").unwrap();
        assert!(
            hint.contains(
                "Report either at\n  that later use — the dereference, or the second `free` — not at the\n  `free` that set it up."
            ),
            "{hint}"
        );
        for key in ["cpp", "c-cpp"] {
            let cpp = lang_hint(key).unwrap();
            assert_eq!(
                cpp.matches("not at the\n  `free` that set it up.").count(),
                1,
                "{key}"
            );
        }
    }

    #[test]
    fn the_cpp_hint_is_the_c_hint_plus_the_cpp_only_hazards() {
        let c = lang_hint("c").unwrap();
        let cpp = lang_hint("cpp").unwrap();
        assert!(
            cpp.starts_with(c),
            "cpp hint must open with the whole C hint"
        );
        assert!(cpp.len() > c.len());
        for extra in [
            "Iterator / reference / pointer invalidation",
            "range-for",
            "c_str()",
            "string_view",
            "reinterpret_cast",
            "dynamic_cast",
            "unique_ptr::get()",
            "double-free",
            "Exception safety",
            "does NOT bounds-check",
            ".at()",
        ] {
            assert!(cpp.contains(extra), "missing C++ hazard {extra}");
        }
        assert_eq!(lang_hint("c-cpp"), Some(cpp));
    }

    #[test]
    fn the_swift_hint_covers_the_ios_specific_entry_points_and_sinks() {
        let hint = lang_hint("swift").unwrap();
        for item in [
            "Force unwraps",
            "`try!`",
            "`as!`",
            "application(_:open:options:)",
            "CFBundleURLSchemes",
            "evaluateJavaScript",
            "WKScriptMessageHandler",
            "NSAllowsArbitraryLoads",
            "kSecAttrAccessibleWhenUnlocked*",
            "UserDefaults",
            "sqlite3_exec",
            "String(format: x, ...)",
            "UnsafeBufferPointer(start:count:)",
            "NSKeyedUnarchiver",
            "NSSecureCoding",
            "resolvingSymlinksInPath",
        ] {
            assert!(hint.contains(item), "missing Swift item {item}");
        }
    }

    #[test]
    fn the_scala_hint_separates_bound_interpolators_from_spliced_ones() {
        let hint = lang_hint("scala").unwrap();
        for item in [
            "conf/routes",
            "entity(as[T])",
            "BIND their values and are safe",
            "#$x",
            "ORDER BY",
            "@Html(x)",
            "ObjectInputStream.readObject",
            "sys.process",
            "Runtime.getRuntime.exec",
            "Option.get",
            "REAL JVM threads",
            "AtomicReference",
            "ToolBox.eval",
            "SIGNED but not encrypted",
        ] {
            assert!(hint.contains(item), "missing Scala item {item}");
        }
    }

    #[test]
    fn hint_key_for_path_routes_the_c_family_swift_and_scala() {
        for (path, key) in [
            ("src/parser.c", "c"),
            ("include/parser.h", "c"),
            ("src/parser.cc", "cpp"),
            ("src/parser.cpp", "cpp"),
            ("src/parser.cxx", "cpp"),
            ("include/parser.hpp", "cpp"),
            ("App/ViewController.swift", "swift"),
            ("app/models/User.scala", "scala"),
            ("build.sc", "scala"),
        ] {
            assert_eq!(hint_key_for_path(path), Some(key), "route for {path}");
            assert!(lang_hint(key).is_some(), "no hint body for {key}");
        }
    }

    #[test]
    fn hint_key_for_path_passes_other_extensions_through_and_rejects_unknown_ones() {
        assert_eq!(hint_key_for_path("SRC/App.PY"), Some("python"));
        assert_eq!(
            hint_key_for_path("web/views/index.hbs"),
            Some("web-template")
        );
        assert_eq!(hint_key_for_path("README"), None);
        assert_eq!(hint_key_for_path("notes.xyz"), None);
    }

    #[test]
    fn lang_hint_covers_every_lang_hints_key() {
        for key in LANG_KEYS {
            assert!(lang_hint(key).is_some(), "missing lang hint for {key}");
        }
        assert_eq!(LANG_KEYS.len(), 42);
    }

    #[test]
    fn lang_hint_unknown_key_is_none() {
        assert_eq!(lang_hint("totally-unknown-lang"), None);
    }

    #[test]
    fn hints_for_specialist_wins_and_excludes_framework_and_language_hints() {
        let out = hints_for(
            &["java"],
            Some("crypto"),
            Some("org.springframework.stereotype.Controller"),
        );
        assert_eq!(out, specialist_hint("crypto"));
        assert!(!out.contains("── Java ──"));
        assert!(!out.contains("(detected)"));
    }

    #[test]
    fn hints_for_unknown_specialist_key_is_empty_even_with_languages_and_code() {
        let out = hints_for(&["java"], Some("nope"), Some("anything"));
        assert_eq!(out, "");
    }

    #[test]
    fn hints_for_no_specialist_wraps_the_single_language_hint_with_its_display_header() {
        let out = hints_for(&["python"], None, None);
        assert!(out.contains("── Python ──"));
        assert!(out.contains(lang_hint("python").unwrap()));
    }

    #[test]
    fn hints_for_only_consults_the_first_three_languages() {
        let out = hints_for(&["rust", "go", "java", "python"], None, None);
        assert!(out.contains("── Rust ──"));
        assert!(out.contains("── Go ──"));
        assert!(out.contains("── Java ──"));
        assert!(!out.contains("── Python ──"));
    }

    #[test]
    fn hints_for_no_specialist_no_languages_no_code_is_empty() {
        assert_eq!(hints_for(&[], None, None), "");
    }

    #[test]
    fn framework_blocks_detects_spring_marker_in_java_code() {
        let code = "package com.example;\nimport org.springframework.stereotype.Controller;\n@Controller\npublic class Foo {}\n";
        let blocks = framework_blocks(&["java"], code);
        assert!(!blocks.is_empty());
        assert!(blocks.iter().any(|b| b.contains("Spring / Spring Boot")));
        assert!(blocks.iter().any(|b| b.contains("(detected)")));
    }

    #[test]
    fn framework_blocks_no_marker_match_is_empty() {
        let code = "def handler(request):\n    return 'no frameworks here'\n";
        assert!(framework_blocks(&["java"], code).is_empty());
    }

    #[test]
    fn framework_blocks_only_consults_the_first_three_languages() {
        let code = "@SpringBootApplication\npublic class App {}\n";
        let blocks = framework_blocks(&["rust", "go", "python", "java"], code);
        assert!(blocks.is_empty());
    }

    #[test]
    fn hints_for_combines_java_lang_hint_with_detected_framework_block() {
        let code = "import org.springframework.stereotype.Controller;\n@Controller\nclass Foo {}\n";
        let out = hints_for(&["java"], None, Some(code));
        assert!(out.contains("── Java ──"));
        assert!(out.contains(lang_hint("java").unwrap()));
        assert!(out.contains("Spring / Spring Boot"));
        assert!(out.contains("(detected)"));
    }

    #[test]
    fn hints_for_code_none_or_empty_skips_framework_blocks() {
        let out_none = hints_for(&["java"], None, None);
        assert!(!out_none.contains("(detected)"));
        let out_empty = hints_for(&["java"], None, Some(""));
        assert!(!out_empty.contains("(detected)"));
    }

    #[test]
    fn char_boundary_never_panics_on_multibyte_content_near_the_cap() {
        let s: String = "€".repeat(10);
        assert_eq!(char_boundary(&s, 5), 15);
        assert_eq!(char_boundary(&s, 100), s.len());
        let _ = &s[..char_boundary(&s, 5)];
    }
}
