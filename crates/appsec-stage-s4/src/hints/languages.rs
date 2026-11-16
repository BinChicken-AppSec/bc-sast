pub(super) const RUST_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Every `unsafe { }` block: what invariant does the surrounding safe API
  promise the compiler, and can a caller break it without writing `unsafe`
  themselves?
- Hand-written `Send`/`Sync` impls (or `#[derive]` on types holding `*mut T`
  / `Rc` / interior-mutable cells) — would sharing across threads race?
- FFI (`extern "C"`): who owns the pointer after the call, and does the Rust
  side keep a borrow alive long enough?
- `transmute`, `from_raw_parts`, `slice::from_raw_parts_mut`, `ptr::offset`:
  are length, alignment and lifetime all proven at the call site?

Easy-to-miss soundness holes:
- A safe method hands out `&T` into interior-mutable storage, then a second
  safe method reallocates/clears that storage — the first borrow now dangles.
- A type that is effectively `!Send` (raw pointer, `RefCell`, OS handle)
  gains `Send`/`Sync` via a blanket impl or derive and becomes shareable
  from safe code."#;

pub(super) const GO_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- HTML built with `text/template` instead of `html/template`, or
  `template.HTML()` casts on request-derived strings.
- Maps / slices / struct fields written from multiple goroutines without a
  mutex or channel hand-off (look at HTTP handlers sharing package-level
  state).
- `os.Stat` → `os.Open`, `Exists` → `Remove` and similar two-step file ops
  on paths another principal can swap between calls.
- `filepath.Join(base, userInput)` without `filepath.Clean` + prefix check
  back to `base` — `..` segments still escape after Join.
- `exec.Command("sh", "-c", x)` or argv elements assembled from request
  fields.
- `interface{}` asserted with `x.(T)` (no `, ok`) on values that came from
  JSON/YAML decode — wrong type panics the handler."#;

pub(super) const PYTHON_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Code execution: eval / exec / compile / __import__ / getattr(obj, user)()
  / functools.reduce over user data; ast.literal_eval is safe, eval is not
- Deserialization: pickle.load(s) / shelve / marshal / jsonpickle / dill /
  joblib.load / yaml.load without SafeLoader / pandas.read_pickle on
  untrusted bytes — all are RCE
- Command exec: subprocess.* with shell=True or string args, os.system,
  os.popen, commands.*; also .NET Process.Start / win32 ShellExecute /
  os.startfile in IronPython / pywin32 / pythonnet code — check the path
  argument is allow-listed (fixed dir + fixed basename), not just "a path"
- SQL: cursor.execute(f"..."), .raw(), .extra(), text() with f-strings,
  string-built queries; ORM bypasses
- Template / HTML: mark_safe, |safe, Markup(), autoescape off — AND
  hand-rolled HTML via f"<td>{x}</td>" / "".join / += where x is external
  and not passed through html.escape()
- XXE: lxml.etree.parse / fromstring without resolve_entities=False or
  no_network=True; xml.sax / xml.dom.pulldom with external-general-entities
- XPath injection (CWE-643): lxml / ElementTree .xpath() / .find() or a
  string-built XPath expression where a request value is concatenated in
- SSRF: requests.* / httpx.* / urllib.request.urlopen where the URL host is
  user-influenced; check redirects aren't followed to internal hosts
- Path traversal: open / shutil.* / send_file / os.remove / rmtree on
  os.path.join(base, user) without os.path.realpath + startswith(base) check
- Archive extraction: tarfile.extractall / zipfile.extractall on untrusted
  archives (zip-slip — member names containing ../ or absolute paths)
- CSV / formula injection (CWE-1236): csv.writer / pandas.to_csv / f-string
  rows where cell values originate from parsed input and are written without
  stripping leading = + - @ TAB (Excel evaluates these as formulas on open)
- Windows forced-auth (CWE-73): externally-supplied paths passed to open(),
  shutil.*, os.startfile, Process.Start, SetValue on a native file-dialog,
  or any Win32 API WITHOUT rejecting UNC prefixes (\\host\..., //host/...).
  Resolving a UNC triggers SMB → leaks the runner's NTLMv2 hash.

Easy-to-miss logic faults:
- Module-level mutable globals: one function sets `global X; X = ...` but a
  sibling function that ALSO changes the same conceptual state forgets the
  assignment — downstream readers of X act on stale state (cross-tenant /
  cross-workspace file ops, wrong-record updates)
- TOCTOU via filesystem metadata: `max(glob(...), key=os.path.getmtime)` or
  `sorted(..., key=getctime)[-1]` to pick "the latest" output — any local
  writer can plant a future-dated entry and win the selection. Same for
  os.path.exists → open, or stat → use, on shared/world-writable dirs
- Destructive ops on derived paths: os.remove / shutil.rmtree / os.rename
  where the target path is built from a global or external value without
  re-validating it belongs to the current run/tenant"#;

pub(super) const JAVA_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Deserialization: ObjectInputStream.readObject without an ObjectInputFilter;
  Jackson enableDefaultTyping / @JsonTypeInfo(Id.CLASS); XStream.fromXML;
  XMLDecoder; SnakeYAML new Yaml() (not SafeConstructor); Kryo/Hessian/FST
- XXE: DocumentBuilderFactory / SAXParserFactory / XMLInputFactory / SAXReader /
  TransformerFactory without FEATURE_SECURE_PROCESSING + disallow-doctype-decl
- XPath injection (CWE-643): XPath.compile / evaluate, XPathExpression, or
  Document.selectNodes built by concatenating a request value into the expr
- JNDI: new InitialContext().lookup(x) / LdapCtx / RMI where x is user-derived
- Command exec: Runtime.exec / ProcessBuilder with user-influenced argv;
  String[] is safe only if argv[0] is fixed
- Path traversal: new File(base, user) / Paths.get / getResourceAsStream
  without getCanonicalPath().startsWith(base) check
- Zip-slip: ZipInputStream / TarArchiveInputStream / ZipFile.entries() where
  entry.getName() is used in new File(dest, name) without canonicalize+prefix
- SSRF: new URL(user).openConnection / HttpURLConnection / Apache HttpClient /
  OkHttp / ImageIO.read(URL) where host is user-controlled
- TLS bypass: X509TrustManager with empty checkServerTrusted, HostnameVerifier
  returning true, SSLContext.init with all-trusting managers
- Reflection: Class.forName(user) / Method.invoke / ScriptEngine.eval /
  URLClassLoader on user-supplied class names or URLs
- Open redirect / CRLF: response.sendRedirect(param), setHeader("Location",
  param), addHeader with unfiltered \r\n"#;

pub(super) const JAVASCRIPT_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Property writes through a request-controlled key (`obj[k] = v`, lodash
  `merge`/`set`, recursive assign) — `__proto__`/`constructor` keys pollute
  the prototype chain.
- Regexes evaluated against request bodies/headers: nested or overlapping
  quantifiers (`(a+)+`, `(.*?,)*`) on unbounded input → CPU exhaustion.
- DOM/SSR sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
  `dangerouslySetInnerHTML`, server-side template literals that splice
  request fields into markup without an encoder.
- `child_process.exec` / `execSync` (string form) or `spawn` with
  `shell: true` taking request-derived arguments.
- File-serving / download routes: `path.join(root, req.params.file)` or
  `res.sendFile(userPath)` without resolving + asserting the result stays
  under `root`.
- `eval`, `new Function`, `vm.runInThisContext` on request data; `require()`
  of a path that includes a request field.
Concurrency — read this before reporting any race/TOCTOU (CWE-362/367):
- JavaScript runs on a SINGLE-THREADED event loop and every synchronous block
  runs to completion. Two requests cannot interleave inside one; there is no
  preemption, no thread scheduler, no torn read.
- A race therefore requires an ASYNCHRONOUS BOUNDARY BETWEEN the check and the
  act on the same shared state — an `await`, a `.then`, a completion callback, a
  timer, or any I/O — AND state another request can reach (module-level, a
  singleton, `app.locals`, a DB row, a cache, the filesystem).
- `counter++`, `obj.n += 1`, and `if (x) { x = ... }` with NO await in between
  are NOT races. Neither is state confined to one request (`req.*`, a local).
  Report nothing for these. `async` on a function is irrelevant on its own — a
  function with no `await` in it does not suspend.
- Genuine concurrency exists only via `worker_threads`/`cluster`/`SharedArrayBuffer`
  (real shared memory) or multi-process deployment against a shared store.";

pub(super) const PHP_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- `unserialize()` on cookies, POST bodies or anything request-derived (POP
  gadget chains → RCE); `phar://` reached via file functions on a user path
  triggers the same.
- `include`/`require`/`include_once` where any part of the path comes from
  the request (LFI; with `allow_url_include` → RFI).
- SQL strings assembled with `.` concat or double-quoted interpolation from
  `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE` instead of PDO bound params.
- `exec`/`system`/`shell_exec`/`passthru`/`popen`/`proc_open`/backticks
  where the command string or argv embeds request data.
- Outbound fetches (`file_get_contents`, `fopen`, `curl_*`, Guzzle) where
  the host/scheme is request-controlled.
- `preg_replace` with the deprecated `/e` modifier, `assert($str)`,
  `create_function`, or `call_user_func($_GET[...])`.";

pub(super) const RUBY_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- `YAML.load`, `Marshal.load`, `Oj.load` (non-strict) on request or uploaded
  bytes — the safe forms are `YAML.safe_load` / `Marshal` never on untrusted
  data.
- Views emitting unescaped content: `raw`, `.html_safe`, `<%== %>`, Haml
  `!=`, Slim `==` on request-derived values.
- `params.permit!` / blanket `permit(...)` that whitelists role/admin/owner
  fields, or `update(params[:model])` straight onto the record.
- Dynamic dispatch with a request-supplied symbol: `send(params[:m])`,
  `public_send`, `constantize`/`safe_constantize` on user strings.
- `system`/`exec`/`` `cmd` ``/`%x{}`/`Open3.*` where any fragment is request
  data; same for `Kernel.open(user)` (leading `|` runs a process).";

pub(super) const OBJECTIVE_C_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Format-string sinks (`NSLog`, `-[NSString stringWithFormat:]`,
  `CFStringCreateWithFormat`) where the FORMAT argument itself is external
  data rather than a literal.
- Raw C buffers under the ObjC layer: `strcpy`/`sprintf`/`memcpy` on
  `[nsstr UTF8String]` or socket bytes without a bound.
- Custom URL-scheme / universal-link handlers: query items reaching
  `NSURL`, `openURL:`, file paths, or WebView loads unvalidated.
- Secrets or session tokens persisted to `NSUserDefaults`, plists, or
  unencrypted SQLite instead of Keychain.";

pub(super) const KOTLIN_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- JVM deserialization surfaces inherited from Java: `ObjectInputStream`,
  Jackson polymorphic typing, SnakeYAML `Yaml()` on request bytes.
- Queries built with `$var` string templates in Exposed / JDBC / Room raw
  SQL rather than bound `?` parameters.
- (Android) exported `Activity`/`Service`/`Receiver`/`Provider` consuming
  `Intent` extras without validating origin or contents — intent redirection
  / extra-driven file/URL loads.
- `File(base, userInput)` / `Paths.get(user)` without canonicalising and
  asserting the result stays under the intended root.
- `Runtime.exec`/`ProcessBuilder` with string-template argv.";

pub(super) const CSHARP_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`,
  `LosFormatter`, `ObjectStateFormatter`, or `JavaScriptSerializer` with a
  custom type resolver, fed from request/viewstate/queue data.
- `SqlCommand`/`OracleCommand`/`NpgsqlCommand` whose `CommandText` is built
  with `+` or `$"... {x} ..."` instead of `Parameters.Add`.
- `Path.Combine(root, user)` / `File.*` / `Directory.*` on request input
  without `Path.GetFullPath` + `StartsWith(root)` containment.
- `XmlDocument.Load`/`XDocument.Load`/`XmlReader.Create` without
  `DtdProcessing = Prohibit` and a null `XmlResolver`.
- `Process.Start` (or `UseShellExecute = true`) with arguments or filename
  derived from the request.
- Newtonsoft `TypeNameHandling != None` on attacker-reachable JSON."#;

pub(super) const PERL_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Command injection via open()/system()/backticks/qx — ONLY when the argument
  crosses a trust boundary (CGI param, network input, file content from an
  untrusted source). $ARGV[n] / @ARGV on a locally-run operator CLI tool is
  TRUSTED input — the operator already has a shell, so do NOT report it.
- Two-arg open(): only a finding when (a) the filename is untrusted AND
  (b) no explicit mode prefix (`<`, `>`) is hard-coded. `open(F, "<$x")`
  cannot reach pipe/command mode — do NOT flag it.
- Regex injection / ReDoS where the PATTERN itself is untrusted input
- Taint propagation through eval STRING, `do $file`, `require $var`
- CSV / formula injection (CWE-1236): print/printf emitting parsed fields
  into a .csv WITHOUT prefixing a single-quote or stripping leading
  = + - @ TAB. Double-quoting ("$x") does NOT neutralise — Excel strips
  RFC-4180 quotes before evaluating the cell.
- Hardcoded credentials / secrets in source (these ARE findings regardless
  of execution reachability)"#;

pub(super) const SWIFT_HINT: &str = r#"Untrusted input reaches an app through another app or the network, not
through a request object: custom URL schemes and universal links, pasteboard
and share-extension payloads, QR/NFC scans, push payloads, WebView pages, and
every server response the app decodes. Start there.

Where to look first (non-exhaustive — reason beyond this list):
- Force unwraps and force casts on external data: `x!`, `try!`, `as!`,
  `Int(s)!`, `array[i]` with an index from input, `dict[k]!`. Each one is a
  crash — a remotely-triggerable denial of service — the moment the field is
  absent, misspelled or the wrong type. Decoding a server or deep-link
  payload and unwrapping on the way out is the usual shape.
- URL entry points: `application(_:open:options:)`, `onOpenURL`,
  `NSUserActivity` universal-link handlers, and the schemes registered under
  `CFBundleURLSchemes` in `Info.plist`. Anything another app on the device
  can invoke is untrusted — check what the components feed: file paths,
  WebView loads, auth/session state, a deep-link "action" dispatch.
- `WKWebView`: `evaluateJavaScript("... \(value) ...")` is script injection
  — the value must be JSON-encoded, not interpolated.
  `WKScriptMessageHandler` / `add(_:name:)` bridges hand page JavaScript a
  native call whose argument arrives as `Any` from the renderer; validate it
  there. `loadHTMLString` with a remote `baseURL`, and
  `allowFileAccessFromFileURLs` / `allowUniversalAccessFromFileURLs`, give a
  compromised page the app's file scheme.
- Transport security: `NSAllowsArbitraryLoads`,
  `NSExceptionAllowsInsecureHTTPLoads`, or an `NSExceptionMinimumTLSVersion`
  below 1.2 in `Info.plist`; and any `URLSessionDelegate` answering
  `didReceive challenge` with `.useCredential(URLCredential(trust:))`
  unconditionally, which disables certificate validation outright.
- Secrets in `UserDefaults`, a plist, `@AppStorage`, or an app-group
  container instead of the Keychain; Keychain items without
  `kSecAttrAccessibleWhenUnlocked*` (or worse, `...Always`), and
  `kSecAttrSynchronizable` pushing them to iCloud.
- SQLite used raw: `sqlite3_exec` or a `sqlite3_prepare_v2` statement built
  by string interpolation, FMDB `executeQuery("... \(x)")` instead of `?`
  placeholders with an arguments array. GRDB/FMDB calls WITH arguments bind;
  interpolation into the SQL text does not.
- `String(format: x, ...)` / `NSString(format:)` where the FORMAT ITSELF is
  external — the ObjC varargs bridge still reads memory through `%@`/`%p`
  and crashes on a mismatched specifier.
- `Unsafe*Pointer`, `withUnsafeBytes`, `UnsafeBufferPointer(start:count:)`,
  `memcpy`, `Data.copyBytes` — Swift's bounds and lifetime guarantees stop
  at these calls, so apply the C rules to whatever is inside them.
- Deserialization: `NSKeyedUnarchiver.unarchiveObject(with:)` and any
  `NSCoding` type decoded without `NSSecureCoding` plus an explicit class
  allow-list (`decodeObject(of:forKey:)`) lets an attacker choose the class
  that gets instantiated; `PropertyListSerialization` on untrusted bytes is
  the same problem.
- `FileManager` operations on paths assembled from URL or query input with
  no `standardizedFileURL` / `resolvingSymlinksInPath` and no check that the
  result is still inside the app's own container.
- Leakage: tokens or PII in `print` or an `os_log` `%{public}@` (plain `%@`
  is redacted, interpolation into the message is not), Core Data / Realm
  stores created without a file-protection class, and screenshots of a
  sensitive view not blanked on `applicationWillResignActive`."#;

pub(super) const SCALA_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Entry points are Play's `conf/routes` and its controllers (`Action { req =>
  ... }`, `Action(parse.json)`), Akka/Pekko HTTP directives (`path`,
  `parameter`, `entity(as[T])`), and http4s/Finatra routes. Every path
  segment, query parameter, header, form field and JSON body arriving at one
  of those is untrusted — start traces there, not at the sink.
- SQL: Slick/Doobie `sql"SELECT ... $x"` and Anorm `SQL("... {x}").on(...)`
  BIND their values and are safe. What is NOT: `#$x` in a Slick
  interpolation and `#${...}` in a Doobie `fr` (both splice raw text BY
  DESIGN), a plain `s"SELECT ... $x"` handed to `sqlu`/`Statement.execute`,
  and any table name, column name or ORDER BY built by concatenation — a
  placeholder cannot carry an identifier, so those need an allow-list.
  Check which interpolator the `$` actually sits in.
- Templates: Twirl escapes `@x` by default. `@Html(x)`, `@Raw(x)`,
  `HtmlFormat.raw(...)` and any `play.twirl.api.Html` built from a request
  value do not — and no HTML escaping saves a value placed inside
  `<script>`, an `on*` handler, or a `href`/`src` that could become
  `javascript:`.
- Deserialization: `ObjectInputStream.readObject` — Scala inherits the JVM
  gadget-chain risk in full. Also `scala.xml.XML.load*` and XML literals
  (external entities are on by default), and Jackson /
  `jackson-module-scala` with default typing enabled.
- Process execution: `sys.process` (`"cmd".!`, `Process(...)`,
  `Seq(...).!!`) and `Runtime.getRuntime.exec`. A single `String` command
  goes through a shell, so an interpolated value is command injection; a
  `Seq` is safe only when element 0 is a fixed program name.
- Partial operations on external data: `Option.get`, `.head`, `.toInt`,
  `Try(...).get`, `Either.right.get`, an incomplete `match` on a decoded
  ADT. Each throws on exactly the input that does not fit, and inside a
  `Future` or an actor the exception is swallowed or kills a supervised
  actor instead of returning a 400.
- Concurrency here is REAL JVM threads, not an event loop: a `var`, a
  mutable `HashMap`/`ListBuffer`, or a lazily-populated cache touched from
  inside a `Future` callback, a parallel collection, or an
  `ExecutionContext` task without a lock, an `AtomicReference` or
  actor-mailbox confinement is a genuine data race. Mutable state closed
  over by an actor and then also read from a `Future` that actor spawned has
  escaped the mailbox guarantee.
- Reflection and dynamic evaluation: `Class.forName`,
  `scala.reflect.runtime` mirrors, `ScriptEngine`, `ToolBox.eval` on
  user-supplied strings — all RCE.
- Play specifics: `session`/`flash` cookies are SIGNED but not encrypted, a
  committed `play.http.secret.key`, the CSRF filter disabled globally or
  `+nocsrf` on a routes entry, and a wide-open `allowedHostsFilter` or CORS
  configuration."#;

pub(super) const COBOL_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Grep for EXEC SQL ... END-EXEC — look for host variables built via STRING/UNSTRING from
  terminal/CICS input (dynamic SQL injection into DB2)
- Grep for EXEC CICS RECEIVE / BMS maps — trace DFHCOMMAREA and map fields to where they
  reach EXEC SQL, CALL, file I/O, or EXEC CICS LINK/XCTL without validation
- Check ACCEPT FROM CONSOLE / SYSIN — untrusted batch input flowing into business logic
- Look for MOVE of larger PIC items into smaller ones (truncation) and COMPUTE without
  ON SIZE ERROR (silent overflow on COMP/COMP-3 fields used in amounts, indices, lengths)
- Check OCCURS ... DEPENDING ON where the count comes from input — out-of-bounds subscript
- Grep for CALL identifier (dynamic CALL with a variable program name) — can untrusted
  input pick the target program?
- Check copybooks (.cpy) shared across programs for REDEFINES that reinterpret tainted
  alphanumeric data as numeric/packed without validation";

pub(super) const JCL_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Look for symbolic parameters (&VAR) that flow into DSN=, PGM=, PARM=, or SYSIN — if
  callers/schedulers can set them, check for dataset-name or program-name injection
- Check DD statements with DISP=(MOD|OLD,DELETE) or IDCAMS DELETE/IEFBR14 steps that
  target datasets named via substitutable parameters
- Grep for IKJEFT01 / IRXJCL / BPXBATCH steps — TSO, REXX, or USS commands built from
  PARM= or SYSTSIN that include externally supplied values (command injection)
- Look for FTP/SFTP (FTP PARM=, BPXBATCH SH) or NJE transmit steps with hardcoded
  credentials in inline SYSIN or unprotected PARMLIB members
- Check RACF/ACF2 context: jobs that run under high-privilege USER= but accept
  operator-supplied or scheduler-supplied parameters";

pub(super) const WEB_TEMPLATE_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Find every spot where a variable is rendered WITHOUT auto-escaping: JSP <%= %> /
  ${} without <c:out>; Thymeleaf th:utext / [( )]; Razor @Html.Raw; ERB <%= raw %> /
  html_safe; Twig |raw; Jinja {{ x|safe }} / {% autoescape false %}; Handlebars {{{ }}};
  Freemarker ?no_esc / <#noescape>; EJS <%- %>; Vue v-html; Svelte {@html}; Angular
  [innerHTML] / bypassSecurityTrust*
- Trace each unescaped expression back to its controller — is the value user-controlled?
- Look for SSTI: places where the TEMPLATE SOURCE itself (not just a variable) is built
  from user input and passed to the engine
- Check inline <script> blocks and on*= attributes that interpolate server variables —
  even "escaped" HTML output is unsafe inside a JS string or event handler
- Check href=/src=/action= built from user input — javascript: URI and open redirect
Auto-escaping — read this before reporting XSS on an interpolation (CWE-79/80):
- These engines HTML-escape by default, and escaping covers `<`, `>`, `&`, quotes AND
  `=`, so even an unquoted attribute value is safe: Handlebars/Mustache `{{ x }}`;
  Pug/Jade `#{x}`, `tag= x`, `attr=x`; EJS `<%= x %>`; Jinja2/Django/Twig `{{ x }}`;
  Rails ERB `<%= x %>`; Razor `@x`; Blade `{{ $x }}`; Vue `{{ x }}` and `:attr="x"`;
  React `{x}`; Angular `{{ x }}`.
- ONLY these are raw: `{{{ }}}` / `{{& }}` (Handlebars); `!{ }` / `!=` / `unescaped`
  (Pug); `<%- %>` (EJS); `|safe` / `|raw` / `Markup()` / `{% autoescape false %}`
  (Jinja/Django/Twig); `<%== %>` / `raw()` / `.html_safe` (ERB); `@Html.Raw` /
  `HtmlString` (Razor); `{!! !!}` (Blade); `v-html` (Vue); `dangerouslySetInnerHTML`
  (React); `[innerHTML]` / `bypassSecurityTrust*` (Angular); `{@html}` (Svelte).
- An XSS finding on a DEFAULT-ESCAPED construct is a FALSE POSITIVE — report nothing —
  UNLESS the value later reaches a raw construct, or the construct sits in a NON-HTML
  context where escaping does not apply: inside `<script>`/`<style>`, in an `on*=`
  handler, in a `href`/`src`/`action` that could become `javascript:` or `data:`, or
  in a CSS value."#;

pub(super) const DART_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Grep for Process.run / Process.start with runInShell: true or string-concatenated args
- Check platform channels (MethodChannel) — untrusted args from the native side reaching
  File/Process/db without validation, or sensitive ops exposed to the platform
- Look for WebView (webview_flutter / InAppWebView) with javascriptMode unrestricted
  loading user-controlled URLs, or addJavaScriptHandler exposing privileged Dart calls
- Check http/dio requests where the URL host is user-influenced (SSRF / open redirect)
- Look for File/Directory paths built from user input without normalization
- Check certificate handling: badCertificateCallback returning true, or
  HttpOverrides that disable TLS verification";

pub(super) const ELIXIR_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Grep for Code.eval_string / Code.eval_quoted / :erlang.binary_to_term on untrusted
  input (binary_to_term without [:safe] is RCE via atom/fun creation)
- Check String.to_atom / List.to_atom on user input — atom-table exhaustion DoS; use
  String.to_existing_atom instead
- Look for Ecto queries built with raw fragments: fragment("... #{x} ...") or
  Repo.query with interpolated SQL
- Check Phoenix templates for raw/1 or {:safe, ...} wrapping user content
- Grep for System.cmd / :os.cmd / Port.open({:spawn, ...}) with user-influenced args
- Check GenServer/Agent state for user-keyed maps that grow unbounded"#;

pub(super) const ERLANG_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Grep for binary_to_term/1 on network input (without the 'safe' option it creates
  atoms/funs → RCE); same for erlang:binary_to_atom/2 (atom-table DoS)
- Check os:cmd/1 and open_port({spawn, Cmd}, ...) for shell-interpreted user input
- Look for distributed-Erlang exposure: net_kernel started with a guessable cookie or
  epmd reachable from untrusted networks (full node RCE)
- Check ETS tables keyed by user input for unbounded growth
- Look for file:open / file:read_file with user-controlled paths";

pub(super) const GROOVY_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Grep for GroovyShell.evaluate / Eval.me / GroovyScriptEngine / @Grab on user input —
  direct RCE; Jenkins Script Console / shared-library code is a common sink
- Check GString SQL: "SELECT ... ${x}" passed to Sql.execute/rows instead of
  parameterized GString placeholders
- Grep for "cmd".execute() / ["sh","-c", x].execute() / ProcessBuilder with user input
- Look for XmlSlurper/XmlParser without disabling DOCTYPE/external entities (XXE)
- Inherits all Java sinks: ObjectInputStream, JNDI lookup, SpEL/OGNL evaluation"#;

pub(super) const LUA_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Grep for load / loadstring / loadfile / dofile with user-influenced source — RCE
- Check os.execute / io.popen for shell-interpreted user input
- In OpenResty/nginx-lua: ngx.var.* or ngx.req.get_*_args() flowing into ngx.location.capture,
  resty.http, or redis/db queries built via string concat (SSRF / injection)
- Check string.format("%s") used to build SQL/shell/redis commands from request data
- Look for setfenv/_ENV or debug.* exposed to sandboxed user scripts (sandbox escape)
- Check io.open paths derived from request input (path traversal)"#;

pub(super) const R_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Grep for eval(parse(text=...)) / source() / do.call where the expression or function
  name comes from request input (Shiny input$*, plumber params)
- Check system / system2 / shell / pipe with user-influenced arguments
- Look for SQL built via paste()/sprintf()/glue() and sent through DBI::dbGetQuery /
  dbExecute instead of dbBind / sqlInterpolate
- Check readRDS / load / unserialize on uploaded or fetched files — arbitrary code via
  promise/active-binding deserialization
- In Shiny/plumber: file download/read endpoints where the path includes input$* without
  normalizePath + base-directory check";

pub(super) const POWERSHELL_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Grep for Invoke-Expression / iex / Invoke-Command -ScriptBlock built from user input,
  and Add-Type / [ScriptBlock]::Create with external strings — direct code execution
- Check Start-Process / & "..." / cmd /c where arguments are interpolated "..." strings
  containing user input (use argument arrays instead)
- Look for Invoke-WebRequest/Invoke-RestMethod where -Uri is user-controlled (SSRF) or
  whose response is piped straight into iex (download-cradle RCE)
- Check Get-Content/Set-Content/Remove-Item paths built from parameters without
  Resolve-Path under a fixed base (path traversal, wildcard injection)
- Look for ConvertTo-SecureString -AsPlainText / hardcoded PSCredential / secrets in
  transcripts; check for -SkipCertificateCheck / TrustAllCertsPolicy"#;

pub(super) const BATCH_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- FOR /F ... (`cmd`) DO ( SET var=%%F ) — %%F is re-tokenised by cmd.exe AFTER
  substitution, so &, |, >, < in file/command output become live operators.
  Unquoted `SET var=%%F` (instead of `SET "var=%%F"`) is second-order command
  injection when the file/command output is attacker-influenceable.
- %VAR% immediate expansion of tainted values inside ECHO, IF, redirection, or
  another command — same re-tokenisation problem. Only !VAR! delayed expansion
  (with EnableDelayedExpansion) is safe.
- CALL %var% / START %var% / %var%.exe where var is built from file content,
  argv (%1..%9), or environment — arbitrary process execution.
- Redirection targets built from tainted vars (>> %outfile%) — path injection
  and file clobber.
- Hardcoded credentials in NET USE / FTP / SQLCMD inline scripts.
- UNC paths (\\host\share) read from config/input and passed to any command —
  forced SMB auth leaks the runner's NTLMv2 hash."#;

pub(super) const ANSIBLE_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- shell: / command: / raw: / script: tasks whose cmd embeds {{ var }} that
  originates from inventory, extra-vars, survey input, or registered output —
  Jinja is rendered THEN passed to /bin/sh, so any unquoted {{ }} is shell
  injection. Same for win_shell / win_command.
- ansible.builtin.uri / get_url / unarchive where url: or src: is templated
  from a variable an operator/CI caller can set (SSRF, supply-chain pull)
- validate_certs: no / verify: false on uri/get_url/yum/apt_repository — TLS
  bypass to internal artefact servers
- lookup('pipe', …) / lookup('url', …) / lookup('file', var) with templated
  arguments — pipe runs on the CONTROL node, so injection here is RCE on the
  Ansible controller, not the target host
- copy/template with mode: 0777 / 0666, or dest: built from {{ var }} without
  a fixed base directory (path traversal onto the managed host)
- become: yes / become_user: root on tasks that consume untrusted vars
- Secrets in plain vars: / defaults/main.yml instead of ansible-vault;
  no_log: missing on tasks that register or echo credentials
- delegate_to: localhost + shell: — same control-node RCE surface as
  lookup('pipe', …)
- Inventory / group_vars committed with real hostnames + credentials";

pub(super) const SHELL_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Grep for eval, bash -c, sh -c, backticks/$() that embed "$VAR" sourced from argv,
  env, or read — command injection via metacharacters
- Find unquoted variable expansions ($var instead of "$var") used as command arguments
  or in [ ] tests — word-splitting and glob injection
- Check curl/wget where the URL contains a variable, and any `curl ... | sh` pattern
- Look for filenames/paths from user input passed to rm/cp/mv/tar without `--` and
  without base-directory containment (option injection, traversal)
- Check `source` / `.` of files at user-writable or variable-derived paths
- Look for tempfile races: > /tmp/fixedname or `mktemp` output reused predictably;
  TOCTOU between [ -f ] check and use"#;

pub(super) const TYPESCRIPT_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Type-erased trust: `as any` / `as unknown as T` / `@ts-ignore` / `@ts-nocheck`
  / non-null `!` on EXTERNAL input — the compile-time check is suppressed, so a
  runtime value the code "trusts" may be attacker-shaped. Validate at the boundary
  (zod / io-ts / class-validator); a cast is NOT validation. (CWE-20)
- Prototype pollution: `obj[userKey] = v`, lodash `merge`/`mergeWith`/`set`,
  `Object.assign({}, req.body)` with a request key `__proto__`/`constructor`/`prototype`.
- Code/command exec: `eval` / `new Function(str)` / `vm.runInContext` on external
  strings; `child_process.exec` with a template-string argument containing ${x} —
  `execFile`/`spawn` with a FIXED binary and array args is safe, `exec` of a built
  string is not.
- SQL: tagged-template clients are safe ONLY if parameterised; `knex.raw`,
  TypeORM `.query()`, Sequelize `literal()` with an interpolated string concatenate
  user input. (CWE-89)
- SSRF: `fetch`/`axios`/`got`/`http.request` where the URL host is user-influenced;
  confirm redirects aren't followed to internal hosts.
- Decorator-driven authz (NestJS/Angular): a route/handler missing
  `@UseGuards`/`@Roles`/`@CanActivate` that siblings have → missing access control.
- Deserialization: `JSON.parse` is safe; `node-serialize` `unserialize`, or
  `yaml.load` (not `safeLoad`) on untrusted bytes is RCE.
Easy-to-miss logic faults:
- TS types vanish at runtime: a value cast with `as` used as an index/length/loop
  bound without a runtime guard — the compiler is silent, the bug is not.
- Optional chaining swallowing a check: `user?.isAdmin` is `undefined` (falsy but
  not `false`); `if (!user?.isAdmin)` may behave unexpectedly when you meant deny.
Concurrency — read this before reporting any race/TOCTOU (CWE-362/367):
- TypeScript compiles to JavaScript and runs on the same SINGLE-THREADED event loop; every
  synchronous block runs to completion and cannot be interrupted by another request.
- A race REQUIRES an asynchronous boundary (`await`, `.then`, a callback, a timer,
  I/O) BETWEEN the check and the act, AND shared mutable state another request can
  reach (module-level, a singleton, `app.locals`, a DB row, a cache).
- `req.app.locals.n++` or `if (!x.solved) { x.solved = true }` with no `await`
  between the read and the write are NOT races — report nothing. Registering a
  handler (`socket.on(...)`, `router.get(...)`) is not a boundary either: each
  invocation of the handler body runs to completion on its own.
- Real concurrency needs `worker_threads`/`cluster`/`SharedArrayBuffer`, or a
  shared store behind multiple processes."#;

pub(super) const SQL_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Dynamic SQL built by concatenation then executed: Oracle EXECUTE IMMEDIATE /
  DBMS_SQL, T-SQL EXEC(@sql) / sp_executesql with a CONCATENATED (not parameter-
  bound) string, MySQL PREPARE FROM a built string — injection inside the DB tier.
  Bind variables (:x, @p, ?) are safe; string-built predicates are not. (CWE-89)
- Definer rights: procedures created WITH AUTHID DEFINER (Oracle) or
  EXECUTE AS OWNER (T-SQL) that run dynamic SQL from caller input → injection runs
  with the owner's privileges (escalation).
- OS / network reach: xp_cmdshell, DBMS_SCHEDULER / DBMS_JAVA, UTL_FILE / UTL_HTTP /
  UTL_SMTP (Oracle), MySQL LOAD_FILE / INTO OUTFILE, OPENROWSET / BULK — file or
  network egress from the DB; flag any reachable from parameterised input.
- Identifier injection: a caller string sets a TABLE/COLUMN name (bind vars cannot
  parameterise identifiers) — require an allow-list, not quoting.
- Excessive grants: GRANT ... TO PUBLIC, ANY-privileges (e.g. SELECT ANY TABLE),
  roles granted inside a proc body.
Easy-to-miss logic faults:
- NULL comparison: `x = NULL` is never true — an authz/filter predicate using
  `= NULL` instead of `IS NULL` silently matches nothing (or, negated, everything).
- Unbounded mutation: UPDATE/DELETE where `WHERE col = p_in` and `p_in` may be NULL
  or unfiltered → mass row change.
- WHEN OTHERS THEN NULL (Oracle) / empty CATCH swallowing a failed integrity or
  authz check so execution continues.";

pub(super) const TERRAFORM_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- IAM over-grant: `Action = "*"` or `Resource = "*"`; assume-role / trust policy
  with `Principal = "*"` or cross-account `sts:AssumeRole` without `ExternalId`. (CWE-732)
- Public exposure: `aws_s3_bucket` without block-public-access / SSE; RDS/Redshift
  `publicly_accessible = true`; security groups / NSGs with `0.0.0.0/0` (or `::/0`)
  on 22/3389/3306/5432/6379/9200/27017.
- Secret hygiene: literal `access_key`/`secret_key`/`password`/`token` in resource
  args, `user_data`, provider blocks, or committed `*.tfvars`; `aws_ssm_parameter`
  as `String` not `SecureString`; secrets in `locals` / `variable default`.
- State & supply chain: backends without encryption; `aws_kms_key` without
  `enable_key_rotation`; modules sourced from a mutable `?ref=branch/tag` (not a
  commit SHA); `local-exec`/`external` provisioners running `curl ... | sh`.
- Audit disabled: CloudTrail / S3 access logging / VPC flow logs off;
  `skip_final_snapshot = true` on a production data store.
Easy-to-miss logic faults:
- `count`/`for_each` on a sensitive resource gated by a variable that DEFAULTS to
  the insecure branch (e.g. `count = var.public ? 1 : 0` with `public = true`).
- A hardened resource shadowed by a later override file; last write in apply order
  wins, silently re-opening what an earlier block locked down."#;

pub(super) const VBNET_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- SQL: `New SqlCommand("..." & userInput)` / string-concatenated CommandText;
  `cmd.Parameters.Add...` is safe, `&`-built SQL is not. (CWE-89)
- Command exec: `Shell(...)`, `Process.Start` with an argument string built from
  input, `CreateObject("WScript.Shell").Run` — a fixed exe with separated args is
  safe, a built command line is not. (CWE-78)
- Dynamic eval (VBA/VBScript): `Eval`, `Execute`, `ExecuteGlobal`, and late-bound
  `CallByName(obj, userName, ...)` on attacker-influenced names.
- Path/file: `My.Computer.FileSystem.*`, `Open ... For`, `Kill` on a path from
  input without a fixed-base + canonical-path containment check (traversal).
- Deserialization: `BinaryFormatter`/`SoapFormatter`/`LosFormatter`/
  `NetDataContractSerializer` on untrusted bytes is RCE; `Type.GetType(userName)` +
  `Activator.CreateInstance`.
- Crypto: `MD5`/`DES`/`TripleDES`, ECB mode, hardcoded keys/IVs; `Rnd()` /
  `System.Random` for tokens (not a CSPRNG).
Easy-to-miss logic faults:
- `Option Strict Off`: implicit narrowing / late binding hides type confusion — a
  string compared to a number, or a `Variant`/`Object` trusted as a typed value.
- VB `=` string compare is case-insensitive by default — a role/secret check with
  `=` may match unintended casings; and `Nothing` vs `""` vs `0` conflation."#;

pub(super) const ABAP_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Dynamic Open SQL: `SELECT ... WHERE (lv_where)` or table name in `(lv_tab)` built
  from input; native `EXEC SQL` blocks — ABAP SQL injection. Use bound host vars and
  validated identifiers. (CWE-89)
- OS command: `CALL 'SYSTEM'`, function modules SXPG_COMMAND_EXECUTE /
  SXPG_CALL_SYSTEM with arguments from input → OS command injection.
- Generic/dynamic invocation: `CALL FUNCTION lv_name`, `CALL METHOD (lv_dyn)`,
  `GENERATE SUBROUTINE POOL`, `INSERT REPORT` on attacker-influenced names → arbitrary
  code / RFC invocation.
- Authorization gaps: a transaction or RFC-enabled FM with NO `AUTHORITY-CHECK
  OBJECT`, or one whose `sy-subrc` result is read but not enforced (continues anyway)
  — missing authorization is the dominant SAP finding.
- File access: `OPEN DATASET ... FILENAME` from input without validation / authority
  check (path traversal on the app server); `GUI_DOWNLOAD`/`GUI_UPLOAD`.
Easy-to-miss logic faults:
- `sy-subrc` ignored after SELECT/CALL: the failure path falls through and the next
  statement runs on stale/initial data (wrong-record or bypassed check).
- Client field (MANDT) omitted in a dynamic/native query → cross-client data access.";

pub(super) const CLOJURE_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Code eval: `eval`, `read-string` / `load-string` on untrusted input (the default
  reader evaluates `#=()` and constructs arbitrary objects) — use
  `clojure.edn/read-string` with controlled `:readers`, not `clojure.core/read`. (CWE-95)
- Reflection/interop: `(Class/forName s)`, `(.invoke method ...)`, eval of Java
  interop forms on user-named classes/methods.
- SQL: `clojure.java.jdbc`/`next.jdbc` with a string-built query instead of a
  parameter vector `["... ?" x]`; HoneySQL raw fragments. (CWE-89)
- Command exec: `clojure.java.shell/sh` / `(ProcessBuilder. ...)` with arg strings
  from input.
- SSRF / deserialization: `clj-http`/`slurp` on a user URL; `nippy/thaw` or Java
  `ObjectInputStream` interop on untrusted bytes.
Easy-to-miss logic faults:
- Lazy-seq side effects: a security check inside a lazy `map`/`filter` that is never
  realized (result not consumed) → the check never runs.
- nil punning: `(get m k)` returning nil treated as a deny when it is a silent pass;
  `false`/`nil` collapsing in a conditional that gates access."#;

pub(super) const HASKELL_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Command/SQL: `System.Process` `callCommand`/`shell` (spawns via /bin/sh) with an
  interpolated string — use `proc exe [args]`; `postgresql-simple`/`persistent` raw
  `Query` built with `<>`/`printf` instead of `?`-params or the `sql` quasi-quoter. (CWE-89)
- Unsafe escape hatches: `unsafePerformIO`, `unsafeCoerce`, `System.IO.Unsafe` —
  they break the type/effect guarantees the rest of the code relies on.
- Deserialization/parsing: `read` on untrusted input can loop or throw;
  `Data.Binary`/`cereal` `decode` of attacker bytes; `aeson` decode into a partial record.
- Partial functions on external input: `head`/`tail`/`fromJust`/`!!` or a
  non-exhaustive `case` — a crafted input triggers an exception (DoS) or skips a branch.
- SSRF: `http-client`/`wreq` on a user-controlled URL.
Easy-to-miss logic faults:
- Laziness: a validating expression whose result is never forced (`seq`/bang) is
  never evaluated → the check is skipped while appearing present.
- `Integer` (unbounded) vs `Int` (machine word) confusion → overflow/truncation in
  an index or size derived from input.";

pub(super) const OCAML_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Command/SQL: `Unix.system`/`Unix.open_process` (via the shell) with a built string
  — prefer `Unix.create_process exe [|args|]`; raw SQL strings to `postgresql`/`sqlite3`
  instead of bound params. (CWE-89)
- Unsafe casts: `Obj.magic`, `Obj.repr`, and `Marshal.from_*` on untrusted bytes —
  Marshal is NOT type-safe; crafted input causes memory unsafety / RCE.
- Partial functions: `List.hd`/`List.assoc`/`Option.get`/non-exhaustive `match` on
  external input → `Not_found`/`Match_failure` (DoS) or a skipped branch.
- FFI: `external` C stubs handling buffers/lengths from input without bounds checks.
- SSRF / file: `cohttp`/curl on user URLs; `open_in`/`Sys.command` on input paths
  without a fixed-base containment check.
Easy-to-miss logic faults:
- Polymorphic `compare`/`=` on values containing functions/closures raises at
  runtime; structural `=` on cyclic data loops.
- `int` is 63-bit and wraps silently — a size/index derived from input overflows
  with no exception.";

pub(super) const FSHARP_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- SQL: string-interpolated queries (`$"... {x}"`) to `SqlCommand`/Dapper/EF Core
  `FromSqlRaw`; bound parameters are safe, interpolation is not. (CWE-89)
- Command exec: `System.Diagnostics.Process.Start` with a built argument string;
  shelling out / `dotnet fsi --exec` on input.
- Deserialization: `BinaryFormatter`/`NetDataContractSerializer` on untrusted bytes
  (RCE); `Type.GetType(userName)`; FsPickler Binary on untrusted input.
- Reflection: `Activator.CreateInstance`/`MethodInfo.Invoke` on input-named types.
- SSRF: `HttpClient`/`WebRequest` with a user-controlled host; redirect to internal ranges.
Easy-to-miss logic faults:
- `obj`-boxing / `:?>` downcast on external data throws or type-confuses; an `Option`
  matched with a wildcard `_ ->` that silently treats `None` as success.
- Lazy / `seq` computations carrying a security side-effect that is never enumerated."#;

pub(super) const JULIA_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Command exec: backtick command literals run via `run`/`read` are arg-safe per
  interpolation, BUT a single interpolated string passed to `sh -c "$x"` (or
  `Cmd(string)`) is injectable. (CWE-78)
- Code eval: `eval`, `Meta.parse` + `eval`, `include_string`, `@eval` on untrusted
  strings → arbitrary code execution.
- SQL: LibPQ/MySQL/SQLite with string-built queries instead of parameter binding. (CWE-89)
- Deserialization: `Serialization.deserialize` / JLD2 / BSON load of untrusted bytes
  can construct arbitrary types (RCE) — not safe for untrusted data.
- SSRF / file: `HTTP.get(userurl)`, `download`, `open(path)` from input without a
  fixed-base check.
Easy-to-miss logic faults:
- `@inbounds` disabling bounds checks on an index derived from input → OOB access.
- `parse(Int, s)` throwing on bad input — unhandled it aborts (DoS), or it is
  `try`-swallowed past a security check."#;

pub(super) const SOLIDITY_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Reentrancy: an external call (`.call{value:}`, `.transfer`, token `transferFrom`,
  ERC-777 hooks) BEFORE state updates — apply checks-effects-interactions or a
  `nonReentrant` guard. (CWE-841)
- Access control: state-changing / `selfdestruct` / `delegatecall` / owner-setter
  functions missing `onlyOwner`/role modifiers or left `public`/`external`;
  uninitialized owner; `tx.origin` used for authz (phishable — use `msg.sender`).
- Arbitrary delegatecall / proxy: `delegatecall` to an address from input, or an
  upgradeable proxy whose implementation slot is settable by non-admin → full takeover.
- Unchecked low-level call: `(bool ok,) = addr.call(...)` whose `ok` is ignored;
  unchecked ERC-20 return values.
- Arithmetic & funds: pre-0.8 overflow without SafeMath; rounding/precision loss in
  share math; `block.timestamp`/`blockhash` as randomness (miner-influenced); price
  read from a single spot AMM (oracle manipulation).
Easy-to-miss logic faults:
- Storage-collision in proxies / mis-ordered inherited state variables.
- Default visibility, shadowed state vars; a `require` with `||` where one clause is
  always true → the check is effectively disabled.";

pub(super) const ASSEMBLY_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Missing bounds before a copy/loop: `rep movs`/`stos`, hand-written memcpy loops,
  or a `lodsb`/`stosb` loop whose counter (length register) comes from input without
  a max cap → buffer overflow. (CWE-120)
- Stack frames: writes past an allocated `sub rsp, N` frame; `ret` after a buffer
  write with no canary/check; argument/length registers trusted as-is.
- Indirect control flow: `call`/`jmp` through a register or table index computed from
  input without a range check → control-flow hijack.
- Sign/width: a 32-bit length used in a 64-bit copy, or a signed compare (`jl`/`jg`)
  on an attacker length so a negative value passes a `> max` check then wraps.
- Syscalls: arguments (paths, fds, sizes) to `int 0x80`/`syscall` taken from input
  without validation.
Easy-to-miss logic faults:
- Stale flags: a branch keyed on a flags register that an intervening instruction
  altered (ZF/CF) so a security compare is read wrong.
- Off-by-one in `<=` vs `<` loop terminators on a buffer index.";

pub(super) const ZIG_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Overflow in unchecked builds: arithmetic in `ReleaseFast`/`ReleaseSmall` (overflow
  is UB there) on input-derived values; `@intCast`/`@truncate`/`@ptrCast` narrowing a
  size or index from input. (CWE-190)
- Slicing: `slice[a..b]` / `ptr[0..len]` where `a`,`b`,`len` come from input without
  validating against the backing length → OOB; a `[]const u8` length trusted from a header.
- Allocator misuse: use-after-free / double-free across `defer`/`errdefer` paths;
  `alloc` size = `count * elem` with no overflow check.
- C interop: `@cImport`/`extern` calls passing Zig slices to C without the length the
  C side expects; `ChildProcess`/`std.c.system` with built args.
- Untrusted parsing: `std.json` or a custom parser reading a length field then
  copying/seeking that many bytes without capping to the buffer.
Easy-to-miss logic faults:
- `catch unreachable` / `orelse unreachable` on an error/null an attacker can trigger
  → panic (DoS) or, in unchecked builds, UB.
- Reading `undefined`-initialized memory before it is set on an error path.";

pub(super) const NIM_HINT: &str = r#"Where to look first (non-exhaustive — reason beyond this list):
- Command exec: `execShellCmd`, `osproc.execProcess`/`startProcess` with
  `{poEvalCommand}`, or `execCmd` on a built string (goes through the shell) — prefer
  arg-array `startProcess` with a fixed exe. (CWE-78)
- Compile-time / FFI: `staticExec` (compile-time shell), `{.emit.}`/`importc` passing
  input to C without bounds checks.
- SQL: `db_postgres`/`db_mysql` `exec(sql"..." & x)` string-built instead of `?`
  bound args. (CWE-89)
- Bounds/overflow: `--checks:off` / `-d:danger` builds disable bounds & overflow
  checks — a `seq`/`array` index or `cast[T]` from input becomes OOB/UB; raw `ptr`/`addr`
  arithmetic.
- SSRF / file: `httpclient` on a user URL; `open`/`readFile` on an input path with no
  fixed-base containment.
Easy-to-miss logic faults:
- `cast[T](x)` reinterprets bits with no check (unlike a converter) — type/size
  confusion on input-derived values.
- An exception from `parseInt`/indexing swallowed by a bare `except:` past a security
  check, so execution continues on bad data."#;

pub(super) const CRYSTAL_HINT: &str = r"Where to look first (non-exhaustive — reason beyond this list):
- Command exec: `system`, backticks, or `Process.run` with `shell: true` and an
  interpolated string — prefer `Process.run(exe, [args])` with a fixed binary. (CWE-78)
- SQL: `crystal-db`/`crystal-pg` queries built with `#{}` interpolation instead of
  `?`/`$1` bound parameters. (CWE-89)
- Deserialization: `YAML.parse`/`from_yaml` and `Object.from_json` into types with
  custom converters on untrusted input.
- SSRF / file: `HTTP::Client.get(userurl)`; `File.open`/`File.read` on an input path
  without a fixed-base + expand-path containment check.
- Unsafe pointers / C bindings: `Pointer`/`Slice` built from an input length; `lib`/
  `fun` C calls passing buffers without the expected length.
Easy-to-miss logic faults:
- `as` unsafe cast / `not_nil!` on attacker-influenceable values → raises (DoS) or
  type-confuses; a `rescue` clause swallowing the error past a security gate.
- Wrapping operators `&+`/`&*` on input-derived sizes silently wrap (Crystal raises
  on plain `+`/`*` overflow by default, so these are the dangerous ones).";
