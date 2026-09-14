// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! Language-specific researcher hints + specialist researcher bodies, ported
//! verbatim from `vvaharness/lang/hints.py`'s `LANG_HINTS` (42 keys),
//! `SPECIALIST_HINTS` (6 keys), and `FRAMEWORK_HINTS` (currently only a
//! `"java"` key, 7 framework entries) dicts, plus the `_framework_blocks`/
//! `hints_for` dispatch functions at the end of that file.
//!
//! Each block is injected into the s4 deep-dive prompt so the researcher gets
//! language-appropriate "where to look" guidance instead of a generic brief.
//! Hints are seeds, not checklists — the researcher is told to reason past
//! them. Every hint body below is a byte-for-byte transcription of the
//! corresponding Python triple-quoted string literal (after Python's own
//! escape decoding — e.g. the two UNC-path hints and the Java CRLF hint
//! contain literal backslashes that came from `\\` / `\r\n` escapes in the
//! non-raw Python string).
//!
//! Four keys deliberately go **beyond** that transcription, because the
//! Python table's bodies for them were a handful of bullets while the
//! scanner's own `VulnClass` carries memory-safety classes
//! (`UseAfterFree`, `HeapOverflow`, `StackOverflow`, `FormatString`,
//! `IntegerOverflow`, `TypeConfusion`) that nothing in the prompt pointed
//! the researcher at:
//!
//! - [`C_HINT`] (`"c"`) and [`CPP_HINT`] (`"cpp"`/`"c-cpp"`, which is
//!   `C_HINT` plus [`CPP_EXTRA`]) — the memory-safety classes first, then
//!   format string, TOCTOU, command and path.
//! - `"swift"` and `"scala"` — mobile and JVM-Scala specifics the two
//!   original bullet lists did not reach.
//!
//! `EXT_TO_LANG` groups C and C++ under one `"c-cpp"` key, which is the
//! right granularity for a language-mix vote but not for a research lens;
//! [`hint_key_for_path`] splits it back per file so a pure-C++ chunk gets
//! the C++ half and a pure-C chunk is not lectured about iterators.

use std::sync::LazyLock;

use regex::Regex;

/// `SPECIALIST_HINTS.get(specialist, "")` ported 1:1: hint body for a
/// repo-wide specialist sweep (crypto / logic-bug / access-control /
/// deserialization / batch-etl / iac), or `""` for an unrecognized key —
/// matching Python's dict-`.get` default-value semantics exactly (never
/// panics on an unknown key).
pub fn specialist_hint(specialist: &str) -> &'static str {
    match specialist {
        "crypto" => {
            r#"You are reviewing the cryptography, key-handling, and security-protocol
surfaces of this codebase. Target weaknesses an attacker can exploit
mathematically or by abusing protocol negotiation — not generic "uses MD5
somewhere" hygiene items.

Where to look first (non-exhaustive — reason beyond this list):
- Secret/HMAC/token equality checks done with `==` / `equals` / `memcmp`
  instead of a constant-time comparator — early-exit leaks match length.
- Signature/JWT verification that reads the algorithm or key-id from the
  token itself and trusts it (alg=none, HS↔RS key confusion, kid path
  traversal).
- Symmetric encryption where the IV/nonce is constant, predictable, or
  derived from data the attacker can replay (GCM nonce reuse = full key
  compromise of authenticity).
- Security-relevant randomness drawn from non-CSPRNG sources
  (`Math.random`, `rand()`, `Random()`, `random.random`) for tokens, IVs,
  keys, OTPs, reset codes.
- TLS / signature verification that is wired up but not enforced — empty
  trust managers, hostname checks returning `true`, verify result ignored.
- Hard-coded keys, salts, or passphrases in source or config; key bytes
  written to logs or error messages."#
        }
        "logic-bug" => {
            r#"You are reviewing for behavioural / state-machine defects — the class of bug
that has no single grep signature and only surfaces when you reason about
ordering, concurrency, and edge-case inputs.

HARD GATE — for every finding you MUST cite the exact trust boundary that is
crossed: the file:line where untrusted/external input enters, and the file:line
where the security decision is made on that input. If both sides are internal
(service-to-service, same trust domain, idempotent retry, intentional design),
DROP the finding. No trust-boundary citation → no finding.

Reason about behaviour, don't pattern-match. Seed questions:
- Check-then-act windows: between the permission/ownership/balance check and
  the mutation, can a second request, another thread, or a filesystem actor
  change what was checked?
- Auth/session state: what does the login or step-up flow do on empty, null,
  duplicated, or out-of-order messages? Can two concurrent requests against
  one session leave it half-authenticated?
- Numeric identity and counters: what happens at overflow, at zero, at
  negative after a narrowing cast? Does an ID truncated to 32-bit collide
  with a privileged record?
- Connection/protocol state: can a malformed or truncated message leave the
  parser mid-state so the NEXT request on the same connection is
  misinterpreted?
- Caches and memoised decisions: is the cache key missing the
  tenant/user/role dimension, so one principal's result is served to
  another? Does a cached "authorised" decision outlive a revocation?
- Sentinel return values: is the result of indexOf/find/search (which returns
  -1 / null when the token is absent) used as an offset or length WITHOUT the
  `== -1` guard, so "not found" silently becomes position 0 or a wrong
  substring slice? Same for parseInt→NaN or a lookup returning null treated as
  success."#
        }
        "access-control" => {
            r#"You are an Authorization / access-control expert. Hunt for IDOR (BOLA),
missing or incorrect authorization checks, horizontal/vertical privilege
escalation, and multi-tenant isolation bypass. The bug here is usually the
ABSENCE of a check — you are looking for what is NOT there.

HARD GATE — for every finding you MUST show:
  (a) the entry point (controller/handler/route) and the identity it
      authenticates as, and
  (b) the object/resource it acts on and WHERE ownership/tenant/role is
      verified for THAT object.
If (b) exists and is correct, DROP the finding. "Endpoint requires login" is
NOT authorization — the question is whether the logged-in user may act on
THIS specific record. A target that is a FIXED/HARDCODED constant (not derived
from the request) is NOT attacker-varied — it is at most a single-record issue
with bounded blast radius, NOT arbitrary/broad object access; do not label it
IDOR/BOLA. Do in depth analysis to confirm first.

When a handler appears to be missing an authentication/authorization check at
all, FLAG it rather than adjudicating it. You have no file access — only this
slice and the neighbor excerpts — so the file that REGISTERS the route is
usually not in front of you. If the registration IS in the code you were given
and the route sits behind framework middleware, a filter or an annotation
(Laravel `->middleware('auth')`, Ktor `authenticate { }`, Rails
`before_action`, axum `.route_layer(...)`, Spring `@PreAuthorize`, ASP.NET
`[Authorize]`), it is already checked on every request, so report it only with
a concrete bypass or a registration the guard does not cover. If the
registration site is not in the code you were given, still report it: say so
in `preconditions` and set `confidence` to 0.6 — below a finding you fully
verified, but NOT under 0.6, which is where the pre-verify gate drops a
finding before any verifier sees it. A verifier with repository access opens
the registration file and checks the guard afterwards.

Where to look first (non-exhaustive — reason beyond this list):
- Enumerate every externally reachable handler (Spring: @RequestMapping/@Get/
  @Post…, JAX-RS: @Path, servlets, message listeners). For each: what object
  ID comes from the request (path var, query, body)? Is that ID checked
  against the caller's identity/tenant before load/update/delete?
- Direct object references: findById(request.id), repository.getOne(id),
  file paths or S3 keys built from request fields — can user A pass user B's ID?
- Missing guards: methods with @PreAuthorize/@Secured/@RolesAllowed on
  siblings but NOT on this one; service-layer methods callable from multiple
  controllers where only some callers check authz.
- Vertical escalation: admin-only operations reachable via non-admin routes;
  role checks that compare strings case-sensitively or trust a role claim
  from the request body/JWT without signature verification.
- Mass assignment: request DTO bound directly to an entity (Spring
  @ModelAttribute / Jackson into JPA entity) letting a caller set owner_id,
  role, isAdmin, tenantId, price.
- Multi-tenant leakage: queries that filter by id but not tenant_id; caches
  or singletons keyed only by object id.
- Destructive bulk operations: deleteAll() / truncate / "DELETE FROM t" or a
  bulk UPDATE with no WHERE / owner / tenant scope, or a schema reset/drop
  reachable from a request — one call wipes or overwrites every record, not
  just the caller's. Treat an unscoped destructive bulk op as a first-class
  high-impact finding, not a lesser issue."#
        }
        "deserialization" => {
            r"You are an Unsafe-deserialization expert. Hunt for deserialization of
attacker-influenced bytes through libraries that invoke code during object
reconstruction — the dominant remote-code-execution vector on the JVM.

HARD GATE — a finding requires BOTH:
  (a) a deserializer call site, AND
  (b) a path from untrusted input (HTTP body/header/param, message queue,
      file upload, cache, DB blob written by another tenant) to that call.
Deserializing your own freshly-serialized data, or data signed/HMAC'd before
serialize and verified before deserialize, is NOT a finding. Cite both
file:line points or drop it.

Where to look first (non-exhaustive — reason beyond this list):
- Java native: ObjectInputStream.readObject / readUnshared, Serializable +
  readObject/readResolve overrides, RMI/JMX/JNDI endpoints, Apache Commons
  SerializationUtils.
- Jackson: ObjectMapper with enableDefaultTyping / activateDefaultTyping,
  @JsonTypeInfo(use = Id.CLASS or Id.MINIMAL_CLASS), PolymorphicTypeValidator
  set to LaissezFaire, or polymorphic fields typed as Object/Serializable.
- XML: XMLDecoder, XStream without a hardened allow-list (fromXML on request
  data), JAXB with XmlAdapter that instantiates by class name.
- YAML: SnakeYAML new Yaml() / Yaml(new Constructor()) on untrusted input
  (allows !!javax.script… etc.); only SafeConstructor is safe.
- Others: Kryo, Hessian/Burlap, FST, Spring DefaultDeserializer,
  RedisTemplate with JdkSerializationRedisSerializer where Redis is shared.
- Mitigation check: is an ObjectInputFilter / serialFilter / class allow-list
  applied BEFORE readObject? If yes, evaluate whether the allow-list itself
  admits a known gadget (e.g. permits java.util.*, org.apache.commons.*)."
        }
        "batch-etl" => {
            r#"You are a Batch / ETL data-pipeline expert. The target is a file-in →
transform → file-out job (mainframe-migrated or scheduler-driven). The
attacker model is: an upstream producer, scheduler/operator parameter, or
shared landing directory — NOT an interactive web user.

HARD GATE — for every finding cite (a) the externally-influenced value
(job parameter, env var, upstream record field, filename in a watched dir)
and (b) the file:line where it reaches a path, command, SQL, or output
record WITHOUT validation. If both producer and consumer are inside the
same trust domain and the value cannot be set by a lower-privileged party,
DROP it.

Where to look first (non-exhaustive — reason beyond this list):
- Job parameters / env vars (sys.argv, os.environ, JCL PARM=, scheduler
  variables) flowing into open()/Path()/shutil.* / os.remove without a
  fixed base-directory + realpath check — path traversal lets an upstream
  caller read/overwrite arbitrary files as the batch service account
- Output filenames or staging dirs derived from input RECORD fields
  (account no, merchant id) — traversal / collision via crafted records
- Shared landing / spool directories: glob('*.dat') or "pick newest by
  mtime" where any writer to that dir can plant a file the job will
  ingest or overwrite (TOCTOU / untrusted-producer)
- Fixed-width / packed-decimal (COMP-3) / EBCDIC parsing: length taken
  from the record header and used to slice/seek without capping to the
  buffer; sign-nibble / zone-nibble not validated → negative amounts or
  index wrap; off-by-one between COBOL 1-based PIC offsets and Python
  0-based slices
- Record-count / hash-total trailer NOT verified against the body —
  truncation or injection of extra records goes undetected
- Emitted CSV / report files: cells sourced from input records written
  without stripping leading = + - @ (formula injection into downstream
  Excel consumers)
- subprocess / os.system invoking sort, sftp, gpg, db loaders with
  arguments built from job params or record fields
- Idempotency / restart: checkpoint files or "processed" markers in a
  world-writable dir; rerun after partial failure double-posts records"#
        }
        "iac" => {
            r#"You are an Infrastructure-as-Code / cloud-config security expert. Targets
in scope include Terraform/HCL, Dockerfiles, Kubernetes & Helm manifests,
GitHub Actions / GitLab CI / Jenkinsfiles, Ansible, docker-compose, and
CloudFormation. Hunt for misconfigurations that expose data, escalate
privilege, or let an attacker inject code into the build / deploy pipeline.

HARD GATE — every finding MUST cite the specific resource block / step /
directive (file:line) AND the security property it violates (least
privilege, network isolation, supply-chain integrity, secret hygiene).
Aspirational best-practice items with no concrete attack path → LOW.
Vendor-default settings that match the platform baseline are NOT findings.

Where to look first (non-exhaustive — reason beyond this list):

TERRAFORM / HCL
- IAM policies with "*" Action or Resource; trust policies allowing
  wildcard principals or sts:AssumeRole without ExternalId on cross-account
- aws_s3_bucket without block_public_access / server_side_encryption,
  publicly_accessible RDS / Redshift, security groups with 0.0.0.0/0 on
  sensitive ports (22 / 3389 / 3306 / 5432 / 6379 / 9200 / 27017)
- Hardcoded credentials in resource args, user_data, template_file vars;
  provider blocks with literal access_key / secret_key
- aws_ssm_parameter as String instead of SecureString
- Audit disabled: CloudTrail off, S3 access logging off, VPC flow logs off
- KMS keys without rotation; default tenant keys protecting sensitive data

DOCKERFILE / CONTAINERFILE
- No USER directive (or USER root) → container runs as root
- ADD <URL> instead of COPY; `RUN curl ... | sh` / `wget ... | bash` →
  unverified supply-chain fetch
- ENV / ARG carrying secrets — visible in image history layers
- FROM image:latest or unpinned tag → reproducibility / supply-chain
- COPY . . dragging .git / .env / build secrets into the final image
- Missing HEALTHCHECK, no apk/apt cache cleanup → larger surface

KUBERNETES / HELM
- securityContext.runAsUser: 0, runAsNonRoot: false, or missing securityContext
- privileged: true, allowPrivilegeEscalation: true, capabilities.add
  containing SYS_ADMIN / NET_ADMIN / NET_RAW / SYS_PTRACE
- hostPath volumes mounting /var/run/docker.sock, /, /etc, /proc, /sys
- hostNetwork / hostPID / hostIPC true
- Secrets with plaintext `data:` (not `stringData` from a sealed source);
  secrets injected via env where any pod-reader can read process env
- ServiceAccount bound to cluster-admin / wildcard RBAC
- LoadBalancer / NodePort exposing internal services without auth
- Missing NetworkPolicy on namespaces handling sensitive data

GITHUB ACTIONS / GITLAB CI / JENKINS
- pull_request_target + actions/checkout pointed at PR head ref + running
  scripts / installs from the checkout → RCE in trusted context with
  access to repo secrets
- ${{ github.event.* }} (issue title, PR title, branch name, commit
  message, body) interpolated into a `run:` step — command injection
- Third-party actions referenced by mutable tag (uses: org/x@v1, @main)
  instead of full commit SHA → supply-chain pin
- secrets.* passed to steps that execute untrusted code, or written into
  env / outputs where downstream steps log them
- Self-hosted runners on public repos without per-job isolation
- Jenkinsfile sh "..." / bat "..." with parameter interpolation; agent {
  docker { args ... } } using attacker-controlled args
- GitLab CI include: remote: ... pulling pipeline templates without SHA
  pinning; rules: that bypass approval gates on certain branches

ANSIBLE / DOCKER-COMPOSE / CLOUDFORMATION
- shell:/command: with {{ unsanitised_var }} from untrusted inventory
- become: yes on plays driven by untrusted inventory
- no_log: false on tasks handling secrets
- docker-compose privileged: true, pid: host, network_mode: host
- docker-compose volumes mounting /var/run/docker.sock → host escape
- CloudFormation IAM with "*", PublicAccessBlockConfiguration disabled
  on S3 buckets, EC2 SecurityGroups with 0.0.0.0/0 ingress

CROSS-CUTTING
- Hardcoded credentials anywhere (connection strings, JWT signing keys,
  cloud access keys, DB passwords) — even in samples or template files
- Disabled TLS verification: insecure_skip_verify = true, verify = false,
  --insecure / -k on curl/wget, GIT_SSL_NO_VERIFY = true
- Default / sample credentials shipped in templates or vault-encrypted
  defaults committed alongside the matching vault key

For each finding give a concrete remediation (the exact directive to add
or remove) and rate severity from real-world exposure: a public S3 bucket
in prod = HIGH; missing log-retention setting on a dev account = LOW."#
        }
        _ => "",
    }
}

/// The C body of the C-family hint, and the whole of the `"c"` key.
///
/// Memory safety leads because that is where the exploitable bugs are and
/// because the researcher has to reach for the right `VulnClass` —
/// use-after-free, heap/stack overflow, format string, integer overflow —
/// rather than a generic "buffer issue" the deduper cannot group. The
/// injection classes (command, path) and TOCTOU follow, since C reaches
/// for `system`/`popen` and `access`-then-`open` far more readily than the
/// managed languages do.
///
/// The `free()` bullet also says WHERE to report, not just what to look
/// for: a use-after-free anchored at the `free` instead of at the later
/// dereference lands outside the range anything downstream expects. The
/// general form of that rule is in `prompts::OUTPUT_SCHEMA`; this is the
/// C-shaped restatement, and [`CPP_HINT`] inherits it verbatim.
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
- Signed overflow and shifting into the sign bit are undefined behaviour, so
  a self-referential check like `if (a + b < a)` may be deleted outright by
  the optimiser."#;

/// The C++-only half, appended to [`C_HINT`] for the `"cpp"`/`"c-cpp"`
/// keys. Every C hazard is still live in a C++ translation unit, so this
/// is additive rather than a replacement: the containers and casts are
/// what C++ adds on top, not what it takes away.
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

/// `"cpp"`/`"c-cpp"`: [`C_HINT`] followed by [`CPP_EXTRA`]. A `LazyLock`
/// rather than a `concat!` because both halves are `const` items, not
/// literal tokens — still one canonical `String`, built once and handed
/// out by reference, so a hint body stays byte-identical across calls
/// (which is what the s4 prompt's caching wants).
static CPP_HINT: LazyLock<String> = LazyLock::new(|| format!("{C_HINT}\n\n{CPP_EXTRA}"));

/// `LANG_HINTS.get(lang)` ported 1:1: per-language "where to look first"
/// researcher hint body, or `None` if `lang` isn't one of the 42 keys the
/// Python table carries — plus the two extra C-family keys
/// [`hint_key_for_path`] can produce, which the Python table has no
/// equivalent for.
pub fn lang_hint(lang: &str) -> Option<&'static str> {
    Some(match lang {
        "c" => C_HINT,
        "cpp" | "c-cpp" => CPP_HINT.as_str(),
        "rust" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
  from safe code."#
        }
        "go" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
  JSON/YAML decode — wrong type panics the handler."#
        }
        "python" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
  re-validating it belongs to the current run/tenant"#
        }
        "java" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
  param), addHeader with unfiltered \r\n"#
        }
        "javascript" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
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
  (real shared memory) or multi-process deployment against a shared store."
        }
        "php" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
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
  `create_function`, or `call_user_func($_GET[...])`."
        }
        "ruby" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
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
  data; same for `Kernel.open(user)` (leading `|` runs a process)."
        }
        "objective-c" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
- Format-string sinks (`NSLog`, `-[NSString stringWithFormat:]`,
  `CFStringCreateWithFormat`) where the FORMAT argument itself is external
  data rather than a literal.
- Raw C buffers under the ObjC layer: `strcpy`/`sprintf`/`memcpy` on
  `[nsstr UTF8String]` or socket bytes without a bound.
- Custom URL-scheme / universal-link handlers: query items reaching
  `NSURL`, `openURL:`, file paths, or WebView loads unvalidated.
- Secrets or session tokens persisted to `NSUserDefaults`, plists, or
  unencrypted SQLite instead of Keychain."
        }
        "kotlin" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
- JVM deserialization surfaces inherited from Java: `ObjectInputStream`,
  Jackson polymorphic typing, SnakeYAML `Yaml()` on request bytes.
- Queries built with `$var` string templates in Exposed / JDBC / Room raw
  SQL rather than bound `?` parameters.
- (Android) exported `Activity`/`Service`/`Receiver`/`Provider` consuming
  `Intent` extras without validating origin or contents — intent redirection
  / extra-driven file/URL loads.
- `File(base, userInput)` / `Paths.get(user)` without canonicalising and
  asserting the result stays under the intended root.
- `Runtime.exec`/`ProcessBuilder` with string-template argv."
        }
        "csharp" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
- Newtonsoft `TypeNameHandling != None` on attacker-reachable JSON."#
        }
        "perl" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
  of execution reachability)"#
        }
        "swift" => {
            r#"Untrusted input reaches an app through another app or the network, not
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
  sensitive view not blanked on `applicationWillResignActive`."#
        }
        "scala" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
  configuration."#
        }
        "cobol" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
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
  alphanumeric data as numeric/packed without validation"
        }
        "jcl" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
- Look for symbolic parameters (&VAR) that flow into DSN=, PGM=, PARM=, or SYSIN — if
  callers/schedulers can set them, check for dataset-name or program-name injection
- Check DD statements with DISP=(MOD|OLD,DELETE) or IDCAMS DELETE/IEFBR14 steps that
  target datasets named via substitutable parameters
- Grep for IKJEFT01 / IRXJCL / BPXBATCH steps — TSO, REXX, or USS commands built from
  PARM= or SYSTSIN that include externally supplied values (command injection)
- Look for FTP/SFTP (FTP PARM=, BPXBATCH SH) or NJE transmit steps with hardcoded
  credentials in inline SYSIN or unprotected PARMLIB members
- Check RACF/ACF2 context: jobs that run under high-privilege USER= but accept
  operator-supplied or scheduler-supplied parameters"
        }
        "web-template" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
  in a CSS value."#
        }
        "dart" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
- Grep for Process.run / Process.start with runInShell: true or string-concatenated args
- Check platform channels (MethodChannel) — untrusted args from the native side reaching
  File/Process/db without validation, or sensitive ops exposed to the platform
- Look for WebView (webview_flutter / InAppWebView) with javascriptMode unrestricted
  loading user-controlled URLs, or addJavaScriptHandler exposing privileged Dart calls
- Check http/dio requests where the URL host is user-influenced (SSRF / open redirect)
- Look for File/Directory paths built from user input without normalization
- Check certificate handling: badCertificateCallback returning true, or
  HttpOverrides that disable TLS verification"
        }
        "elixir" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
- Grep for Code.eval_string / Code.eval_quoted / :erlang.binary_to_term on untrusted
  input (binary_to_term without [:safe] is RCE via atom/fun creation)
- Check String.to_atom / List.to_atom on user input — atom-table exhaustion DoS; use
  String.to_existing_atom instead
- Look for Ecto queries built with raw fragments: fragment("... #{x} ...") or
  Repo.query with interpolated SQL
- Check Phoenix templates for raw/1 or {:safe, ...} wrapping user content
- Grep for System.cmd / :os.cmd / Port.open({:spawn, ...}) with user-influenced args
- Check GenServer/Agent state for user-keyed maps that grow unbounded"#
        }
        "erlang" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
- Grep for binary_to_term/1 on network input (without the 'safe' option it creates
  atoms/funs → RCE); same for erlang:binary_to_atom/2 (atom-table DoS)
- Check os:cmd/1 and open_port({spawn, Cmd}, ...) for shell-interpreted user input
- Look for distributed-Erlang exposure: net_kernel started with a guessable cookie or
  epmd reachable from untrusted networks (full node RCE)
- Check ETS tables keyed by user input for unbounded growth
- Look for file:open / file:read_file with user-controlled paths"
        }
        "groovy" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
- Grep for GroovyShell.evaluate / Eval.me / GroovyScriptEngine / @Grab on user input —
  direct RCE; Jenkins Script Console / shared-library code is a common sink
- Check GString SQL: "SELECT ... ${x}" passed to Sql.execute/rows instead of
  parameterized GString placeholders
- Grep for "cmd".execute() / ["sh","-c", x].execute() / ProcessBuilder with user input
- Look for XmlSlurper/XmlParser without disabling DOCTYPE/external entities (XXE)
- Inherits all Java sinks: ObjectInputStream, JNDI lookup, SpEL/OGNL evaluation"#
        }
        "lua" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
- Grep for load / loadstring / loadfile / dofile with user-influenced source — RCE
- Check os.execute / io.popen for shell-interpreted user input
- In OpenResty/nginx-lua: ngx.var.* or ngx.req.get_*_args() flowing into ngx.location.capture,
  resty.http, or redis/db queries built via string concat (SSRF / injection)
- Check string.format("%s") used to build SQL/shell/redis commands from request data
- Look for setfenv/_ENV or debug.* exposed to sandboxed user scripts (sandbox escape)
- Check io.open paths derived from request input (path traversal)"#
        }
        "r" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
- Grep for eval(parse(text=...)) / source() / do.call where the expression or function
  name comes from request input (Shiny input$*, plumber params)
- Check system / system2 / shell / pipe with user-influenced arguments
- Look for SQL built via paste()/sprintf()/glue() and sent through DBI::dbGetQuery /
  dbExecute instead of dbBind / sqlInterpolate
- Check readRDS / load / unserialize on uploaded or fetched files — arbitrary code via
  promise/active-binding deserialization
- In Shiny/plumber: file download/read endpoints where the path includes input$* without
  normalizePath + base-directory check"
        }
        "powershell" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
- Grep for Invoke-Expression / iex / Invoke-Command -ScriptBlock built from user input,
  and Add-Type / [ScriptBlock]::Create with external strings — direct code execution
- Check Start-Process / & "..." / cmd /c where arguments are interpolated "..." strings
  containing user input (use argument arrays instead)
- Look for Invoke-WebRequest/Invoke-RestMethod where -Uri is user-controlled (SSRF) or
  whose response is piped straight into iex (download-cradle RCE)
- Check Get-Content/Set-Content/Remove-Item paths built from parameters without
  Resolve-Path under a fixed base (path traversal, wildcard injection)
- Look for ConvertTo-SecureString -AsPlainText / hardcoded PSCredential / secrets in
  transcripts; check for -SkipCertificateCheck / TrustAllCertsPolicy"#
        }
        "batch" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
  forced SMB auth leaks the runner's NTLMv2 hash."#
        }
        "ansible" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
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
- Inventory / group_vars committed with real hostnames + credentials"
        }
        "shell" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
- Grep for eval, bash -c, sh -c, backticks/$() that embed "$VAR" sourced from argv,
  env, or read — command injection via metacharacters
- Find unquoted variable expansions ($var instead of "$var") used as command arguments
  or in [ ] tests — word-splitting and glob injection
- Check curl/wget where the URL contains a variable, and any `curl ... | sh` pattern
- Look for filenames/paths from user input passed to rm/cp/mv/tar without `--` and
  without base-directory containment (option injection, traversal)
- Check `source` / `.` of files at user-writable or variable-derived paths
- Look for tempfile races: > /tmp/fixedname or `mktemp` output reused predictably;
  TOCTOU between [ -f ] check and use"#
        }
        "typescript" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
  shared store behind multiple processes."#
        }
        "sql" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
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
  authz check so execution continues."
        }
        "terraform" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
  wins, silently re-opening what an earlier block locked down."#
        }
        "vbnet" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
  `=` may match unintended casings; and `Nothing` vs `""` vs `0` conflation."#
        }
        "abap" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
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
- Client field (MANDT) omitted in a dynamic/native query → cross-client data access."
        }
        "clojure" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
  `false`/`nil` collapsing in a conditional that gates access."#
        }
        "haskell" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
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
  an index or size derived from input."
        }
        "ocaml" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
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
  with no exception."
        }
        "fsharp" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
- Lazy / `seq` computations carrying a security side-effect that is never enumerated."#
        }
        "julia" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
  `try`-swallowed past a security check."#
        }
        "solidity" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
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
  always true → the check is effectively disabled."
        }
        "assembly" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
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
- Off-by-one in `<=` vs `<` loop terminators on a buffer index."
        }
        "zig" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
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
- Reading `undefined`-initialized memory before it is set on an error path."
        }
        "nim" => {
            r#"Where to look first (non-exhaustive — reason beyond this list):
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
  check, so execution continues on bad data."#
        }
        "crystal" => {
            r"Where to look first (non-exhaustive — reason beyond this list):
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
  on plain `+`/`*` overflow by default, so these are the dangerous ones)."
        }
        _ => return None,
    })
}

/// The [`lang_hint`] key for a single file, sharpening the one place
/// `EXT_TO_LANG` is deliberately coarse.
///
/// `bc_repo_analysis::ext_to_lang` groups the whole C family under one
/// `"c-cpp"` key, which is the right granularity for a language-mix vote
/// but not for a research lens: the C++-only hazards (iterator
/// invalidation, `c_str()` lifetime, `reinterpret_cast`, exception safety)
/// are noise in a `.c` file, and a `.cpp` file needs them. So `.c`/`.h`
/// resolve to `"c"` and `.cc`/`.cpp`/`.cxx`/`.hpp` to `"cpp"` — the same
/// split `bc_repo_analysis::ts_graph` already applies when it picks a
/// tree-sitter grammar, so the two agree on what a given file is.
///
/// `.swift` -> `"swift"` and `.scala`/`.sc` -> `"scala"` need no split and
/// pass their `ext_to_lang` key through, as does every other extension.
/// `None` when no language claims the extension.
pub fn hint_key_for_path(path: &str) -> Option<&'static str> {
    let ext = bc_repo_analysis::suffix_lower(path);
    let key = bc_repo_analysis::ext_to_lang(&ext)?;
    Some(match (key, ext.as_str()) {
        ("c-cpp", ".c" | ".h") => "c",
        ("c-cpp", _) => "cpp",
        _ => key,
    })
}

// ---------------------------------------------------------------------------
// FRAMEWORK_HINTS — ported 1:1. Only `"java"` has entries in the Python
// source today (7 tuples: Spring/Spring Boot, JAX-RS/Jakarta REST, JPA/
// Hibernate, MyBatis, Struts 2, Servlet (raw), Android). All 7 marker
// regexes translate to the `regex` crate unchanged — none use lookahead/
// lookbehind, so no conservative rewrite was needed anywhere in this table.
//
// Structured as one `LazyLock<Regex>` + one body `const` per framework entry
// (matching the single-regex-per-static style used elsewhere in this
// codebase, e.g. `bc-repo-analysis/src/lang.rs`), wired together by
// `framework_entries`. Adding a new language key later is just: add its
// regex statics + body consts, then a new `match` arm in `framework_entries`
// returning its slice — the dispatch in `framework_blocks` needs no changes.
// ---------------------------------------------------------------------------

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

// Explicit `static` (rather than building the array inline inside the
// `match` below) because a `&'static [...]` return type needs the array's
// storage to actually live in static memory — rustc's rvalue-static-
// promotion does not kick in for a temporary array of `&'static
// LazyLock<Regex>` elements inside a function body (E0515), so it must be
// named as its own `static` item instead.
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

/// Byte offset of the boundary after the `max_chars`-th `char` of `s` (or
/// `s.len()` if `s` has fewer chars) — always a valid `str` slice boundary.
/// Used to reproduce Python's `code[:200_000]` *character* slice without
/// panicking on a byte offset that lands mid-UTF-8-sequence.
fn char_boundary(s: &str, max_chars: usize) -> usize {
    s.char_indices()
        .nth(max_chars)
        .map(|(i, _)| i)
        .unwrap_or(s.len())
}

/// Framework hints for the first 3 of `languages`, gated on each entry's
/// marker regex matching within `code`'s first 200,000 chars. Ported from
/// `_framework_blocks`. Returns `"── {name} (detected) ──\n{body}"` blocks
/// for every marker that matched, in table order (language order outer,
/// table order inner — matching the Python nested-loop order exactly).
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

/// Ported from `hints_for(languages, specialist, code)`: builds the hint
/// block injected into a researcher's system prompt.
///
/// - If `specialist` is `Some`, returns `specialist_hint(specialist)` alone
///   — framework/language hints are NEVER added to a specialist chunk; the
///   two branches are mutually exclusive, exactly like the Python original
///   (`if specialist: return SPECIALIST_HINTS.get(specialist, "")`).
/// - Otherwise, for the first 3 entries of `languages`, looks up
///   [`lang_hint`] and — if found — wraps it
///   `"── {display_name} ──\n{block}"` (display name via
///   `bc_repo_analysis::lang_display`), then, if `code` is `Some` and
///   non-empty, appends [`framework_blocks`]'s output the same way. Parts
///   are joined with `"\n\n"`. Returns `""` if nothing matched anywhere.
pub fn hints_for(languages: &[&str], specialist: Option<&str>, code: Option<&str>) -> String {
    if let Some(specialist) = specialist {
        return specialist_hint(specialist).to_string();
    }

    let mut parts: Vec<String> = Vec::new();
    for lang in languages.iter().take(3) {
        if let Some(block) = lang_hint(lang) {
            let name = bc_repo_analysis::lang_display(lang);
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
        assert_eq!(SPECIALIST_KEYS.len(), 6);

        // Spot-check a distinctive phrase per key so a mis-wired match arm
        // (wrong body swapped to the wrong key) would fail loudly.
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

    /// The knowledge behind `bc_stage_s5::lang_gates`' race gate, in the
    /// two languages that produced the 2026-09-06 Juice Shop false
    /// positives. S4 raising fewer of these is cheaper than S6 refuting
    /// them one agentic session at a time.
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

    /// The knowledge behind the same module's template-escaping gate.
    #[test]
    fn the_web_template_hint_separates_escaped_constructs_from_raw_ones() {
        let hint = lang_hint("web-template").unwrap();
        assert!(hint.contains("HTML-escape by default"));
        // Escaping covers `=`, which is why an unquoted Handlebars
        // attribute value is safe — the `{{userEmail}}` field case.
        assert!(hint.contains("even an unquoted attribute value is safe"));
        assert!(hint.contains("ONLY these are raw"));
        assert!(hint.contains("is a FALSE POSITIVE"));
        for raw in ["{{{ }}}", "!{ }", "<%- %>", "|safe", "{!! !!}", "v-html"] {
            assert!(hint.contains(raw), "missing {raw}");
        }
    }

    /// The C hint has to name the `VulnClass` variants it is there to
    /// steer toward — nothing else in the prompt chain mentions
    /// use-after-free, format-string or integer-overflow — and cover the
    /// non-memory classes C reaches for far more readily than a managed
    /// language does (TOCTOU, `system`, path).
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

    /// The 2026-09-07 polyglot C app lost a row to a use-after-free the
    /// model found but anchored at the `free()`. The schema carries the
    /// general rule; the `free()` bullet has to repeat it in C's own terms
    /// where the researcher is actually walking the pointer's lifetime.
    #[test]
    fn the_c_hint_says_to_report_a_use_after_free_at_the_later_use() {
        let hint = lang_hint("c").unwrap();
        assert!(
            hint.contains(
                "Report either at\n  that later use — the dereference, or the second `free` — not at the\n  `free` that set it up."
            ),
            "{hint}"
        );
        // Same sentence, one bullet, in both C-family keys — `CPP_HINT` is
        // `C_HINT` plus `CPP_EXTRA`, so it inherits rather than restates.
        for key in ["cpp", "c-cpp"] {
            let cpp = lang_hint(key).unwrap();
            assert_eq!(
                cpp.matches("not at the\n  `free` that set it up.").count(),
                1,
                "{key}"
            );
        }
    }

    /// `"cpp"` and `"c-cpp"` are the C body plus the C++ body: every C
    /// hazard is still live in a C++ translation unit, so the split is
    /// additive, never a replacement.
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
        // The coarse `EXT_TO_LANG` key a mixed chunk keeps must carry both
        // halves, since either flavour may be in it.
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

    /// The routing half of the C/C++ split, plus the two keys that need no
    /// split at all: every one of the four extensions the deep-dive gained
    /// hints for must resolve to a body.
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
        // Uppercase and a directory-qualified name both normalise.
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
        // "java" appears 4th; its Spring marker must NOT be picked up.
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
        // Regression guard: a naive byte-index slice (`&code[..200_000]`)
        // panics if byte 200_000 lands mid-UTF-8-sequence. Build a string
        // whose char count straddles a small cap with multi-byte chars so
        // the boundary logic is exercised, not just documented.
        let s: String = "€".repeat(10);
        assert_eq!(char_boundary(&s, 5), 15); // 5 chars * 3 bytes each
        assert_eq!(char_boundary(&s, 100), s.len());
        let _ = &s[..char_boundary(&s, 5)]; // must not panic
    }
}
