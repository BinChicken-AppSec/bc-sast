//! Finding gRPC server registrations in source code, statically, so the
//! services a `.proto` file defines can be checked against the services
//! the code serves. Each match is a citation: the file, the 1-based line
//! and the matched text.
//!
//! | Language | Registration recognized | Service |
//! |---|---|---|
//! | Go | `pb.RegisterGreeterServer(s, ...)`, grpc-gateway's `RegisterGreeterHandlerServer(...)` | `Greeter` |
//! | Python | `add_GreeterServicer_to_server(...)` | `Greeter` |
//! | Java, Kotlin | `extends GreeterGrpc.GreeterImplBase`, `GreeterGrpcKt.GreeterCoroutineImplBase` | `Greeter` |
//! | C# | `: Greeter.GreeterBase` | `Greeter` |
//! | JavaScript, TypeScript | `server.addService(proto.Greeter.service, ...)`, `addService(GreeterService, ...)` | `Greeter` |
//! | Rust (tonic) | `GreeterServer::new(...)`, `GreeterServer::from_arc(...)` in a file that uses tonic | `Greeter` |
//! | C++ | `: public Greeter::Service` (also `CallbackService`, `AsyncService`) | `Greeter` |
//!
//! A registration built another way (reflection, a generic helper, a
//! framework that hides it) is not found, so a service without a match
//! is reported as unverified, never as wrong.

use std::sync::LazyLock;

use regex::Regex;

use crate::inventory::CitedOperation;

struct Pattern {
    extensions: &'static [&'static str],
    /// The file must mention this for its matches to count.
    requires: Option<&'static str>,
    regex: LazyLock<Regex>,
}

static PATTERNS: [Pattern; 7] = [
    Pattern {
        extensions: &["go"],
        requires: None,
        regex: LazyLock::new(|| Regex::new(r"\bRegister([A-Z]\w*?)(?:Handler)?Server\(").unwrap()),
    },
    Pattern {
        extensions: &["py"],
        requires: None,
        regex: LazyLock::new(|| Regex::new(r"\badd_(\w+?)Servicer_to_server\(").unwrap()),
    },
    Pattern {
        extensions: &["java", "kt"],
        requires: None,
        regex: LazyLock::new(|| {
            Regex::new(r"\b(\w+)Grpc(?:Kt)?\.\w+?(?:Coroutine)?ImplBase\b").unwrap()
        }),
    },
    Pattern {
        extensions: &["cs"],
        requires: None,
        regex: LazyLock::new(|| Regex::new(r":\s*(\w+)\.(\w+)Base\b").unwrap()),
    },
    Pattern {
        extensions: &["js", "mjs", "cjs", "ts", "mts", "cts"],
        requires: None,
        regex: LazyLock::new(|| {
            Regex::new(r"\baddService\(\s*(?:[\w.]*?\.)?(\w+?)(?:\.service|Service)\b").unwrap()
        }),
    },
    Pattern {
        extensions: &["rs"],
        requires: Some("tonic"),
        regex: LazyLock::new(|| Regex::new(r"\b(\w+)Server::(?:new|from_arc)\(").unwrap()),
    },
    Pattern {
        extensions: &["cc", "cpp", "cxx", "h", "hpp"],
        requires: None,
        regex: LazyLock::new(|| {
            Regex::new(r"\bpublic\s+(\w+)::(?:Callback|Async)?Service\b").unwrap()
        }),
    },
];

/// Whether `path` is a source file the scan reads.
pub fn is_source(path: &str) -> bool {
    let extension = path.rsplit_once('.').map_or("", |(_, extension)| extension);
    PATTERNS
        .iter()
        .any(|pattern| pattern.extensions.contains(&extension))
}

/// Every gRPC service registration in `text`, the contents of `path`.
pub fn registrations(path: &str, text: &str) -> Vec<CitedOperation> {
    let extension = path.rsplit_once('.').map_or("", |(_, extension)| extension);
    let mut found = Vec::new();
    for pattern in &PATTERNS {
        if !pattern.extensions.contains(&extension)
            || pattern
                .requires
                .is_some_and(|needle| !text.contains(needle))
        {
            continue;
        }
        for (index, line) in text.lines().enumerate() {
            for captures in pattern.regex.captures_iter(line) {
                // C# names the service twice (`Greeter.GreeterBase`); any
                // other `X.YBase` base class is not a gRPC service.
                if captures
                    .get(2)
                    .is_some_and(|base| base.as_str() != &captures[1])
                {
                    continue;
                }
                found.push(CitedOperation {
                    method: "service".into(),
                    path: captures[1].to_string(),
                    file: path.into(),
                    line: index + 1,
                    snippet: captures[0].to_string(),
                });
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn services(path: &str, text: &str) -> Vec<(String, usize)> {
        registrations(path, text)
            .into_iter()
            .map(|cited| (cited.path, cited.line))
            .collect()
    }

    #[test]
    fn each_language_registration_names_its_service() {
        assert_eq!(
            services(
                "main.go",
                "s := grpc.NewServer()\npb.RegisterGreeterServer(s, &server{})\ngw.RegisterOrdersHandlerServer(ctx, mux, srv)\n"
            ),
            [("Greeter".into(), 2), ("Orders".into(), 3)]
        );
        assert_eq!(
            services(
                "server.py",
                "helloworld_pb2_grpc.add_GreeterServicer_to_server(Greeter(), server)"
            ),
            [("Greeter".into(), 1)]
        );
        assert_eq!(
            services(
                "GreeterImpl.java",
                "class GreeterImpl extends GreeterGrpc.GreeterImplBase {}\nclass K : OrdersGrpcKt.OrdersCoroutineImplBase()"
            ),
            [("Greeter".into(), 1), ("Orders".into(), 2)]
        );
        assert_eq!(
            services(
                "GreeterService.cs",
                "public class GreeterService : Greeter.GreeterBase\npublic class Other : Foo.BarBase"
            ),
            [("Greeter".into(), 1)]
        );
        assert_eq!(
            services(
                "server.ts",
                "server.addService(helloProto.helloworld.Greeter.service, impl);\nserver.addService(OrdersService, new OrdersServer());"
            ),
            [("Greeter".into(), 1), ("Orders".into(), 2)]
        );
        assert_eq!(
            services(
                "main.rs",
                "use tonic::transport::Server;\nServer::builder().add_service(GreeterServer::new(greeter))"
            ),
            [("Greeter".into(), 2)]
        );
        assert!(services("main.rs", "let s = HttpServer::new(app);").is_empty());
        assert_eq!(
            services(
                "greeter.cc",
                "class GreeterServiceImpl final : public Greeter::Service {"
            ),
            [("Greeter".into(), 1)]
        );
        assert!(services("README.md", "RegisterGreeterServer(").is_empty());
        let cited = &registrations("main.go", "RegisterGreeterServer(s, x)")[0];
        assert_eq!(cited.method, "service");
        assert_eq!(cited.snippet, "RegisterGreeterServer(");
        assert_eq!(cited.file, "main.go");
    }

    #[test]
    fn source_files_are_recognized_by_extension() {
        assert!(is_source("cmd/main.go"));
        assert!(is_source("src/Server.kt"));
        assert!(!is_source("docs/api.md"));
        assert!(!is_source("Makefile"));
    }
}
