//! Recognizing HTTP frameworks from package manifests.
//!
//! A web framework dependency is the evidence that a package serves an
//! HTTP API, and it decides where a specification conventionally lives.
//! Manifests are matched on declared dependency names, never on arbitrary
//! text, so a README that mentions Flask does not make a package a Flask
//! service. The caller reads manifests; this module only interprets text.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebFramework {
    SpringBoot,
    Quarkus,
    Micronaut,
    JaxRs,
    Ktor,
    AspNetCore,
    Rails,
    Sinatra,
    Grape,
    Laravel,
    Symfony,
    Slim,
    Express,
    NestJs,
    Fastify,
    Koa,
    Hapi,
    Hono,
    NextJs,
    Flask,
    FastApi,
    Django,
    Starlette,
    Aiohttp,
    Tornado,
    Falcon,
    Sanic,
    Bottle,
    Gin,
    Echo,
    Chi,
    GorillaMux,
    Fiber,
    Axum,
    ActixWeb,
    Rocket,
    Warp,
    Poem,
}

/// Whether a file name is a manifest this module interprets.
pub fn is_manifest(name: &str) -> bool {
    matches!(
        name,
        "package.json"
            | "requirements.txt"
            | "pyproject.toml"
            | "setup.py"
            | "setup.cfg"
            | "Pipfile"
            | "go.mod"
            | "pom.xml"
            | "build.gradle"
            | "build.gradle.kts"
            | "Cargo.toml"
            | "Gemfile"
            | "composer.json"
    ) || name.ends_with(".csproj")
}

/// Frameworks a manifest named `name` declares in `text`.
pub fn detect(name: &str, text: &str) -> BTreeSet<WebFramework> {
    use WebFramework::*;
    let lower = text.to_ascii_lowercase();
    let mut found = BTreeSet::new();
    let mut mark = |present: bool, framework: WebFramework| {
        if present {
            found.insert(framework);
        }
    };
    match name {
        "package.json" => {
            let declared = json_keys(text, &["dependencies", "devDependencies"]);
            for (package, framework) in [
                ("express", Express),
                ("@nestjs/core", NestJs),
                ("fastify", Fastify),
                ("koa", Koa),
                ("@hapi/hapi", Hapi),
                ("hono", Hono),
                ("next", NextJs),
            ] {
                mark(declared.contains(package), framework);
            }
        }
        "composer.json" => {
            let declared = json_keys(text, &["require"]);
            mark(
                declared.contains("laravel/framework")
                    || declared.contains("laravel/lumen-framework"),
                Laravel,
            );
            mark(declared.contains("symfony/framework-bundle"), Symfony);
            mark(declared.contains("slim/slim"), Slim);
        }
        "requirements.txt" | "pyproject.toml" | "setup.py" | "setup.cfg" | "Pipfile" => {
            for (package, framework) in [
                ("flask", Flask),
                ("fastapi", FastApi),
                ("django", Django),
                ("starlette", Starlette),
                ("aiohttp", Aiohttp),
                ("tornado", Tornado),
                ("falcon", Falcon),
                ("sanic", Sanic),
                ("bottle", Bottle),
            ] {
                mark(has_token(&lower, package), framework);
            }
        }
        "go.mod" => {
            for (module, framework) in [
                ("github.com/gin-gonic/gin", Gin),
                ("github.com/labstack/echo", Echo),
                ("github.com/go-chi/chi", Chi),
                ("github.com/gorilla/mux", GorillaMux),
                ("github.com/gofiber/fiber", Fiber),
            ] {
                mark(lower.contains(module), framework);
            }
        }
        "pom.xml" | "build.gradle" | "build.gradle.kts" => {
            mark(
                lower.contains("spring-boot-starter-web")
                    || lower.contains("spring-boot-starter-webflux"),
                SpringBoot,
            );
            mark(lower.contains("quarkus-rest"), Quarkus);
            mark(lower.contains("micronaut-http-server"), Micronaut);
            mark(lower.contains("ktor-server"), Ktor);
            mark(
                lower.contains("jakarta.ws.rs")
                    || lower.contains("javax.ws.rs")
                    || lower.contains("jersey-server"),
                JaxRs,
            );
        }
        "Cargo.toml" => {
            for (package, framework) in [
                ("axum", Axum),
                ("actix-web", ActixWeb),
                ("rocket", Rocket),
                ("warp", Warp),
                ("poem", Poem),
            ] {
                mark(has_token(&lower, package), framework);
            }
        }
        "Gemfile" => {
            for (gem, framework) in [("rails", Rails), ("sinatra", Sinatra), ("grape", Grape)] {
                mark(
                    lower.contains(&format!("gem '{gem}'"))
                        || lower.contains(&format!("gem \"{gem}\"")),
                    framework,
                );
            }
        }
        csproj if csproj.ends_with(".csproj") => {
            mark(
                lower.contains("microsoft.net.sdk.web") || lower.contains("microsoft.aspnetcore"),
                AspNetCore,
            );
        }
        _ => {}
    }
    found
}

/// Keys of the named top-level objects of a JSON manifest.
fn json_keys(text: &str, fields: &[&str]) -> BTreeSet<String> {
    let parsed: Value = serde_json::from_str(text).unwrap_or_default();
    fields
        .iter()
        .filter_map(|field| parsed.get(field).and_then(Value::as_object))
        .flat_map(|object| object.keys().cloned())
        .collect()
}

/// `token` appears as a whole dependency name: not preceded by a name
/// character and not followed by a letter, digit or underscore. A
/// following `-` is allowed, because `flask-cors` still depends on Flask.
pub(crate) fn has_token(text: &str, token: &str) -> bool {
    text.match_indices(token).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + token.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            && !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use WebFramework::*;

    fn found(name: &str, text: &str) -> Vec<WebFramework> {
        detect(name, text).into_iter().collect()
    }

    #[test]
    fn manifests_are_recognized_by_name() {
        for name in [
            "package.json",
            "go.mod",
            "Gemfile",
            "Api.csproj",
            "composer.json",
        ] {
            assert!(is_manifest(name), "{name}");
        }
        assert!(!is_manifest("README.md"));
    }

    #[test]
    fn javascript_and_php_frameworks_come_from_declared_dependencies() {
        let package = r#"{"dependencies":{"express":"4","@nestjs/core":"10"},"devDependencies":{"next":"14"},"description":"koa fastify"}"#;
        assert_eq!(found("package.json", package), [Express, NestJs, NextJs]);
        assert!(found("package.json", "{not json").is_empty());
        let composer = r#"{"require":{"laravel/framework":"^11","slim/slim":"4"}}"#;
        assert_eq!(found("composer.json", composer), [Laravel, Slim]);
        assert_eq!(
            found(
                "composer.json",
                r#"{"require":{"symfony/framework-bundle":"7","laravel/lumen-framework":"1"}}"#
            ),
            [Laravel, Symfony]
        );
    }

    #[test]
    fn python_rust_and_go_frameworks_match_whole_names() {
        assert_eq!(
            found("requirements.txt", "Flask==3.0\nflask-cors\nbottleneck\n"),
            [Flask]
        );
        assert_eq!(
            found(
                "pyproject.toml",
                "dependencies = [\"fastapi>=0.110\", \"django\"]"
            ),
            [FastApi, Django]
        );
        assert!(found("setup.py", "organic_sanic_tornadoes").is_empty());
        assert_eq!(
            found(
                "Cargo.toml",
                "[dependencies]\naxum = \"0.7\"\nactix-web = \"4\"\n"
            ),
            [Axum, ActixWeb]
        );
        assert_eq!(
            found("go.mod", "require github.com/gin-gonic/gin v1.9.1"),
            [Gin]
        );
    }

    #[test]
    fn jvm_dotnet_and_ruby_frameworks_are_recognized() {
        assert_eq!(
            found(
                "pom.xml",
                "<artifactId>spring-boot-starter-web</artifactId>"
            ),
            [SpringBoot]
        );
        assert_eq!(
            found(
                "build.gradle.kts",
                "implementation(\"io.ktor:ktor-server-core\")"
            ),
            [Ktor]
        );
        assert_eq!(
            found("build.gradle", "io.quarkus:quarkus-rest jakarta.ws.rs"),
            [Quarkus, JaxRs]
        );
        assert_eq!(found("pom.xml", "micronaut-http-server-netty"), [Micronaut]);
        assert_eq!(
            found("Api.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Web\">"),
            [AspNetCore]
        );
        assert!(found("Lib.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\">").is_empty());
        assert_eq!(
            found("Gemfile", "gem 'rails', '~> 7.1'\ngem \"grape\""),
            [Rails, Grape]
        );
        assert!(found("Makefile", "express flask").is_empty());
    }
}
