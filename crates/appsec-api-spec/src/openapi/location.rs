//! Where an OpenAPI or Swagger document belongs, by framework convention.
//!
//! A new specification is placed where the framework's common tooling
//! reads a static document, so it is served or found without extra
//! configuration. Where a framework has no such convention the neutral
//! `docs/api/openapi.yaml` is used.
//!
//! | Framework | Location (relative to the service root) | Basis |
//! |---|---|---|
//! | Spring Boot | `src/main/resources/static/openapi.yaml` | Spring serves `static/`; springdoc's UI reads it via `springdoc.swagger-ui.url` |
//! | Quarkus | `src/main/resources/META-INF/openapi.yaml` | SmallRye OpenAPI merges this static file |
//! | Ktor | `src/main/resources/openapi/documentation.yaml` | Default path of Ktor's OpenAPI and Swagger plugins |
//! | ASP.NET Core | `wwwroot/swagger/v1/swagger.json` | Static files serve it at Swashbuckle UI's default `/swagger/v1/swagger.json` |
//! | Rails | `swagger/v1/swagger.yaml` | rswag's default `openapi_root` and document name |
//! | Laravel | `storage/api-docs/api-docs.json` | l5-swagger's default docs path and file name |
//! | Go (gin, echo, chi, gorilla/mux, fiber) | `api/openapi.yaml` | golang-standards project layout `api/` directory |
//! | Anything else | `docs/api/openapi.yaml` | Neutral documentation location |
//!
//! Only the first six are *confident*: their tooling reads the file from
//! that place, so a specification elsewhere is not found by default. The
//! Go layout is a community convention rather than something tooling
//! reads, and the fallback is a neutral choice, so neither ever justifies
//! moving a file somebody already placed.

use std::collections::BTreeSet;

use crate::format::Syntax;
use crate::frameworks::WebFramework;
pub use crate::location::Convention;
#[cfg(test)]
use crate::location::{conventional_path, is_accepted};

const SPRING: Convention = Convention {
    path: "src/main/resources/static/openapi.yaml",
    syntax: Syntax::Yaml,
    confident: true,
    accepted_directories: &["src/main/resources"],
    code_first: false,
    basis: "Spring Boot serves src/main/resources/static; springdoc's UI reads a static document from there",
};
const QUARKUS: Convention = Convention {
    path: "src/main/resources/META-INF/openapi.yaml",
    syntax: Syntax::Yaml,
    confident: true,
    accepted_directories: &["src/main/resources"],
    code_first: false,
    basis: "SmallRye OpenAPI merges src/main/resources/META-INF/openapi.yaml",
};
const KTOR: Convention = Convention {
    path: "src/main/resources/openapi/documentation.yaml",
    syntax: Syntax::Yaml,
    confident: true,
    accepted_directories: &["src/main/resources"],
    code_first: false,
    basis: "Ktor's OpenAPI and Swagger plugins default to openapi/documentation.yaml",
};
const ASPNET: Convention = Convention {
    path: "wwwroot/swagger/v1/swagger.json",
    syntax: Syntax::Json,
    confident: true,
    accepted_directories: &["wwwroot"],
    code_first: false,
    basis: "static files serve wwwroot at Swashbuckle UI's default /swagger/v1/swagger.json",
};
const RAILS: Convention = Convention {
    path: "swagger/v1/swagger.yaml",
    syntax: Syntax::Yaml,
    confident: true,
    accepted_directories: &["swagger", "openapi", "public"],
    code_first: false,
    basis: "rswag's default openapi_root is swagger/ with v1/swagger.yaml",
};
const LARAVEL: Convention = Convention {
    path: "storage/api-docs/api-docs.json",
    syntax: Syntax::Json,
    confident: true,
    accepted_directories: &["storage/api-docs", "public"],
    code_first: false,
    basis: "l5-swagger reads storage/api-docs/api-docs.json by default",
};
const GO: Convention = Convention {
    path: "api/openapi.yaml",
    syntax: Syntax::Yaml,
    confident: false,
    accepted_directories: &[],
    code_first: false,
    basis: "golang-standards project layout keeps OpenAPI documents in api/",
};
pub(crate) const FALLBACK: Convention = Convention {
    path: "docs/api/openapi.yaml",
    syntax: Syntax::Yaml,
    confident: false,
    accepted_directories: &[],
    code_first: false,
    basis: "no framework convention applies; docs/api is a neutral documentation location",
};

fn framework_convention(framework: WebFramework) -> Convention {
    use WebFramework::*;
    match framework {
        SpringBoot => SPRING,
        Quarkus => QUARKUS,
        Ktor => KTOR,
        AspNetCore => ASPNET,
        Rails => RAILS,
        Laravel => LARAVEL,
        Gin | Echo | Chi | GorillaMux | Fiber => GO,
        _ => FALLBACK,
    }
}

/// The convention for a service using `frameworks`. Frameworks whose
/// conventions disagree (two confident answers, say) are ambiguous and
/// get the neutral fallback; frameworks without a convention of their
/// own defer to one that has one.
pub fn convention(frameworks: &BTreeSet<WebFramework>) -> Convention {
    let specific: Vec<Convention> = frameworks
        .iter()
        .map(|framework| framework_convention(*framework))
        .filter(|convention| *convention != FALLBACK)
        .collect();
    match specific.first() {
        Some(first) if specific.iter().all(|other| other == first) => *first,
        _ => FALLBACK,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use WebFramework::*;

    fn of(frameworks: &[WebFramework]) -> Convention {
        convention(&frameworks.iter().copied().collect())
    }

    #[test]
    fn each_framework_maps_to_its_convention() {
        assert_eq!(
            of(&[SpringBoot]).path,
            "src/main/resources/static/openapi.yaml"
        );
        assert_eq!(
            of(&[Quarkus]).path,
            "src/main/resources/META-INF/openapi.yaml"
        );
        assert_eq!(
            of(&[Ktor]).path,
            "src/main/resources/openapi/documentation.yaml"
        );
        assert_eq!(of(&[AspNetCore]).path, "wwwroot/swagger/v1/swagger.json");
        assert_eq!(of(&[AspNetCore]).syntax, Syntax::Json);
        assert_eq!(of(&[Rails]).path, "swagger/v1/swagger.yaml");
        assert_eq!(of(&[Laravel]).path, "storage/api-docs/api-docs.json");
        assert_eq!(of(&[Gin]).path, "api/openapi.yaml");
        assert!(!of(&[Gin]).confident);
        assert_eq!(of(&[Express]).path, "docs/api/openapi.yaml");
        assert_eq!(of(&[]).path, "docs/api/openapi.yaml");
        assert!(of(&[SpringBoot]).basis.contains("springdoc"));
    }

    #[test]
    fn frameworks_without_a_convention_defer_and_disagreements_fall_back() {
        assert_eq!(of(&[SpringBoot, JaxRs]), SPRING);
        assert_eq!(of(&[Gin, Chi]), GO);
        assert_eq!(of(&[SpringBoot, Quarkus]), FALLBACK);
        assert_eq!(of(&[Rails, Gin]), FALLBACK);
    }

    #[test]
    fn accepted_locations_are_decided_per_framework() {
        let spring = of(&[SpringBoot]);
        assert!(is_accepted(
            &spring,
            ".",
            "src/main/resources/static/openapi.yaml"
        ));
        assert!(is_accepted(
            &spring,
            ".",
            "src/main/resources/api/openapi.json"
        ));
        assert!(!is_accepted(&spring, ".", "openapi.yaml"));
        assert!(!is_accepted(&spring, ".", "docs/openapi.yaml"));
        assert!(!is_accepted(&spring, "svc", "other/openapi.yaml"));
        assert!(is_accepted(
            &of(&[AspNetCore]),
            "api",
            "api/wwwroot/swagger/v1/swagger.json"
        ));
        assert!(is_accepted(&of(&[Rails]), ".", "swagger/v1/swagger.yaml"));
        assert!(is_accepted(
            &of(&[Ktor]),
            ".",
            "src/main/resources/openapi/documentation.yaml"
        ));
        // Without a confident convention every location is accepted.
        assert!(is_accepted(&of(&[Express]), ".", "openapi.yaml"));
        assert!(is_accepted(&of(&[Gin]), ".", "docs/openapi.yaml"));
    }

    #[test]
    fn a_relocation_keeps_the_existing_format() {
        let aspnet = of(&[AspNetCore]);
        assert_eq!(
            conventional_path(&aspnet, "api", Syntax::Json),
            "api/wwwroot/swagger/v1/swagger.json"
        );
        assert_eq!(
            conventional_path(&aspnet, ".", Syntax::Yaml),
            "wwwroot/swagger/v1/swagger.yaml"
        );
        assert_eq!(
            conventional_path(&of(&[SpringBoot]), ".", Syntax::Json),
            "src/main/resources/static/openapi.json"
        );
    }
}
