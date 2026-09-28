//! Where a GraphQL schema belongs, by server library convention.
//!
//! | Library | Location (relative to the service root) | Basis |
//! |---|---|---|
//! | Spring for GraphQL | `src/main/resources/graphql/schema.graphqls` | Loads `*.graphqls` and `*.gqls` from `classpath:graphql/**/` by default |
//! | Netflix DGS | `src/main/resources/schema/schema.graphqls` | Loads `schema/**/*.graphql*` from the classpath by default |
//! | Lighthouse (Laravel) | `graphql/schema.graphql` | Its default `schema_path` |
//! | gqlgen | `graph/schema.graphqls` | What `gqlgen init` writes; `gqlgen.yml` lists the files it reads |
//! | graphql-java | `src/main/resources/schema.graphqls` | The application names the file; the classpath root is common |
//! | NestJS GraphQL | `src/schema.gql` | Its documented `autoSchemaFile` location for a generated schema |
//! | Code-first libraries (Strawberry, Graphene, Juniper, async-graphql, Hot Chocolate, graphql-go, graphql-ruby, graphql-php, TypeGraphQL, Nexus) | `schema.graphql` | They build the schema from code; the file is a reviewed snapshot |
//! | Anything else (Apollo Server, GraphQL Yoga, graphql-js, Mercurius, Ariadne, graph-gophers) | `schema.graphql` | The application loads a file it names; the service root is neutral |
//!
//! Only the first three are confident: the library reads the file from
//! that place without configuration. The rest never justify moving a file
//! somebody already placed. These locations were written without
//! documentation access and are listed for verification in `TODO.md`.

use std::collections::BTreeSet;

use crate::format::Syntax;
use crate::libraries::ApiLibrary;
use crate::location::Convention;

const fn convention(
    path: &'static str,
    confident: bool,
    accepted_directories: &'static [&'static str],
    code_first: bool,
    basis: &'static str,
) -> Convention {
    Convention {
        path,
        syntax: Syntax::Graphql,
        confident,
        accepted_directories,
        basis,
        code_first,
    }
}

const SPRING: Convention = convention(
    "src/main/resources/graphql/schema.graphqls",
    true,
    &["src/main/resources/graphql"],
    false,
    "Spring for GraphQL loads *.graphqls and *.gqls files from classpath:graphql/**/ by default",
);
const DGS: Convention = convention(
    "src/main/resources/schema/schema.graphqls",
    true,
    &["src/main/resources/schema"],
    false,
    "Netflix DGS loads schema/**/*.graphql* from the classpath by default",
);
const LIGHTHOUSE: Convention = convention(
    "graphql/schema.graphql",
    true,
    &["graphql"],
    false,
    "Lighthouse reads graphql/schema.graphql by default (lighthouse.schema_path)",
);
const GQLGEN: Convention = convention(
    "graph/schema.graphqls",
    false,
    &[],
    false,
    "gqlgen init writes graph/schema.graphqls; gqlgen.yml lists the schema files it reads",
);
const GRAPHQL_JAVA: Convention = convention(
    "src/main/resources/schema.graphqls",
    false,
    &[],
    false,
    "graphql-java loads a schema file the application names; the classpath root is common",
);
const NEST: Convention = convention(
    "src/schema.gql",
    false,
    &[],
    true,
    "NestJS GraphQL writes a code-first schema to its autoSchemaFile, documented as src/schema.gql",
);
const CODE_FIRST: Convention = convention(
    "schema.graphql",
    false,
    &[],
    true,
    "the library builds the schema from code; schema.graphql at the service root is a reviewed \
     snapshot of it",
);
pub(crate) const FALLBACK: Convention = convention(
    "schema.graphql",
    false,
    &[],
    false,
    "the application loads a schema file it names; schema.graphql at the service root is neutral",
);

fn library_convention(library: ApiLibrary) -> Convention {
    use ApiLibrary::*;
    match library {
        SpringGraphql => SPRING,
        Dgs => DGS,
        Lighthouse => LIGHTHOUSE,
        Gqlgen => GQLGEN,
        GraphqlJava => GRAPHQL_JAVA,
        NestGraphql => NEST,
        Strawberry | Graphene | Juniper | AsyncGraphql | HotChocolate | GraphqlGo | GraphqlRuby
        | GraphqlPhp | TypeGraphql | Nexus => CODE_FIRST,
        _ => FALLBACK,
    }
}

/// The convention for a service using `libraries`. graphql-java is
/// usually a transitive detail of Spring for GraphQL or DGS, so it defers
/// to them like the fallback does; other disagreements fall back.
pub fn convention_for(libraries: &BTreeSet<ApiLibrary>) -> Convention {
    let all: Vec<Convention> = libraries.iter().map(|l| library_convention(*l)).collect();
    let specific: Vec<Convention> = all
        .iter()
        .copied()
        .filter(|c| *c != FALLBACK && *c != GRAPHQL_JAVA)
        .collect();
    match specific.first() {
        Some(first) if specific.iter().all(|other| other == first) => *first,
        Some(_) => FALLBACK,
        None if all.contains(&GRAPHQL_JAVA) => GRAPHQL_JAVA,
        None => FALLBACK,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ApiLibrary::*;

    fn of(libraries: &[ApiLibrary]) -> Convention {
        convention_for(&libraries.iter().copied().collect())
    }

    #[test]
    fn each_library_maps_to_its_convention() {
        assert_eq!(
            of(&[SpringGraphql]).path,
            "src/main/resources/graphql/schema.graphqls"
        );
        assert!(of(&[SpringGraphql]).confident);
        assert_eq!(of(&[Dgs]).path, "src/main/resources/schema/schema.graphqls");
        assert_eq!(of(&[Lighthouse]).path, "graphql/schema.graphql");
        assert_eq!(of(&[Gqlgen]).path, "graph/schema.graphqls");
        assert!(!of(&[Gqlgen]).confident);
        assert_eq!(of(&[GraphqlJava]), GRAPHQL_JAVA);
        assert_eq!(of(&[NestGraphql]).path, "src/schema.gql");
        assert!(of(&[NestGraphql]).code_first);
        assert!(of(&[Strawberry]).code_first);
        assert_eq!(of(&[ApolloServer]), FALLBACK);
        assert_eq!(of(&[]), FALLBACK);
    }

    #[test]
    fn conventions_are_graphql_documents() {
        let built = convention("a.graphql", false, &[], false, "b");
        assert_eq!(built.syntax, Syntax::Graphql);
    }

    #[test]
    fn graphql_java_defers_and_disagreements_fall_back() {
        assert_eq!(of(&[SpringGraphql, GraphqlJava]), SPRING);
        assert_eq!(of(&[Dgs, GraphqlJava, ApolloServer]), DGS);
        assert_eq!(of(&[Strawberry, Graphene]), CODE_FIRST);
        assert_eq!(of(&[SpringGraphql, Dgs]), FALLBACK);
    }
}
