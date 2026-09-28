//! Recognizing non-HTTP API libraries from package manifests: GraphQL
//! servers, messaging clients, JSON-RPC servers, gRPC, SOAP servers and
//! OData servers.
//!
//! Like [`crate::frameworks`], manifests are matched on declared
//! dependency names, never on arbitrary text. A library is evidence that a
//! package may expose an API of that kind; the generator still has to cite
//! the code that does. Some common libraries are deliberately not
//! evidence on their own: a Redis client is far more often a cache than a
//! pub/sub channel, and a generic cloud SDK (boto3) says nothing about
//! queues, so neither makes a package a messaging service. Likewise zeep
//! is a SOAP client only, so it does not make a package a SOAP service.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::frameworks::has_token;

/// Which standard a library's API is described by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiFamily {
    /// GraphQL SDL.
    Graphql,
    /// AsyncAPI.
    Messaging,
    /// OpenRPC.
    JsonRpc,
    /// Protocol Buffers service definitions.
    Grpc,
    /// WSDL.
    Soap,
    /// OData CSDL.
    OData,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiLibrary {
    // GraphQL servers.
    ApolloServer,
    GraphqlYoga,
    /// graphql-js served by `graphql-http` or `express-graphql`.
    GraphqlJs,
    Mercurius,
    NestGraphql,
    TypeGraphql,
    Nexus,
    Strawberry,
    Graphene,
    Ariadne,
    Gqlgen,
    GraphGophers,
    GraphqlGo,
    HotChocolate,
    SpringGraphql,
    Dgs,
    GraphqlJava,
    Juniper,
    AsyncGraphql,
    GraphqlRuby,
    Lighthouse,
    GraphqlPhp,
    // Messaging.
    Kafka,
    Amqp,
    Mqtt,
    Nats,
    Sqs,
    Sns,
    WebSocket,
    SocketIo,
    // RPC.
    JsonRpc,
    Grpc,
    // SOAP servers.
    /// JAX-WS: the reference implementation (Metro), Apache CXF's JAX-WS
    /// frontend or the Jakarta XML Web Services API.
    JaxWs,
    SpringWs,
    /// WCF on .NET Framework (`System.ServiceModel`).
    Wcf,
    CoreWcf,
    /// ASP.NET XML web services (`System.Web.Services`).
    Asmx,
    Spyne,
    /// PHP's SOAP extension (`SoapServer`) or laminas-soap.
    PhpSoap,
    /// The `soap` or `strong-soap` package for Node.js.
    NodeSoap,
    // OData servers.
    AspNetCoreOData,
    /// SAP Cloud Application Programming Model (Node.js or Java).
    SapCap,
    /// Apache Olingo.
    Olingo,
}

impl ApiLibrary {
    pub fn family(self) -> ApiFamily {
        use ApiLibrary::*;
        match self {
            Kafka | Amqp | Mqtt | Nats | Sqs | Sns | WebSocket | SocketIo => ApiFamily::Messaging,
            JsonRpc => ApiFamily::JsonRpc,
            Grpc => ApiFamily::Grpc,
            JaxWs | SpringWs | Wcf | CoreWcf | Asmx | Spyne | PhpSoap | NodeSoap => ApiFamily::Soap,
            AspNetCoreOData | SapCap | Olingo => ApiFamily::OData,
            _ => ApiFamily::Graphql,
        }
    }
}

/// A package discovery found API libraries in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiSurface {
    /// Repository-relative directory, `.` for the root.
    pub root: String,
    pub manifests: Vec<String>,
    pub libraries: BTreeSet<ApiLibrary>,
}

impl ApiSurface {
    /// This surface's libraries of `family`.
    pub fn of(&self, family: ApiFamily) -> BTreeSet<ApiLibrary> {
        self.libraries
            .iter()
            .copied()
            .filter(|library| library.family() == family)
            .collect()
    }
}

/// Libraries a manifest named `name` declares in `text`. Only the
/// manifests [`crate::frameworks::is_manifest`] accepts are interpreted.
pub fn detect(name: &str, text: &str) -> BTreeSet<ApiLibrary> {
    use ApiLibrary::*;
    let lower = text.to_ascii_lowercase();
    let mut found = BTreeSet::new();
    let mut mark = |present: bool, library: ApiLibrary| {
        if present {
            found.insert(library);
        }
    };
    let contains_any = |needles: &[&str]| needles.iter().any(|needle| lower.contains(needle));
    let token_any = |tokens: &[&str]| tokens.iter().any(|token| has_token(&lower, token));
    match name {
        "package.json" => {
            let parsed: Value = serde_json::from_str(text).unwrap_or_default();
            let declared: BTreeSet<&str> = ["dependencies", "devDependencies"]
                .iter()
                .filter_map(|field| parsed.get(field).and_then(Value::as_object))
                .flat_map(|object| object.keys().map(String::as_str))
                .collect();
            let any = |packages: &[&str]| packages.iter().any(|p| declared.contains(p));
            mark(
                declared
                    .iter()
                    .any(|p| *p == "@apollo/server" || p.starts_with("apollo-server")),
                ApolloServer,
            );
            mark(any(&["graphql-yoga"]), GraphqlYoga);
            mark(any(&["graphql-http", "express-graphql"]), GraphqlJs);
            mark(any(&["mercurius"]), Mercurius);
            mark(any(&["@nestjs/graphql"]), NestGraphql);
            mark(any(&["type-graphql"]), TypeGraphql);
            mark(any(&["nexus"]), Nexus);
            mark(
                any(&["kafkajs", "node-rdkafka", "@confluentinc/kafka-javascript"]),
                Kafka,
            );
            mark(any(&["amqplib", "amqp-connection-manager", "rhea"]), Amqp);
            mark(any(&["mqtt", "async-mqtt"]), Mqtt);
            mark(any(&["nats"]), Nats);
            mark(any(&["@aws-sdk/client-sqs", "sqs-consumer"]), Sqs);
            mark(any(&["@aws-sdk/client-sns"]), Sns);
            mark(any(&["ws"]), WebSocket);
            mark(any(&["socket.io"]), SocketIo);
            mark(
                any(&["jayson", "json-rpc-2.0", "@open-rpc/server-js"]),
                JsonRpc,
            );
            mark(any(&["@grpc/grpc-js", "grpc"]), Grpc);
            mark(any(&["soap", "strong-soap"]), NodeSoap);
            mark(any(&["@sap/cds"]), SapCap);
        }
        "requirements.txt" | "pyproject.toml" | "setup.py" | "setup.cfg" | "Pipfile" => {
            mark(token_any(&["strawberry-graphql"]), Strawberry);
            mark(token_any(&["graphene"]), Graphene);
            mark(token_any(&["ariadne"]), Ariadne);
            mark(
                token_any(&["confluent-kafka", "kafka-python", "aiokafka"]),
                Kafka,
            );
            mark(token_any(&["pika", "aio-pika"]), Amqp);
            mark(token_any(&["paho-mqtt", "aiomqtt", "asyncio-mqtt"]), Mqtt);
            mark(token_any(&["nats-py"]), Nats);
            mark(token_any(&["websockets"]), WebSocket);
            mark(token_any(&["python-socketio"]), SocketIo);
            mark(
                token_any(&["jsonrpcserver", "json-rpc", "fastapi-jsonrpc"]),
                JsonRpc,
            );
            mark(token_any(&["grpcio"]), Grpc);
            mark(token_any(&["spyne"]), Spyne);
        }
        "go.mod" => {
            mark(contains_any(&["github.com/99designs/gqlgen"]), Gqlgen);
            mark(
                contains_any(&["github.com/graph-gophers/graphql-go"]),
                GraphGophers,
            );
            mark(contains_any(&["github.com/graphql-go/graphql"]), GraphqlGo);
            mark(
                contains_any(&[
                    "github.com/segmentio/kafka-go",
                    "github.com/ibm/sarama",
                    "github.com/shopify/sarama",
                    "github.com/confluentinc/confluent-kafka-go",
                    "github.com/twmb/franz-go",
                ]),
                Kafka,
            );
            mark(
                contains_any(&[
                    "github.com/rabbitmq/amqp091-go",
                    "github.com/streadway/amqp",
                ]),
                Amqp,
            );
            mark(contains_any(&["github.com/eclipse/paho.mqtt.golang"]), Mqtt);
            mark(contains_any(&["github.com/nats-io/nats.go"]), Nats);
            mark(contains_any(&["aws-sdk-go-v2/service/sqs"]), Sqs);
            mark(contains_any(&["aws-sdk-go-v2/service/sns"]), Sns);
            mark(
                contains_any(&[
                    "github.com/gorilla/websocket",
                    "nhooyr.io/websocket",
                    "github.com/coder/websocket",
                ]),
                WebSocket,
            );
            mark(
                contains_any(&["github.com/googollee/go-socket.io"]),
                SocketIo,
            );
            mark(contains_any(&["github.com/sourcegraph/jsonrpc2"]), JsonRpc);
            mark(contains_any(&["google.golang.org/grpc"]), Grpc);
        }
        "pom.xml" | "build.gradle" | "build.gradle.kts" => {
            mark(
                contains_any(&["spring-boot-starter-graphql", "spring-graphql"]),
                SpringGraphql,
            );
            mark(contains_any(&["graphql-dgs"]), Dgs);
            mark(contains_any(&["graphql-java"]), GraphqlJava);
            mark(
                contains_any(&["spring-kafka", "kafka-clients", "messaging-kafka"]),
                Kafka,
            );
            mark(
                contains_any(&["spring-boot-starter-amqp", "spring-rabbit", "amqp-client"]),
                Amqp,
            );
            mark(
                contains_any(&["org.eclipse.paho", "hivemq-mqtt-client"]),
                Mqtt,
            );
            mark(contains_any(&["io.nats"]), Nats);
            mark(
                contains_any(&["awssdk:sqs", "<artifactid>sqs</artifactid>", "starter-sqs"]),
                Sqs,
            );
            mark(
                contains_any(&["awssdk:sns", "<artifactid>sns</artifactid>", "starter-sns"]),
                Sns,
            );
            mark(
                contains_any(&[
                    "spring-boot-starter-websocket",
                    "jakarta.websocket",
                    "javax.websocket",
                ]),
                WebSocket,
            );
            mark(contains_any(&["netty-socketio"]), SocketIo);
            mark(contains_any(&["jsonrpc4j"]), JsonRpc);
            mark(
                contains_any(&["io.grpc", "quarkus-grpc", "grpc-spring"]),
                Grpc,
            );
            mark(
                contains_any(&[
                    "jaxws-rt",
                    "jakarta.xml.ws-api",
                    "jaxws-api",
                    "cxf-rt-frontend-jaxws",
                    "cxf-spring-boot-starter-jaxws",
                ]),
                JaxWs,
            );
            mark(
                contains_any(&["spring-boot-starter-web-services", "spring-ws-core"]),
                SpringWs,
            );
            mark(
                contains_any(&["com.sap.cds", "cds-starter-spring-boot"]),
                SapCap,
            );
            mark(contains_any(&["org.apache.olingo"]), Olingo);
        }
        "Cargo.toml" => {
            mark(token_any(&["juniper"]), Juniper);
            mark(token_any(&["async-graphql"]), AsyncGraphql);
            mark(token_any(&["rdkafka"]), Kafka);
            mark(token_any(&["lapin"]), Amqp);
            mark(token_any(&["rumqttc", "paho-mqtt"]), Mqtt);
            mark(token_any(&["async-nats", "nats"]), Nats);
            mark(token_any(&["aws-sdk-sqs"]), Sqs);
            mark(token_any(&["aws-sdk-sns"]), Sns);
            mark(token_any(&["tokio-tungstenite", "tungstenite"]), WebSocket);
            mark(token_any(&["socketioxide"]), SocketIo);
            mark(token_any(&["jsonrpsee", "jsonrpc-core"]), JsonRpc);
            mark(token_any(&["tonic"]), Grpc);
        }
        "Gemfile" => {
            let gem = |name: &str| {
                lower.contains(&format!("gem '{name}'"))
                    || lower.contains(&format!("gem \"{name}\""))
            };
            mark(gem("graphql"), GraphqlRuby);
            mark(gem("ruby-kafka") || gem("rdkafka") || gem("karafka"), Kafka);
            mark(gem("bunny"), Amqp);
            mark(gem("grpc"), Grpc);
        }
        "composer.json" => {
            let parsed: Value = serde_json::from_str(text).unwrap_or_default();
            let required = |package: &str| {
                parsed
                    .get("require")
                    .and_then(Value::as_object)
                    .is_some_and(|object| object.contains_key(package))
            };
            mark(required("nuwave/lighthouse"), Lighthouse);
            mark(
                required("webonyx/graphql-php") || required("rebing/graphql-laravel"),
                GraphqlPhp,
            );
            mark(required("php-amqplib/php-amqplib"), Amqp);
            mark(required("grpc/grpc"), Grpc);
            mark(
                required("ext-soap") || required("laminas/laminas-soap"),
                PhpSoap,
            );
        }
        csproj if csproj.ends_with(".csproj") => {
            mark(contains_any(&["hotchocolate"]), HotChocolate);
            mark(contains_any(&["confluent.kafka"]), Kafka);
            mark(
                contains_any(&["rabbitmq.client", "masstransit.rabbitmq"]),
                Amqp,
            );
            mark(contains_any(&["mqttnet"]), Mqtt);
            mark(contains_any(&["nats.client", "nats.net"]), Nats);
            mark(contains_any(&["awssdk.sqs"]), Sqs);
            mark(contains_any(&["awssdk.simplenotificationservice"]), Sns);
            mark(contains_any(&["streamjsonrpc"]), JsonRpc);
            mark(contains_any(&["grpc.aspnetcore"]), Grpc);
            mark(contains_any(&["include=\"corewcf"]), CoreWcf);
            // The framework assemblies themselves, not the client-only
            // `System.ServiceModel.*` packages.
            mark(contains_any(&["include=\"system.servicemodel\""]), Wcf);
            mark(contains_any(&["include=\"system.web.services\""]), Asmx);
            mark(
                contains_any(&["include=\"microsoft.aspnetcore.odata\""]),
                AspNetCoreOData,
            );
        }
        _ => {}
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use ApiLibrary::*;

    fn found(name: &str, text: &str) -> Vec<ApiLibrary> {
        detect(name, text).into_iter().collect()
    }

    #[test]
    fn families_group_libraries_by_standard() {
        assert_eq!(ApolloServer.family(), ApiFamily::Graphql);
        assert_eq!(Kafka.family(), ApiFamily::Messaging);
        assert_eq!(JsonRpc.family(), ApiFamily::JsonRpc);
        assert_eq!(Grpc.family(), ApiFamily::Grpc);
        assert_eq!(Wcf.family(), ApiFamily::Soap);
        assert_eq!(Olingo.family(), ApiFamily::OData);
        let surface = ApiSurface {
            root: ".".into(),
            manifests: vec![],
            libraries: [Kafka, Grpc, Strawberry].into_iter().collect(),
        };
        assert_eq!(
            surface.of(ApiFamily::Messaging),
            [Kafka].into_iter().collect()
        );
        assert!(surface.of(ApiFamily::JsonRpc).is_empty());
    }

    #[test]
    fn javascript_libraries_come_from_declared_dependencies() {
        let package = r#"{"dependencies":{"@apollo/server":"4","kafkajs":"2","ws":"8","@grpc/grpc-js":"1","jayson":"4"},"devDependencies":{"socket.io":"4"},"description":"mqtt nats"}"#;
        assert_eq!(
            found("package.json", package),
            [ApolloServer, Kafka, WebSocket, SocketIo, JsonRpc, Grpc]
        );
        let more = r#"{"dependencies":{"apollo-server-express":"3","graphql-yoga":"5","graphql-http":"1","mercurius":"1","@nestjs/graphql":"12","type-graphql":"2","nexus":"1","amqplib":"1","mqtt":"5","nats":"2","@aws-sdk/client-sqs":"3","@aws-sdk/client-sns":"3"}}"#;
        assert_eq!(
            found("package.json", more),
            [
                ApolloServer,
                GraphqlYoga,
                GraphqlJs,
                Mercurius,
                NestGraphql,
                TypeGraphql,
                Nexus,
                Amqp,
                Mqtt,
                Nats,
                Sqs,
                Sns
            ]
        );
        assert!(found("package.json", "{not json").is_empty());
    }

    #[test]
    fn python_go_and_rust_libraries_match_whole_names() {
        assert_eq!(
            found(
                "requirements.txt",
                "strawberry-graphql==0.2\ngraphene-django\nariadne\naiokafka\npika\npaho-mqtt\nnats-py\nwebsockets\npython-socketio\njsonrpcserver\ngrpcio-tools\n"
            ),
            [
                Strawberry, Graphene, Ariadne, Kafka, Amqp, Mqtt, Nats, WebSocket, SocketIo,
                JsonRpc, Grpc
            ]
        );
        assert!(found("setup.py", "boto3 redis celery").is_empty());
        let go = "require (\n github.com/99designs/gqlgen v0.17\n github.com/graph-gophers/graphql-go v1\n github.com/graphql-go/graphql v0.8\n github.com/IBM/sarama v1\n github.com/rabbitmq/amqp091-go v1\n github.com/eclipse/paho.mqtt.golang v1\n github.com/nats-io/nats.go v1\n github.com/aws/aws-sdk-go-v2/service/sqs v1\n github.com/aws/aws-sdk-go-v2/service/sns v1\n github.com/gorilla/websocket v1\n github.com/googollee/go-socket.io v1\n github.com/sourcegraph/jsonrpc2 v0\n google.golang.org/grpc v1\n)";
        assert_eq!(
            found("go.mod", go),
            [
                Gqlgen,
                GraphGophers,
                GraphqlGo,
                Kafka,
                Amqp,
                Mqtt,
                Nats,
                Sqs,
                Sns,
                WebSocket,
                SocketIo,
                JsonRpc,
                Grpc
            ]
        );
        let cargo = "[dependencies]\njuniper = \"0.16\"\nasync-graphql = \"7\"\nrdkafka = \"0.36\"\nlapin = \"2\"\nrumqttc = \"0.24\"\nasync-nats = \"0.35\"\naws-sdk-sqs = \"1\"\naws-sdk-sns = \"1\"\ntokio-tungstenite = \"0.21\"\nsocketioxide = \"0.13\"\njsonrpsee = \"0.22\"\ntonic = \"0.11\"\n";
        assert_eq!(
            found("Cargo.toml", cargo),
            [
                Juniper,
                AsyncGraphql,
                Kafka,
                Amqp,
                Mqtt,
                Nats,
                Sqs,
                Sns,
                WebSocket,
                SocketIo,
                JsonRpc,
                Grpc
            ]
        );
    }

    #[test]
    fn jvm_dotnet_ruby_and_php_libraries_are_recognized() {
        let pom = "spring-boot-starter-graphql graphql-dgs graphql-java spring-kafka spring-rabbit org.eclipse.paho io.nats <artifactId>sqs</artifactId> software.amazon.awssdk:sns spring-boot-starter-websocket netty-socketio jsonrpc4j io.grpc";
        assert_eq!(
            found("pom.xml", pom),
            [
                SpringGraphql,
                Dgs,
                GraphqlJava,
                Kafka,
                Amqp,
                Mqtt,
                Nats,
                Sqs,
                Sns,
                WebSocket,
                SocketIo,
                JsonRpc,
                Grpc
            ]
        );
        let csproj = "HotChocolate.AspNetCore Confluent.Kafka RabbitMQ.Client MQTTnet NATS.Client AWSSDK.SQS AWSSDK.SimpleNotificationService StreamJsonRpc Grpc.AspNetCore";
        assert_eq!(
            found("Api.csproj", csproj),
            [
                HotChocolate,
                Kafka,
                Amqp,
                Mqtt,
                Nats,
                Sqs,
                Sns,
                JsonRpc,
                Grpc
            ]
        );
        assert_eq!(
            found(
                "Gemfile",
                "gem 'graphql'\ngem \"karafka\"\ngem 'bunny'\ngem 'grpc'"
            ),
            [GraphqlRuby, Kafka, Amqp, Grpc]
        );
        let composer = r#"{"require":{"nuwave/lighthouse":"6","webonyx/graphql-php":"15","php-amqplib/php-amqplib":"3","grpc/grpc":"1"}}"#;
        assert_eq!(
            found("composer.json", composer),
            [Lighthouse, GraphqlPhp, Amqp, Grpc]
        );
        assert!(found("composer.json", "[]").is_empty());
        assert!(found("Makefile", "kafka grpc").is_empty());
    }

    #[test]
    fn soap_and_odata_servers_are_recognized() {
        let pom = "<artifactId>cxf-spring-boot-starter-jaxws</artifactId> spring-boot-starter-web-services com.sap.cds org.apache.olingo";
        assert_eq!(found("pom.xml", pom), [JaxWs, SpringWs, SapCap, Olingo]);
        let csproj = r#"<PackageReference Include="CoreWCF.Http" /><Reference Include="System.ServiceModel" /><Reference Include="System.Web.Services" /><PackageReference Include="Microsoft.AspNetCore.OData" Version="8" />"#;
        assert_eq!(
            found("Api.csproj", csproj),
            [Wcf, CoreWcf, Asmx, AspNetCoreOData]
        );
        // A WCF client package is not a service.
        let client = r#"<PackageReference Include="System.ServiceModel.Http" />"#;
        assert!(found("Api.csproj", client).is_empty());
        assert_eq!(found("requirements.txt", "spyne==2.14\n"), [Spyne]);
        assert!(found("requirements.txt", "zeep==4.2\n").is_empty());
        assert_eq!(
            found(
                "package.json",
                r#"{"dependencies":{"soap":"1","@sap/cds":"8"}}"#
            ),
            [NodeSoap, SapCap]
        );
        assert_eq!(
            found("composer.json", r#"{"require":{"ext-soap":"*"}}"#),
            [PhpSoap]
        );
    }
}
