//! The OData CSDL standard: detection, validation, completeness,
//! preservation and what is never written.

use serde_json::json;

use super::*;
use crate::diagnostic::{Code, Severity};
use crate::libraries::ApiLibrary;

/// A complete OData 4.0 `$metadata` document.
pub(crate) const CATALOG: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx">
  <edmx:Reference Uri="https://oasis-tcs.github.io/odata-vocabularies/vocabularies/Org.OData.Core.V1.xml">
    <edmx:Include Namespace="Org.OData.Core.V1" Alias="Core"/>
  </edmx:Reference>
  <edmx:DataServices>
    <Schema Namespace="Catalog" Alias="C" xmlns="http://docs.oasis-open.org/odata/ns/edm">
      <EntityType Name="Product">
        <Key><PropertyRef Name="ID"/></Key>
        <Property Name="ID" Type="Edm.Int32" Nullable="false"/>
        <Property Name="Name" Type="Edm.String"/>
        <Property Name="Color" Type="C.Color"/>
        <Property Name="Tags" Type="Collection(Edm.String)"/>
        <NavigationProperty Name="Category" Type="Catalog.Category" Partner="Products"/>
      </EntityType>
      <EntityType Name="Category">
        <Key><PropertyRef Name="ID"/></Key>
        <Property Name="ID" Type="Edm.Int32" Nullable="false"/>
        <NavigationProperty Name="Products" Type="Collection(Catalog.Product)" Partner="Category"/>
      </EntityType>
      <EntityType Name="Special" BaseType="Catalog.Product"/>
      <EnumType Name="Color"><Member Name="Red" Value="0"/></EnumType>
      <Action Name="Rate" IsBound="true">
        <Parameter Name="product" Type="Catalog.Product"/>
        <Parameter Name="stars" Type="Edm.Int32"/>
      </Action>
      <Action Name="Reset"/>
      <Function Name="Top"><ReturnType Type="Collection(Catalog.Product)"/></Function>
      <EntityContainer Name="Container">
        <EntitySet Name="Products" EntityType="Catalog.Product">
          <NavigationPropertyBinding Path="Category" Target="Categories"/>
        </EntitySet>
        <EntitySet Name="Categories" EntityType="Catalog.Category">
          <NavigationPropertyBinding Path="Products" Target="Catalog.Container/Products"/>
        </EntitySet>
        <Singleton Name="Featured" Type="C.Product"/>
        <ActionImport Name="Reset" Action="Catalog.Reset"/>
        <FunctionImport Name="Top" Function="Catalog.Top" EntitySet="Products"/>
      </EntityContainer>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>
"#;

fn parse(text: &str) -> Value {
    ODATA.parse(text, Syntax::Xml).unwrap()
}

fn keys(model: &Value, peers: &[Peer<'_>]) -> Vec<(Severity, Code, String)> {
    ODATA
        .validate(model, peers)
        .into_iter()
        .map(|d| (d.severity, d.code, d.pointer))
        .collect()
}

fn messages(model: &Value) -> Vec<String> {
    ODATA
        .validate(model, &[])
        .into_iter()
        .map(|d| d.message)
        .collect()
}

#[test]
fn names_nominate_metadata_files() {
    for (path, strength) in [
        ("$metadata", Some(NameStrength::Strong)),
        ("srv/$METADATA.xml", Some(NameStrength::Strong)),
        ("api/$metadata.json", Some(NameStrength::Strong)),
        ("Model.edmx", Some(NameStrength::Strong)),
        ("catalog.csdl.xml", Some(NameStrength::Strong)),
        ("catalog.csdl.json", Some(NameStrength::Strong)),
        ("webapp/localService/metadata.xml", Some(NameStrength::Weak)),
        ("odata-service.json", Some(NameStrength::Weak)),
        ("pom.xml", None),
        ("metadata.yaml", None),
    ] {
        assert_eq!(ODATA.candidate_strength(path), strength, "{path}");
    }
}

#[test]
fn content_decides_what_a_candidate_is() {
    let classify = |path: &str, text: &str| ODATA.classify(path, text.as_bytes(), 1 << 20);
    assert!(matches!(
        classify("$metadata.xml", CATALOG),
        Candidate::Spec {
            syntax: Syntax::Xml,
            version: Some(SpecVersion::Odata4),
            ..
        }
    ));
    assert!(matches!(
        classify("$metadata", CATALOG),
        Candidate::Spec {
            syntax: Syntax::Xml,
            ..
        }
    ));
    let json = r#"{"$Version": "4.01", "S": {}}"#;
    for path in ["$metadata", "service.csdl.json"] {
        assert!(matches!(
            classify(path, json),
            Candidate::Spec {
                syntax: Syntax::Json,
                version: Some(SpecVersion::Odata4),
                ..
            }
        ));
    }
    // A strongly named file that is not JSON may be replaced; one that is
    // JSON but not CSDL is left alone.
    assert!(matches!(
        classify("service.csdl.json", "{"),
        Candidate::Malformed {
            syntax: Syntax::Json,
            ..
        }
    ));
    assert!(matches!(
        classify("service.csdl.json", "{}"),
        Candidate::Unverifiable { reason } if reason.contains("without $Version")
    ));
    assert_eq!(classify("odata.json", "{}"), Candidate::NotASpec);
    assert_eq!(classify("odata.json", "{"), Candidate::NotASpec);
    assert!(matches!(
        classify("odata.json", "{\"$Version\": "),
        Candidate::Unverifiable { .. }
    ));
    let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
    assert!(matches!(
        classify("service.csdl.json", &deep),
        Candidate::Unverifiable { .. }
    ));
    // A DOCTYPE is refused outright.
    let doctype = format!("<!DOCTYPE x>{CATALOG}");
    assert!(matches!(
        classify("$metadata.xml", &doctype),
        Candidate::Unverifiable { reason } if reason.contains("DOCTYPE")
    ));
    assert_eq!(
        classify("metadata.xml", "<!DOCTYPE x><x/>"),
        Candidate::NotASpec
    );
    assert!(matches!(
        classify("Model.edmx", "<Model/>"),
        Candidate::Unverifiable { reason } if reason.contains("not an OData edmx:Edmx")
    ));
    assert_eq!(classify("metadata.xml", "<Model/>"), Candidate::NotASpec);
    let designer = format!(
        r#"<edmx:Edmx Version="3.0" xmlns:edmx="{}"><edmx:Runtime/></edmx:Edmx>"#,
        model::EDMX_ENTITY_FRAMEWORK[1]
    );
    assert_eq!(classify("Model.edmx", &designer), Candidate::NotASpec);
    assert!(matches!(
        ODATA.classify("$metadata.xml", CATALOG.as_bytes(), 8),
        Candidate::Unverifiable { .. }
    ));
    assert_eq!(
        ODATA.classify("metadata.xml", b"<x/>0123456789", 8),
        Candidate::NotASpec
    );
    assert!(matches!(
        ODATA.classify("Model.edmx", &[0xff], 8),
        Candidate::Unverifiable { .. }
    ));
    assert_eq!(classify("pom.xml", CATALOG), Candidate::NotASpec);
}

#[test]
fn a_complete_document_has_no_diagnostics_in_either_syntax() {
    let model = parse(CATALOG);
    assert_eq!(keys(&model, &[]), []);
    let json = json!({
        "$Version": "4.01",
        "$EntityContainer": "C.Container",
        "Catalog": {
            "$Alias": "C",
            "Product": {"$Kind": "EntityType", "$Key": ["ID"], "ID": {"$Type": "Edm.Int32"}},
            "Container": {"$Kind": "EntityContainer", "Products": {"$Collection": true, "$Type": "C.Product"}},
        },
    });
    let model = ODATA.parse(&json.to_string(), Syntax::Json).unwrap();
    assert_eq!(keys(&model, &[]), []);
    assert_eq!(ODATA.version(&model), Some(SpecVersion::Odata4));
    assert!(matches!(
        ODATA.parse("{\"a\": 1}", Syntax::Json),
        Err(ParseFailure::Malformed(reason)) if reason.contains("no $Version")
    ));
    assert!(matches!(
        ODATA.parse("<x/>", Syntax::Xml),
        Err(ParseFailure::Malformed(_))
    ));
    assert_eq!(ODATA.name(), "OData CSDL");
    assert_eq!(ODATA.id(), FormatId::OData);
    assert_eq!(ODATA.capabilities(), CAPABILITIES);
    assert!(!ODATA.scans_source() && ODATA.scan_source("a.cs", "EntitySet<T>").is_empty());
}

/// Breaks most rules once.
const BROKEN: &str = r#"<edmx:Edmx Version="4.1" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx">
  <edmx:Reference Uri="https://example.com/common.xml"><edmx:Include Namespace="Common" Alias="Co"/></edmx:Reference>
  <edmx:Reference Uri="../shared/missing.xml"><edmx:Include/></edmx:Reference>
  <edmx:Reference><edmx:Include Namespace="X"/></edmx:Reference>
  <edmx:DataServices>
    <Schema Namespace="S" Alias="Edm" xmlns="http://docs.oasis-open.org/odata/ns/edm">
      <EntityType Name="NoKey"><Property Name="A" Type="Edm.Strin"/><Property Name="A" Type="Co.Thing"/></EntityType>
      <EntityType Name="BadKey">
        <Key><PropertyRef Name="Missing"/><PropertyRef Name="Id"/></Key>
        <Property Name="Id" Type="Edm.Int32"/>
        <Property Name="Entity" Type="S.BadKey"/>
        <Property Name="Unknown" Type="S.Nope"/>
        <Property Name="NoType"/>
        <NavigationProperty Name="ToEnum" Type="S.Color"/>
        <NavigationProperty Name="ToPrimitive" Type="Edm.Int32"/>
        <NavigationProperty Name="Partnered" Type="S.NoKey" Partner="Back"/>
        <NavigationProperty Name="Lost" Type="S.Gone" Partner="Back"/>
      </EntityType>
      <EntityType Name="Derived" BaseType="S.Color"/>
      <EntityType Name="Derived"/>
      <ComplexType Name="Base" BaseType="Edm.String"/>
      <EnumType Name="Color"/>
      <EnumType/>
      <EntityType Name="Cycle" BaseType="S.Cycle"><Key><PropertyRef Name="Z"/></Key><Property Name="Bare" Type="Bare"/></EntityType>
      <Action Name="Bound" IsBound="true"/>
      <Function Name="NoReturn"/>
      <Function Name="Color"><ReturnType Type="S.Missing"/></Function>
      <Action Name="Twice"/>
      <Function Name="Twice"><ReturnType Type="Edm.Int32"/></Function>
      <EntityContainer Name="C">
        <EntitySet Name="Sets" EntityType="S.Base">
          <NavigationPropertyBinding Path="X" Target="Nowhere"/>
        </EntitySet>
        <Singleton Name="Sets" Type="S.NoKey"/>
        <ActionImport Name="A" Action="S.Missing" EntitySet="Nope"/>
        <ActionImport Name="B" Action="S.Bound"/>
        <ActionImport Name="Vocabulary" Action="Org.OData.Core.V1.Thing"/>
        <FunctionImport Name="F" Function="S.Twice"/>
      </EntityContainer>
      <EntityContainer Name="Second"/>
    </Schema>
    <Schema Namespace="System"/>
    <Schema Namespace="S"/>
  </edmx:DataServices>
</edmx:Edmx>"#;

#[test]
fn a_broken_document_reports_each_problem() {
    let model = parse(BROKEN);
    let found = keys(&model, &[]);
    let expected: Vec<(Severity, Code, &str)> = vec![
        (Severity::Error, Code::InvalidVersion, "/version"),
        (
            Severity::Warning,
            Code::ExternalRef,
            "/references/https:~1~1example.com~1common.xml",
        ),
        (
            Severity::Error,
            Code::MissingField,
            "/references/..~1shared~1missing.xml",
        ),
        (
            Severity::Error,
            Code::UnresolvedRef,
            "/references/..~1shared~1missing.xml",
        ),
        (Severity::Error, Code::MissingField, "/references/"),
        (Severity::Error, Code::DuplicateDefinition, "/schemas/S"),
        (Severity::Error, Code::ReservedName, "/schemas/S"),
        (Severity::Error, Code::ReservedName, "/schemas/System"),
        (
            Severity::Error,
            Code::DuplicateDefinition,
            "/types/S.Derived",
        ),
        (Severity::Error, Code::MissingField, "/types/S."),
        (Severity::Error, Code::DuplicateField, "/types/S.NoKey/A"),
        (
            Severity::Error,
            Code::UnknownType,
            "/types/S.NoKey/properties/A",
        ),
        (Severity::Error, Code::MissingKey, "/types/S.NoKey"),
        (
            Severity::Error,
            Code::InvalidType,
            "/types/S.BadKey/properties/Entity",
        ),
        (
            Severity::Error,
            Code::UnknownType,
            "/types/S.BadKey/properties/Unknown",
        ),
        (
            Severity::Error,
            Code::MissingField,
            "/types/S.BadKey/properties/NoType",
        ),
        (
            Severity::Error,
            Code::InvalidType,
            "/types/S.BadKey/navigation/ToEnum",
        ),
        (
            Severity::Error,
            Code::InvalidType,
            "/types/S.BadKey/navigation/ToPrimitive",
        ),
        (
            Severity::Error,
            Code::UnresolvedRef,
            "/types/S.BadKey/navigation/Partnered",
        ),
        (
            Severity::Error,
            Code::UnknownType,
            "/types/S.BadKey/navigation/Lost",
        ),
        (Severity::Error, Code::InvalidKey, "/types/S.BadKey"),
        (Severity::Warning, Code::InvalidKey, "/types/S.BadKey"),
        (Severity::Error, Code::InvalidType, "/types/S.Derived"),
        (Severity::Error, Code::MissingKey, "/types/S.Derived"),
        (Severity::Error, Code::InvalidType, "/types/S.Base"),
        (
            Severity::Error,
            Code::UnknownType,
            "/types/S.Cycle/properties/Bare",
        ),
        (Severity::Error, Code::InvalidKey, "/types/S.Cycle"),
        (Severity::Error, Code::MissingField, "/operations/S.Bound"),
        (
            Severity::Error,
            Code::MissingField,
            "/operations/S.NoReturn",
        ),
        (
            Severity::Error,
            Code::DuplicateDefinition,
            "/operations/S.Color",
        ),
        (Severity::Error, Code::UnknownType, "/operations/S.Color"),
        (
            Severity::Error,
            Code::DuplicateDefinition,
            "/operations/S.Twice",
        ),
        (Severity::Error, Code::DuplicateDefinition, "/containers"),
        (
            Severity::Error,
            Code::DuplicateDefinition,
            "/containers/S.C/Sets",
        ),
        (
            Severity::Error,
            Code::InvalidType,
            "/containers/S.C/entitySets/Sets",
        ),
        (
            Severity::Error,
            Code::UnresolvedRef,
            "/containers/S.C/entitySets/Sets",
        ),
        (
            Severity::Error,
            Code::UnresolvedRef,
            "/containers/S.C/actionImports/A",
        ),
        (
            Severity::Error,
            Code::UnresolvedRef,
            "/containers/S.C/actionImports/A",
        ),
        (
            Severity::Error,
            Code::UnresolvedRef,
            "/containers/S.C/actionImports/B",
        ),
    ];
    let found_keys: Vec<(Severity, Code, &str)> = found
        .iter()
        .map(|(severity, code, pointer)| (*severity, *code, pointer.as_str()))
        .collect();
    assert_eq!(found_keys, expected, "{found:#?}");
    let messages = messages(&model);
    for fragment in [
        "CSDL version `4.1` is not 4.0 or 4.01",
        "was not fetched",
        "an include needs a namespace",
        "not found among the repository's readable CSDL files",
        "a reference needs a URI",
        "`Edm` is reserved",
        "`Edm.Strin` is not an OData primitive type",
        "entity type `S.NoKey` needs a key",
        "which is a EntityType",
        "type `S.Nope` is not declared",
        "property `NoType` needs a type",
        "cannot be of the primitive type `Edm.Int32`",
        "partner `Back` is not a navigation property of `S.NoKey`",
        "key property `Missing` is not a property",
        "key property `Id` is nullable",
        "bound Action `S.Bound` needs a binding parameter",
        "function `S.NoReturn` needs a return type",
        "names more than one kind of definition",
        "at most one entity container",
        "navigation binding target `Nowhere`",
        "entity set `Nope` is not an entity set of the container",
        "`S.Missing` names no unbound action",
    ] {
        assert!(
            messages.iter().any(|message| message.contains(fragment)),
            "{fragment}"
        );
    }
}

#[test]
fn json_documents_name_their_container_and_version() {
    let parse_json = |value: Value| ODATA.parse(&value.to_string(), Syntax::Json).unwrap();
    let wrong = parse_json(json!({"$Version": "4.01", "$EntityContainer": "S.Other", "S": {}}));
    assert_eq!(
        keys(&wrong, &[]),
        [(
            Severity::Error,
            Code::UnresolvedRef,
            "/entityContainer".to_string()
        )]
    );
    let unversioned =
        parse(r#"<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx"/>"#);
    assert_eq!(
        keys(&unversioned, &[]),
        [
            (
                Severity::Error,
                Code::MissingVersion,
                "/version".to_string()
            ),
            (Severity::Error, Code::MissingField, "/schemas".to_string()),
        ]
    );
}

#[test]
fn legacy_metadata_is_validated_and_never_rewritten() {
    let legacy = r#"<edmx:Edmx Version="1.0" xmlns:edmx="http://schemas.microsoft.com/ado/2007/06/edmx"
    xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
  <edmx:DataServices m:DataServiceVersion="2.0">
    <Schema Namespace="Northwind" xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
      <EntityType Name="Order">
        <Key><PropertyRef Name="OrderID"/></Key>
        <Property Name="OrderID" Type="Edm.Int32" Nullable="false"/>
        <Property Name="OrderDate" Type="Edm.DateTime"/>
        <NavigationProperty Name="Customer" Relationship="Northwind.FK" FromRole="Order" ToRole="Customer"/>
      </EntityType>
      <EntityContainer Name="Entities" m:IsDefaultEntityContainer="true">
        <EntitySet Name="Orders" EntityType="Northwind.Order"/>
        <FunctionImport Name="Recent" ReturnType="Collection(Northwind.Order)" EntitySet="Orders"/>
      </EntityContainer>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>"#;
    let candidate = ODATA.classify("$metadata.xml", legacy.as_bytes(), 1 << 20);
    let parts = candidate.into_parts().unwrap().unwrap();
    assert_eq!(parts.version, Some(SpecVersion::Odata2));
    let model = parts.document.unwrap();
    let found = ODATA.validate(&model, &[]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].severity, Severity::Warning);
    assert_eq!(found[0].code, Code::LegacyVersion);
    assert!(found[0].message.contains("OData version 2 metadata"));
    assert_eq!(
        ODATA.document_capabilities(Some(SpecVersion::Odata2)),
        Capabilities::CHECK_ONLY
    );
    assert_eq!(
        ODATA.document_capabilities(Some(SpecVersion::Odata3)),
        Capabilities::CHECK_ONLY
    );
    assert_eq!(
        ODATA.document_capabilities(Some(SpecVersion::Odata4)),
        CAPABILITIES
    );
    const { assert!(CAPABILITIES.repair && !CAPABILITIES.create && !CAPABILITIES.relocate) };
    assert_eq!(
        ODATA.operations(&model),
        [
            Operation::new("entity_set", "Orders"),
            Operation::new("function", "Recent"),
        ]
    );
    assert_eq!(ODATA.version(&model), Some(SpecVersion::Odata2));
    assert_eq!(
        ODATA.version(&json!({"odata": 3})),
        Some(SpecVersion::Odata3)
    );
    assert_eq!(ODATA.version(&json!({})), None);
}

#[test]
fn references_resolve_within_the_repository() {
    let shared = parse(
        r#"<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx"><edmx:DataServices><Schema Namespace="Common" xmlns="http://docs.oasis-open.org/odata/ns/edm"><ComplexType Name="Address"/></Schema></edmx:DataServices></edmx:Edmx>"#,
    );
    let peers = [Peer {
        path: "srv/shared/common.xml",
        document: &shared,
    }];
    let using = |uri: &str, kind: &str| {
        parse(&format!(
            r#"<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx">
  <edmx:Reference Uri="{uri}"><edmx:Include Namespace="Common" Alias="Co"/></edmx:Reference>
  <edmx:DataServices><Schema Namespace="S" xmlns="http://docs.oasis-open.org/odata/ns/edm">
    <ComplexType Name="C"><Property Name="A" Type="Co.{kind}"/></ComplexType>
  </Schema></edmx:DataServices>
</edmx:Edmx>"#
        ))
    };
    assert_eq!(keys(&using("../shared/common.xml", "Address"), &peers), []);
    assert_eq!(
        keys(&using("../shared/common.xml", "Missing"), &peers),
        [(
            Severity::Error,
            Code::UnknownType,
            "/types/S.C/properties/A".to_string()
        )]
    );
    // A remote reference is never fetched: a warning, and its types are
    // not checked.
    let remote = keys(&using("https://example.com/common.xml", "Anything"), &peers);
    assert_eq!(
        remote,
        [(
            Severity::Warning,
            Code::ExternalRef,
            "/references/https:~1~1example.com~1common.xml".to_string()
        )]
    );
}

#[test]
fn operations_are_sets_singletons_actions_and_functions() {
    let model = parse(CATALOG);
    let operations = ODATA.operations(&model);
    assert_eq!(
        operations,
        [
            Operation::new("action", "Rate"),
            Operation::new("action", "Reset"),
            Operation::new("entity_set", "Categories"),
            Operation::new("entity_set", "Products"),
            Operation::new("function", "Top"),
            Operation::new("singleton", "Featured"),
        ]
    );
    let other = ODATA
        .parse(r#"{"$Version": "4.01", "O": {"C": {"$Kind": "EntityContainer", "Orders": {"$Collection": true, "$Type": "O.Order"}}}}"#, Syntax::Json)
        .unwrap();
    let peers = [Peer {
        path: "orders.csdl.json",
        document: &other,
    }];
    let inventory = [
        Operation::new("entity_set", "Products"),
        Operation::new("entity_set", "Orders"),
        Operation::new("entity_set", "Customers"),
    ];
    let result = ODATA.compare(&model, &peers, &inventory);
    assert_eq!(result.missing, [Operation::new("entity_set", "Customers")]);
    assert_eq!(result.unverified.len(), 5);
    assert!(ODATA
        .operations(&json!({"containers": [{"entitySets": [{"name": ""}]}]}))
        .is_empty());
}

#[test]
fn inventory_entries_are_addressable_names() {
    assert_eq!(
        ODATA
            .inventory_operation(" Entity_Set ", " Products ")
            .unwrap(),
        Operation::new("entity_set", "Products")
    );
    assert!(ODATA.inventory_operation("function", "Straße_1").is_ok());
    assert!(ODATA
        .inventory_operation("get", "Products")
        .unwrap_err()
        .contains("is not entity_set, singleton, action or function"));
    for path in ["", "1a", "a.b", "/Products", &"a".repeat(129)] {
        assert!(ODATA
            .inventory_operation("action", path)
            .unwrap_err()
            .contains("simple identifier"));
    }
}

#[test]
fn a_repair_keeps_what_the_document_declared() {
    let original = parse(CATALOG);
    let added = CATALOG.replace(
        "<Property Name=\"Name\" Type=\"Edm.String\"/>",
        "<Property Name=\"Name\" Type=\"Edm.String\"/>\n        <Property Name=\"Price\" Type=\"Edm.Decimal\"/>",
    );
    assert!(ODATA
        .preservation(&original, &parse(&added), &[])
        .is_empty());
    let check = |text: &str| ODATA.preservation(&original, &parse(text), &[]);
    assert_eq!(
        check(&CATALOG.replace("<Singleton Name=\"Featured\" Type=\"C.Product\"/>", "")),
        ["removed documented singleton `Catalog.Container.Featured`"]
    );
    assert_eq!(
        check(&CATALOG.replace(
            "Type=\"Edm.String\"/>\n        <Property Name=\"Color\"",
            "Type=\"Edm.Guid\"/>\n        <Property Name=\"Color\""
        )),
        ["changed property `Catalog.Product.Name`, which had no diagnostics"]
    );
    assert_eq!(
        check(&CATALOG.replace("Version=\"4.0\"", "Version=\"4.01\"")),
        ["changed the CSDL version, which had no diagnostics"]
    );
    assert_eq!(
        check(&CATALOG.replace("Alias=\"Core\"", "Alias=\"Cr\"")),
        ["removed or changed the reference to `https://oasis-tcs.github.io/odata-vocabularies/vocabularies/Org.OData.Core.V1.xml`"]
    );
    let legacy = json!({"odata": 2, "format": "xml"});
    assert_eq!(
        ODATA.preservation(&original, &legacy, &[]),
        ["the repair changed the OData version or CSDL syntax; repairs keep the author's"]
    );
    let json_before = json!({"odata": 4, "format": "json", "entityContainer": "A.B"});
    let json_after = json!({"odata": 4, "format": "json", "entityContainer": "A.C"});
    assert_eq!(
        ODATA.preservation(&json_before, &json_after, &[]),
        ["changed $EntityContainer, which had no diagnostics"]
    );
    let before = [
        Diagnostic::error(Code::UnresolvedRef, "/entityContainer", ""),
        Diagnostic::error(Code::InvalidVersion, "/version", ""),
    ];
    assert!(ODATA
        .preservation(&json_before, &json_after, &before)
        .is_empty());
    let unversioned = parse(&CATALOG.replace("Version=\"4.0\"", "Version=\"4\""));
    assert!(ODATA
        .preservation(&unversioned, &original, &before)
        .is_empty());
}

#[test]
fn nothing_is_ever_created() {
    assert!(ODATA
        .emit(&json!("<edmx:Edmx/>"), Syntax::Xml)
        .unwrap_err()
        .contains("never created"));
    assert_eq!(ODATA.new_document_problems(&json!({})), [NEVER_CREATED]);
}

#[test]
fn owners_are_services_with_an_odata_server() {
    let surfaces = [ApiSurface {
        root: "srv".into(),
        manifests: vec!["srv/package.json".into()],
        libraries: [ApiLibrary::SapCap, ApiLibrary::Kafka]
            .into_iter()
            .collect(),
    }];
    let owners = ODATA.owners(&[], &surfaces);
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].stack, ["sap_cap"]);
    assert!(owners[0].convention.basis.contains("SAP CAP"));
    assert!(ODATA.owners(&[], &[]).is_empty());
    assert!(ODATA.fallback().basis.contains("never created"));
}
