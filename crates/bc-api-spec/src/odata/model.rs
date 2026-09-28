//! OData CSDL, from XML (EDMX) or JSON, read into one stable model.
//!
//! The model keeps, by qualified name (`Namespace.Name`, as written, so
//! an alias-qualified name stays alias-qualified until validation
//! resolves it): the declared version, references and their includes,
//! schemas and aliases, types (entity, complex, enum and type
//! definitions) with their keys, properties and navigation properties,
//! actions and functions with their overloads, and entity containers with
//! their entity sets, singletons and imports. A collection type is
//! written `Collection(Namespace.Name)` whichever syntax it came from.
//!
//! Both syntaxes share the shape, but not every default: an XML property
//! is nullable unless it says otherwise, a JSON one only when it says so.

use bc_xml::{Document, Element};
use serde_json::{json, Map, Value};

use crate::xml::attribute;

pub const EDMX4: &str = "http://docs.oasis-open.org/odata/ns/edmx";
/// The EDMX namespace of OData versions 1 to 3 (WCF Data Services).
pub const EDMX_LEGACY: &str = "http://schemas.microsoft.com/ado/2007/06/edmx";
/// Entity Framework designer namespaces, which also wrap a CSDL model,
/// but only as OData metadata when they carry `DataServices`.
pub const EDMX_ENTITY_FRAMEWORK: [&str; 2] = [
    "http://schemas.microsoft.com/ado/2008/10/edmx",
    "http://schemas.microsoft.com/ado/2009/11/edmx",
];
/// The WCF Data Services metadata namespace (`m:DataServiceVersion`).
pub const DATA_SERVICES_METADATA: &str =
    "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata";

/// The OData major version a model is for: `2` and `3` are legacy.
pub fn major(model: &Value) -> Option<u64> {
    model["odata"].as_u64()
}

fn flag(element: &Element, name: &str) -> bool {
    element.attribute(name) == Some("true")
}

/// The model of an EDMX document, or `None` when it is not OData
/// metadata (another root, or an Entity Framework model).
pub fn from_xml(document: &Document) -> Option<Value> {
    let root = &document.root;
    if root.name.local != "Edmx" {
        return None;
    }
    let namespace = root.namespace.as_deref()?;
    let services = root.first_child_named(Some(namespace), "DataServices");
    let odata = match namespace {
        EDMX4 => 4,
        EDMX_LEGACY => {
            let declared = services.and_then(|services| {
                services.attribute_ns(Some(DATA_SERVICES_METADATA), "DataServiceVersion")
            });
            if declared.is_some_and(|version| version.starts_with('3')) {
                3
            } else {
                2
            }
        }
        other if EDMX_ENTITY_FRAMEWORK.contains(&other) && services.is_some() => 3,
        _ => return None,
    };
    let references: Vec<Value> = root
        .children_named(Some(namespace), "Reference")
        .map(|reference| {
            let includes: Vec<Value> = reference
                .children_named(Some(namespace), "Include")
                .map(|include| {
                    json!({
                        "namespace": attribute(include, "Namespace"),
                        "alias": attribute(include, "Alias"),
                    })
                })
                .collect();
            json!({"uri": attribute(reference, "Uri"), "includes": includes})
        })
        .collect();
    let mut model = Builder::new("xml", attribute(root, "Version"), odata);
    model.references = references;
    for schema in services
        .into_iter()
        .flat_map(|services| services.child_elements())
        .filter(|schema| schema.name.local == "Schema")
    {
        model.xml_schema(schema);
    }
    Some(model.finish(Value::Null))
}

/// Collects a model's entries.
struct Builder {
    format: &'static str,
    version: Value,
    odata: u64,
    references: Vec<Value>,
    schemas: Vec<Value>,
    types: Vec<Value>,
    operations: Vec<Value>,
    containers: Vec<Value>,
}

impl Builder {
    fn new(format: &'static str, version: Value, odata: u64) -> Self {
        Self {
            format,
            version,
            odata,
            references: Vec::new(),
            schemas: Vec::new(),
            types: Vec::new(),
            operations: Vec::new(),
            containers: Vec::new(),
        }
    }

    fn finish(self, entity_container: Value) -> Value {
        json!({
            "kind": "csdl",
            "format": self.format,
            "version": self.version,
            "odata": self.odata,
            "entityContainer": entity_container,
            "references": self.references,
            "schemas": self.schemas,
            "types": self.types,
            "operations": self.operations,
            "containers": self.containers,
        })
    }

    /// Record an overload of the action or function `name`.
    fn overload(&mut self, name: String, kind: &str, overload: Value) {
        match self
            .operations
            .iter_mut()
            .find(|operation| operation["name"] == name.as_str() && operation["kind"] == kind)
        {
            Some(operation) => operation["overloads"]
                .as_array_mut()
                .expect("an operation's overloads are a list")
                .push(overload),
            None => self.operations.push(json!({
                "name": name,
                "kind": kind,
                "overloads": [overload],
            })),
        }
    }

    fn xml_schema(&mut self, schema: &Element) {
        let namespace = schema.attribute("Namespace").unwrap_or_default();
        self.schemas.push(json!({
            "name": schema.attribute("Namespace"),
            "alias": attribute(schema, "Alias"),
        }));
        let edm = schema.namespace.as_deref();
        for child in schema
            .child_elements()
            .filter(|child| child.namespace.as_deref() == edm)
        {
            let qualified = format!(
                "{namespace}.{}",
                child.attribute("Name").unwrap_or_default()
            );
            let named = |local| child.children_named(edm, local);
            match child.name.local.as_str() {
                kind @ ("EntityType" | "ComplexType") => {
                    let key = child.first_child_named(edm, "Key").map(|key| {
                        key.children_named(edm, "PropertyRef")
                            .map(|reference| attribute(reference, "Name"))
                            .collect::<Vec<Value>>()
                    });
                    let properties: Vec<Value> = named("Property")
                        .map(|property| {
                            json!({
                                "name": attribute(property, "Name"),
                                "type": attribute(property, "Type"),
                                "nullable": property.attribute("Nullable") != Some("false"),
                            })
                        })
                        .collect();
                    let navigation: Vec<Value> = named("NavigationProperty")
                        .map(|navigation| {
                            json!({
                                "name": attribute(navigation, "Name"),
                                "type": attribute(navigation, "Type"),
                                "partner": attribute(navigation, "Partner"),
                            })
                        })
                        .collect();
                    self.types.push(json!({
                        "name": qualified,
                        "kind": kind,
                        "baseType": attribute(child, "BaseType"),
                        "abstract": flag(child, "Abstract"),
                        "key": key,
                        "properties": properties,
                        "navigation": navigation,
                    }));
                }
                "EnumType" => {
                    let members: Vec<Value> = named("Member")
                        .map(|member| {
                            json!({"name": attribute(member, "Name"), "value": attribute(member, "Value")})
                        })
                        .collect();
                    self.types.push(json!({
                        "name": qualified,
                        "kind": "EnumType",
                        "underlyingType": attribute(child, "UnderlyingType"),
                        "members": members,
                    }));
                }
                "TypeDefinition" => self.types.push(json!({
                    "name": qualified,
                    "kind": "TypeDefinition",
                    "underlyingType": attribute(child, "UnderlyingType"),
                })),
                kind @ ("Action" | "Function") => {
                    let parameters: Vec<Value> = named("Parameter")
                        .map(|parameter| {
                            json!({"name": attribute(parameter, "Name"), "type": attribute(parameter, "Type")})
                        })
                        .collect();
                    let return_type = child
                        .first_child_named(edm, "ReturnType")
                        .map_or(Value::Null, |returned| attribute(returned, "Type"));
                    let overload = json!({
                        "bound": flag(child, "IsBound"),
                        "parameters": parameters,
                        "returnType": return_type,
                    });
                    self.overload(qualified, kind, overload);
                }
                "EntityContainer" => {
                    let bindings = |set: &Element| -> Vec<Value> {
                        set.children_named(edm, "NavigationPropertyBinding")
                            .map(|binding| {
                                json!({"path": attribute(binding, "Path"), "target": attribute(binding, "Target")})
                            })
                            .collect()
                    };
                    let entity_sets: Vec<Value> = named("EntitySet")
                        .map(|set| {
                            json!({
                                "name": attribute(set, "Name"),
                                "entityType": attribute(set, "EntityType"),
                                "bindings": bindings(set),
                            })
                        })
                        .collect();
                    let singletons: Vec<Value> = named("Singleton")
                        .map(|singleton| {
                            json!({
                                "name": attribute(singleton, "Name"),
                                "type": attribute(singleton, "Type"),
                                "bindings": bindings(singleton),
                            })
                        })
                        .collect();
                    // `ActionImport Action=` or `FunctionImport Function=`.
                    let imports = |kind: &str, key: &str| -> Vec<Value> {
                        let local = format!("{kind}Import");
                        child
                            .children_named(edm, &local)
                            .map(|import| {
                                let mut entry = json!({
                                    "name": attribute(import, "Name"),
                                    "entitySet": attribute(import, "EntitySet"),
                                });
                                entry[key] = attribute(import, kind);
                                entry
                            })
                            .collect()
                    };
                    self.containers.push(json!({
                        "name": qualified,
                        "extends": attribute(child, "Extends"),
                        "entitySets": entity_sets,
                        "singletons": singletons,
                        "actionImports": imports("Action", "action"),
                        "functionImports": imports("Function", "function"),
                    }));
                }
                // Terms, annotations and the legacy associations are not
                // part of what this step checks.
                _ => {}
            }
        }
    }
}

/// `$Type` with `$Collection`, as one type string.
fn json_type(member: &Map<String, Value>, default: &str) -> Value {
    let base = member
        .get("$Type")
        .and_then(Value::as_str)
        .unwrap_or(default);
    if member.get("$Collection") == Some(&Value::Bool(true)) {
        json!(format!("Collection({base})"))
    } else {
        json!(base)
    }
}

fn json_flag(member: &Map<String, Value>, name: &str) -> bool {
    member.get(name) == Some(&Value::Bool(true))
}

fn json_text(member: &Map<String, Value>, name: &str) -> Value {
    member.get(name).cloned().unwrap_or(Value::Null)
}

/// The named members of a JSON CSDL object: every key that is neither a
/// `$` keyword nor an `@` annotation.
fn json_members(object: &Map<String, Value>) -> impl Iterator<Item = (&String, &Value)> {
    object
        .iter()
        .filter(|(name, _)| !name.starts_with('$') && !name.contains('@'))
}

/// The model of a CSDL JSON document, or `None` when it has no
/// `$Version`.
pub fn from_json(document: &Value) -> Option<Value> {
    let root = document.as_object()?;
    let version = root.get("$Version")?.clone();
    let mut model = Builder::new("json", version, 4);
    for (uri, reference) in root
        .get("$Reference")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let includes: Vec<Value> = reference["$Include"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|include| json!({"namespace": include["$Namespace"], "alias": include["$Alias"]}))
            .collect();
        model
            .references
            .push(json!({"uri": uri, "includes": includes}));
    }
    for (namespace, schema) in json_members(root) {
        let Some(schema) = schema.as_object() else {
            continue;
        };
        model.schemas.push(json!({
            "name": namespace,
            "alias": json_text(schema, "$Alias"),
        }));
        for (name, member) in json_members(schema) {
            model.json_member(&format!("{namespace}.{name}"), member);
        }
    }
    Some(model.finish(json_text(root, "$EntityContainer")))
}

impl Builder {
    fn json_member(&mut self, qualified: &str, member: &Value) {
        if let Some(overloads) = member.as_array() {
            for overload in overloads.iter().filter_map(Value::as_object) {
                let kind = overload
                    .get("$Kind")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let parameters: Vec<Value> = overload
                    .get("$Parameter")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_object)
                    .map(|parameter| {
                        json!({"name": json_text(parameter, "$Name"), "type": json_type(parameter, "Edm.String")})
                    })
                    .collect();
                let return_type = overload
                    .get("$ReturnType")
                    .and_then(Value::as_object)
                    .map_or(Value::Null, |returned| json_type(returned, "Edm.String"));
                let entry = json!({
                    "bound": json_flag(overload, "$IsBound"),
                    "parameters": parameters,
                    "returnType": return_type,
                });
                self.overload(qualified.to_string(), kind, entry);
            }
            return;
        }
        let Some(member) = member.as_object() else {
            return;
        };
        match member.get("$Kind").and_then(Value::as_str) {
            Some(kind @ ("EntityType" | "ComplexType")) => {
                let key = member.get("$Key").and_then(Value::as_array).map(|key| {
                    key.iter()
                        .map(|part| match part {
                            // `{"Alias": "Path/To/Property"}`
                            Value::Object(aliased) => {
                                aliased.values().next().cloned().unwrap_or(Value::Null)
                            }
                            other => other.clone(),
                        })
                        .collect::<Vec<Value>>()
                });
                let mut properties = Vec::new();
                let mut navigation = Vec::new();
                for (name, property) in json_members(member) {
                    let Some(property) = property.as_object() else {
                        continue;
                    };
                    if property.get("$Kind").and_then(Value::as_str) == Some("NavigationProperty") {
                        navigation.push(json!({
                            "name": name,
                            "type": json_type(property, ""),
                            "partner": json_text(property, "$Partner"),
                        }));
                    } else {
                        properties.push(json!({
                            "name": name,
                            "type": json_type(property, "Edm.String"),
                            "nullable": json_flag(property, "$Nullable"),
                        }));
                    }
                }
                self.types.push(json!({
                    "name": qualified,
                    "kind": kind,
                    "baseType": json_text(member, "$BaseType"),
                    "abstract": json_flag(member, "$Abstract"),
                    "key": key,
                    "properties": properties,
                    "navigation": navigation,
                }));
            }
            Some("EnumType") => {
                let members: Vec<Value> = json_members(member)
                    .map(|(name, value)| json!({"name": name, "value": value}))
                    .collect();
                self.types.push(json!({
                    "name": qualified,
                    "kind": "EnumType",
                    "underlyingType": json_text(member, "$UnderlyingType"),
                    "members": members,
                }));
            }
            Some("TypeDefinition") => self.types.push(json!({
                "name": qualified,
                "kind": "TypeDefinition",
                "underlyingType": json_text(member, "$UnderlyingType"),
            })),
            Some("EntityContainer") => self.json_container(qualified, member),
            _ => {}
        }
    }

    fn json_container(&mut self, qualified: &str, container: &Map<String, Value>) {
        let mut entity_sets = Vec::new();
        let mut singletons = Vec::new();
        let mut action_imports = Vec::new();
        let mut function_imports = Vec::new();
        for (name, child) in json_members(container) {
            let Some(child) = child.as_object() else {
                continue;
            };
            let bindings: Vec<Value> = child
                .get("$NavigationPropertyBinding")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .map(|(path, target)| json!({"path": path, "target": target}))
                .collect();
            if child.contains_key("$Action") {
                action_imports.push(json!({
                    "name": name,
                    "action": json_text(child, "$Action"),
                    "entitySet": json_text(child, "$EntitySet"),
                }));
            } else if child.contains_key("$Function") {
                function_imports.push(json!({
                    "name": name,
                    "function": json_text(child, "$Function"),
                    "entitySet": json_text(child, "$EntitySet"),
                }));
            } else if json_flag(child, "$Collection") {
                entity_sets.push(json!({
                    "name": name,
                    "entityType": json_text(child, "$Type"),
                    "bindings": bindings,
                }));
            } else {
                singletons.push(json!({
                    "name": name,
                    "type": json_text(child, "$Type"),
                    "bindings": bindings,
                }));
            }
        }
        self.containers.push(json!({
            "name": qualified,
            "extends": json_text(container, "$Extends"),
            "entitySets": entity_sets,
            "singletons": singletons,
            "actionImports": action_imports,
            "functionImports": function_imports,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::read;

    pub(crate) const EDMX: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx">
  <edmx:Reference Uri="https://oasis-tcs.github.io/odata-vocabularies/vocabularies/Org.OData.Core.V1.xml">
    <edmx:Include Namespace="Org.OData.Core.V1" Alias="Core"/>
  </edmx:Reference>
  <edmx:DataServices>
    <Schema Namespace="Shop" Alias="S" xmlns="http://docs.oasis-open.org/odata/ns/edm">
      <EntityType Name="Product">
        <Key><PropertyRef Name="ID"/></Key>
        <Property Name="ID" Type="Edm.Int32" Nullable="false"/>
        <Property Name="Name" Type="Edm.String"/>
        <NavigationProperty Name="Category" Type="S.Category" Partner="Products"/>
      </EntityType>
      <EntityType Name="Category" Abstract="true" BaseType="Shop.Base"/>
      <ComplexType Name="Address"><Property Name="City" Type="Edm.String"/></ComplexType>
      <EnumType Name="Color"><Member Name="Red" Value="0"/></EnumType>
      <TypeDefinition Name="Money" UnderlyingType="Edm.Decimal"/>
      <Action Name="Rate" IsBound="true"><Parameter Name="p" Type="Shop.Product"/></Action>
      <Action Name="Rate" IsBound="true"><Parameter Name="c" Type="Shop.Category"/></Action>
      <Function Name="Top"><ReturnType Type="Collection(Shop.Product)"/></Function>
      <Term Name="Ignored" Type="Edm.String"/>
      <EntityContainer Name="Container">
        <EntitySet Name="Products" EntityType="Shop.Product">
          <NavigationPropertyBinding Path="Category" Target="Categories"/>
        </EntitySet>
        <Singleton Name="Featured" Type="Shop.Product"/>
        <ActionImport Name="Reset" Action="Shop.Reset"/>
        <FunctionImport Name="Top" Function="Shop.Top" EntitySet="Products"/>
      </EntityContainer>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>"#;

    fn xml(text: &str) -> Option<Value> {
        from_xml(&read(text).unwrap())
    }

    #[test]
    fn edmx_becomes_the_model() {
        let model = xml(EDMX).unwrap();
        assert_eq!(model["format"], "xml");
        assert_eq!(model["version"], "4.0");
        assert_eq!(major(&model), Some(4));
        assert_eq!(model["references"][0]["includes"][0]["alias"], "Core");
        assert_eq!(model["schemas"], json!([{"name": "Shop", "alias": "S"}]));
        let product = &model["types"][0];
        assert_eq!(product["name"], "Shop.Product");
        assert_eq!(product["key"], json!(["ID"]));
        assert_eq!(product["properties"][0]["nullable"], false);
        assert_eq!(product["properties"][1]["nullable"], true);
        assert_eq!(product["navigation"][0]["partner"], "Products");
        let category = &model["types"][1];
        assert_eq!(category["abstract"], true);
        assert_eq!(category["key"], Value::Null);
        assert_eq!(category["baseType"], "Shop.Base");
        assert_eq!(model["types"][2]["kind"], "ComplexType");
        assert_eq!(model["types"][3]["members"][0]["value"], "0");
        assert_eq!(model["types"][4]["underlyingType"], "Edm.Decimal");
        assert_eq!(model["types"].as_array().unwrap().len(), 5);
        let rate = &model["operations"][0];
        assert_eq!(rate["overloads"].as_array().unwrap().len(), 2);
        assert_eq!(rate["overloads"][0]["returnType"], Value::Null);
        assert_eq!(
            model["operations"][1]["overloads"][0]["returnType"],
            "Collection(Shop.Product)"
        );
        let container = &model["containers"][0];
        assert_eq!(container["name"], "Shop.Container");
        assert_eq!(
            container["entitySets"][0]["bindings"][0]["target"],
            "Categories"
        );
        assert_eq!(container["singletons"][0]["type"], "Shop.Product");
        assert_eq!(container["actionImports"][0]["action"], "Shop.Reset");
        assert_eq!(container["functionImports"][0]["entitySet"], "Products");
        assert_eq!(model["entityContainer"], Value::Null);
    }

    #[test]
    fn legacy_and_entity_framework_edmx_are_told_apart() {
        let legacy = |attributes: &str| {
            xml(&format!(
                r#"<edmx:Edmx Version="1.0" xmlns:edmx="{EDMX_LEGACY}" xmlns:m="{DATA_SERVICES_METADATA}"><edmx:DataServices {attributes}/></edmx:Edmx>"#
            ))
            .unwrap()
        };
        assert_eq!(major(&legacy(r#"m:DataServiceVersion="3.0""#)), Some(3));
        assert_eq!(major(&legacy(r#"m:DataServiceVersion="2.0""#)), Some(2));
        assert_eq!(major(&legacy("")), Some(2));
        let designer = EDMX_ENTITY_FRAMEWORK[1];
        assert_eq!(
            xml(&format!(
                r#"<edmx:Edmx xmlns:edmx="{designer}"><edmx:Runtime/></edmx:Edmx>"#
            )),
            None
        );
        let served = xml(&format!(
            r#"<edmx:Edmx xmlns:edmx="{designer}"><edmx:DataServices/></edmx:Edmx>"#
        ))
        .unwrap();
        assert_eq!(major(&served), Some(3));
        assert_eq!(xml("<Edmx/>"), None);
        assert_eq!(xml(r#"<Edmx xmlns="urn:x"/>"#), None);
        assert_eq!(xml("<Schema/>"), None);
    }

    #[test]
    fn csdl_json_becomes_the_same_model() {
        let document = json!({
            "$Version": "4.01",
            "$EntityContainer": "Shop.Container",
            "$Reference": {"common.json": {"$Include": [{"$Namespace": "Common", "$Alias": "C"}]}},
            "Shop": {
                "$Alias": "S",
                "Product": {
                    "$Kind": "EntityType",
                    "$Key": ["ID", {"City": "Address/City"}],
                    "ID": {"$Type": "Edm.Int32"},
                    "Name": {"$Nullable": true},
                    "Tags": {"$Collection": true},
                    "Category": {"$Kind": "NavigationProperty", "$Type": "Shop.Category", "$Partner": "Products"},
                    "Name@Core.Description": "ignored",
                    "Broken": 1,
                },
                "Color": {"$Kind": "EnumType", "Red": 0, "$UnderlyingType": "Edm.Int32"},
                "Money": {"$Kind": "TypeDefinition", "$UnderlyingType": "Edm.Decimal"},
                "Rate": [
                    {"$Kind": "Action", "$IsBound": true, "$Parameter": [{"$Name": "p", "$Type": "Shop.Product"}]},
                    {"$Kind": "Action", "$IsBound": true, "$Parameter": [{"$Name": "c", "$Collection": true}]},
                ],
                "Top": [{"$Kind": "Function", "$ReturnType": {"$Type": "Shop.Product", "$Collection": true}}],
                "Term": {"$Kind": "Term"},
                "Stray": 1,
                "Container": {
                    "$Kind": "EntityContainer",
                    "Products": {"$Collection": true, "$Type": "Shop.Product", "$NavigationPropertyBinding": {"Category": "Categories"}},
                    "Featured": {"$Type": "Shop.Product"},
                    "Reset": {"$Action": "Shop.Reset"},
                    "Top": {"$Function": "Shop.Top", "$EntitySet": "Products"},
                    "Odd": 1,
                },
            },
            "Stray": 1,
        });
        let model = from_json(&document).unwrap();
        assert_eq!(model["format"], "json");
        assert_eq!(model["version"], "4.01");
        assert_eq!(model["entityContainer"], "Shop.Container");
        assert_eq!(model["references"][0]["uri"], "common.json");
        assert_eq!(model["references"][0]["includes"][0]["namespace"], "Common");
        assert_eq!(model["schemas"], json!([{"name": "Shop", "alias": "S"}]));
        let product = &model["types"][2];
        assert_eq!(product["key"], json!(["ID", "Address/City"]));
        assert_eq!(
            product["properties"],
            json!([
                {"name": "ID", "type": "Edm.Int32", "nullable": false},
                {"name": "Name", "type": "Edm.String", "nullable": true},
                {"name": "Tags", "type": "Collection(Edm.String)", "nullable": false},
            ])
        );
        assert_eq!(product["navigation"][0]["type"], "Shop.Category");
        assert_eq!(
            model["types"][0]["members"],
            json!([{"name": "Red", "value": 0}])
        );
        assert_eq!(model["types"][1]["kind"], "TypeDefinition");
        let rate = &model["operations"][0];
        assert_eq!(
            rate["overloads"][1]["parameters"][0]["type"],
            "Collection(Edm.String)"
        );
        assert_eq!(
            model["operations"][1]["overloads"][0]["returnType"],
            "Collection(Shop.Product)"
        );
        let container = &model["containers"][0];
        assert_eq!(
            container["entitySets"][0]["bindings"][0]["path"],
            "Category"
        );
        assert_eq!(container["singletons"][0]["name"], "Featured");
        assert_eq!(container["actionImports"][0]["action"], "Shop.Reset");
        assert_eq!(container["functionImports"][0]["entitySet"], "Products");
        assert_eq!(from_json(&json!({"openapi": "3.1.0"})), None);
        assert_eq!(from_json(&json!([])), None);
        let bare =
            from_json(&json!({"$Version": "4.0", "N": {"A": [1], "B": {"$Key": [1]}}})).unwrap();
        assert!(bare["operations"].as_array().unwrap().is_empty());
    }
}
