//! A GraphQL type system parser (October 2021 specification, section 3)
//! producing a stable JSON tree, written here because the supply-chain
//! policy rules out adding a GraphQL library for one step.
//!
//! It reads schema, type (scalar, object, interface, union, enum, input
//! object) and directive definitions, their `extend` forms, descriptions,
//! directive applications and default values. A document that contains an
//! executable definition (an operation or fragment) is a client query
//! file, not a schema, and is reported as such rather than parsed.
//!
//! The tree keeps every definition in document order, so duplicates stay
//! visible to the validator:
//!
//! ```json
//! {"schema": [{"extension": false, "description": null, "directives": [],
//!              "operations": [{"operation": "query", "type": "Query"}]}],
//!  "types": [{"kind": "object", "name": "User", "extension": false,
//!             "description": null, "directives": ["@key(fields: \"id\")"],
//!             "interfaces": ["Node"], "members": [], "values": [],
//!             "fields": [{"name": "id", "description": null, "type": "ID!",
//!                         "arguments": [], "default": null, "directives": []}]}],
//!  "directives": [{"name": "auth", "description": null, "arguments": [],
//!                  "repeatable": false, "locations": ["FIELD_DEFINITION"]}]}
//! ```
//!
//! Directive applications and default values are kept as canonical text,
//! so two spellings of the same value compare equal.

use serde_json::{json, Value};

use super::lexer::{tokenize, Spanned, Token};

/// Nesting beyond this (list types, list and object values) is refused.
const MAX_DEPTH: usize = 64;

/// Why text is not a GraphQL schema this parser reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Not valid GraphQL, or valid only beyond this parser's bounds.
    Syntax { line: usize, message: String },
    /// An operation or fragment: a client document, not a schema.
    Executable { line: usize },
}

/// Parse a schema document into the tree described above.
pub fn parse(text: &str) -> Result<Value> {
    let tokens = tokenize(text).map_err(|error| ParseError::Syntax {
        line: error.line,
        message: error.message,
    })?;
    let mut parser = Parser {
        tokens: &tokens,
        position: 0,
        depth: 0,
    };
    let mut schema = Vec::new();
    let mut types = Vec::new();
    let mut directives = Vec::new();
    while parser.position < tokens.len() {
        parser.definition(&mut schema, &mut types, &mut directives)?;
    }
    Ok(json!({"schema": schema, "types": types, "directives": directives}))
}

struct Parser<'a> {
    tokens: &'a [Spanned],
    position: usize,
    depth: usize,
}

type Result<T> = std::result::Result<T, ParseError>;

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position).map(|spanned| &spanned.token)
    }

    fn line(&self) -> usize {
        self.tokens
            .get(self.position)
            .or(self.tokens.last())
            .map_or(1, |spanned| spanned.line)
    }

    fn error<T>(&self, message: impl Into<String>) -> Result<T> {
        Err(ParseError::Syntax {
            line: self.line(),
            message: message.into(),
        })
    }

    fn at_punct(&self, punct: char) -> bool {
        self.peek() == Some(&Token::Punct(punct))
    }

    fn at_name(&self, name: &str) -> bool {
        matches!(self.peek(), Some(Token::Name(found)) if found == name)
    }

    fn eat_punct(&mut self, punct: char) -> bool {
        let found = self.at_punct(punct);
        self.position += usize::from(found);
        found
    }

    fn expect_punct(&mut self, punct: char) -> Result<()> {
        if self.eat_punct(punct) {
            Ok(())
        } else {
            self.error(format!("expected `{punct}`"))
        }
    }

    fn name(&mut self) -> Result<String> {
        match self.peek() {
            Some(Token::Name(name)) => {
                let name = name.clone();
                self.position += 1;
                Ok(name)
            }
            _ => self.error("expected a name"),
        }
    }

    fn keyword(&mut self, keyword: &str) -> Result<()> {
        if self.at_name(keyword) {
            self.position += 1;
            Ok(())
        } else {
            self.error(format!("expected `{keyword}`"))
        }
    }

    fn description(&mut self) -> Value {
        match self.peek() {
            Some(Token::Str { value, .. }) => {
                let value = Value::String(value.clone());
                self.position += 1;
                value
            }
            _ => Value::Null,
        }
    }

    fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return self.error("nested deeper than the built-in parser reads");
        }
        Ok(())
    }

    fn definition(
        &mut self,
        schema: &mut Vec<Value>,
        types: &mut Vec<Value>,
        directives: &mut Vec<Value>,
    ) -> Result<()> {
        if self.at_punct('{') {
            return Err(ParseError::Executable { line: self.line() });
        }
        let description = self.description();
        let extension = self.at_name("extend");
        if extension {
            if !description.is_null() {
                return self.error("an extension cannot have a description");
            }
            self.position += 1;
        }
        let keyword = self.name()?;
        match keyword.as_str() {
            "query" | "mutation" | "subscription" | "fragment" if !extension => {
                self.position -= 1;
                Err(ParseError::Executable { line: self.line() })
            }
            "schema" => {
                let definition = self.schema(extension, description)?;
                schema.push(definition);
                Ok(())
            }
            "directive" if !extension => {
                let definition = self.directive_definition(description)?;
                directives.push(definition);
                Ok(())
            }
            "scalar" | "type" | "interface" | "union" | "enum" | "input" => {
                let definition = self.type_definition(&keyword, extension, description)?;
                types.push(definition);
                Ok(())
            }
            other => {
                self.position -= 1;
                self.error(format!("`{other}` does not start a type system definition"))
            }
        }
    }

    fn schema(&mut self, extension: bool, description: Value) -> Result<Value> {
        let directives = self.directives()?;
        let mut operations = Vec::new();
        if self.eat_punct('{') {
            while !self.eat_punct('}') {
                let operation = self.name()?;
                if !matches!(operation.as_str(), "query" | "mutation" | "subscription") {
                    self.position -= 1;
                    return self.error("expected query, mutation or subscription");
                }
                self.expect_punct(':')?;
                let named = self.name()?;
                operations.push(json!({"operation": operation, "type": named}));
            }
            if operations.is_empty() {
                return self.error("a schema definition lists at least one root operation");
            }
        } else if !extension {
            return self.error("expected `{`");
        }
        Ok(json!({
            "extension": extension,
            "description": description,
            "directives": directives,
            "operations": operations,
        }))
    }

    fn directive_definition(&mut self, description: Value) -> Result<Value> {
        self.expect_punct('@')?;
        let name = self.name()?;
        let arguments = self.arguments_definition()?;
        let repeatable = self.at_name("repeatable");
        self.position += usize::from(repeatable);
        self.keyword("on")?;
        self.eat_punct('|');
        let mut locations = vec![self.name()?];
        while self.eat_punct('|') {
            locations.push(self.name()?);
        }
        Ok(json!({
            "name": name,
            "description": description,
            "arguments": arguments,
            "repeatable": repeatable,
            "locations": locations,
        }))
    }

    fn type_definition(
        &mut self,
        keyword: &str,
        extension: bool,
        description: Value,
    ) -> Result<Value> {
        let name = self.name()?;
        let kind = match keyword {
            "type" => "object",
            other => other,
        };
        let mut interfaces = Vec::new();
        if matches!(kind, "object" | "interface") && self.at_name("implements") {
            self.position += 1;
            self.eat_punct('&');
            interfaces.push(self.name()?);
            while self.eat_punct('&') {
                interfaces.push(self.name()?);
            }
        }
        let directives = self.directives()?;
        let mut fields = Vec::new();
        let mut values = Vec::new();
        let mut members = Vec::new();
        match kind {
            "object" | "interface" if self.eat_punct('{') => {
                while !self.eat_punct('}') {
                    fields.push(self.field()?);
                }
            }
            "input" if self.eat_punct('{') => {
                while !self.eat_punct('}') {
                    fields.push(self.input_value()?);
                }
            }
            "enum" if self.eat_punct('{') => {
                while !self.eat_punct('}') {
                    let description = self.description();
                    let name = self.name()?;
                    let directives = self.directives()?;
                    values.push(json!({
                        "name": name, "description": description, "directives": directives,
                    }));
                }
            }
            "union" if self.eat_punct('=') => {
                self.eat_punct('|');
                members.push(self.name()?);
                while self.eat_punct('|') {
                    members.push(self.name()?);
                }
            }
            _ => {}
        }
        Ok(json!({
            "kind": kind,
            "name": name,
            "extension": extension,
            "description": description,
            "directives": directives,
            "interfaces": interfaces,
            "fields": fields,
            "values": values,
            "members": members,
        }))
    }

    fn field(&mut self) -> Result<Value> {
        let description = self.description();
        let name = self.name()?;
        let arguments = self.arguments_definition()?;
        self.expect_punct(':')?;
        let kind = self.type_reference()?;
        let directives = self.directives()?;
        Ok(json!({
            "name": name,
            "description": description,
            "type": kind,
            "arguments": arguments,
            "default": null,
            "directives": directives,
        }))
    }

    fn arguments_definition(&mut self) -> Result<Vec<Value>> {
        let mut arguments = Vec::new();
        if self.eat_punct('(') {
            while !self.eat_punct(')') {
                arguments.push(self.input_value()?);
            }
        }
        Ok(arguments)
    }

    fn input_value(&mut self) -> Result<Value> {
        let description = self.description();
        let name = self.name()?;
        self.expect_punct(':')?;
        let kind = self.type_reference()?;
        let default = if self.eat_punct('=') {
            Value::String(self.value()?)
        } else {
            Value::Null
        };
        let directives = self.directives()?;
        Ok(json!({
            "name": name,
            "description": description,
            "type": kind,
            "arguments": [],
            "default": default,
            "directives": directives,
        }))
    }

    fn type_reference(&mut self) -> Result<String> {
        self.enter()?;
        let mut kind = if self.eat_punct('[') {
            let inner = self.type_reference()?;
            self.expect_punct(']')?;
            format!("[{inner}]")
        } else {
            self.name()?
        };
        if self.eat_punct('!') {
            kind.push('!');
        }
        self.depth -= 1;
        Ok(kind)
    }

    fn directives(&mut self) -> Result<Vec<Value>> {
        let mut applied = Vec::new();
        while self.eat_punct('@') {
            let mut text = format!("@{}", self.name()?);
            if self.eat_punct('(') {
                let mut arguments = Vec::new();
                while !self.eat_punct(')') {
                    let name = self.name()?;
                    self.expect_punct(':')?;
                    arguments.push(format!("{name}: {}", self.value()?));
                }
                text.push_str(&format!("({})", arguments.join(", ")));
            }
            applied.push(Value::String(text));
        }
        Ok(applied)
    }

    /// A constant value, as canonical text.
    fn value(&mut self) -> Result<String> {
        self.enter()?;
        let text = match self.peek().cloned() {
            Some(Token::Int(text) | Token::Float(text) | Token::Name(text)) => {
                self.position += 1;
                text
            }
            Some(Token::Str { value, .. }) => {
                self.position += 1;
                Value::String(value).to_string()
            }
            Some(Token::Punct('[')) => {
                self.position += 1;
                let mut items = Vec::new();
                while !self.eat_punct(']') {
                    items.push(self.value()?);
                }
                format!("[{}]", items.join(", "))
            }
            Some(Token::Punct('{')) => {
                self.position += 1;
                let mut fields = Vec::new();
                while !self.eat_punct('}') {
                    let name = self.name()?;
                    self.expect_punct(':')?;
                    fields.push(format!("{name}: {}", self.value()?));
                }
                format!("{{{}}}", fields.join(", "))
            }
            Some(Token::Punct('$')) => return self.error("a variable is not a constant value"),
            _ => return self.error("expected a value"),
        };
        self.depth -= 1;
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syntax(text: &str) -> String {
        let error = parse(text).unwrap_err();
        // One line, so a mismatch adds no line that goes unexecuted.
        #[rustfmt::skip]
        let ParseError::Syntax { message, .. } = error else { unreachable!("{error:?}") };
        message
    }

    #[test]
    fn every_type_system_definition_is_read() {
        let text = r#"
"""The schema."""
schema @link(url: "https://specs.example.invalid/v1") { query: Query mutation: Mutation }
extend schema { subscription: Subscription }
extend schema @tag
"A node" interface Node { id: ID! }
type User implements & Node & Named @key(fields: "id") {
  "Identifier" id: ID!
  posts(first: Int = 10, filter: PostFilter = {tags: ["a", "b"], flag: true, level: HIGH, n: null}): [Post!]! @deprecated(reason: "use feed")
}
extend type User { email: String }
interface Named implements Node { name: String }
union Result = | User | Post
extend union Result = Comment
enum Level { "low" LOW @deprecated HIGH }
extend enum Level { MID }
input PostFilter { tags: [String!] = [] flag: Boolean level: Level = HIGH }
extend input PostFilter @oneOf
scalar DateTime @specifiedBy(url: "https://example.invalid/datetime")
extend scalar DateTime @tag
directive @key(fields: String!) repeatable on | OBJECT | INTERFACE
"Auth" directive @auth on FIELD_DEFINITION
type Empty
"#;
        let tree = parse(text).unwrap();
        assert_eq!(tree["schema"].as_array().unwrap().len(), 3);
        assert_eq!(tree["schema"][0]["description"], "The schema.");
        assert_eq!(
            tree["schema"][0]["directives"][0],
            "@link(url: \"https://specs.example.invalid/v1\")"
        );
        assert_eq!(
            tree["schema"][1]["operations"][0],
            json!({"operation": "subscription", "type": "Subscription"})
        );
        assert_eq!(tree["schema"][2]["operations"], json!([]));
        let types = tree["types"].as_array().unwrap();
        let user = &types[1];
        assert_eq!(user["kind"], "object");
        assert_eq!(user["interfaces"], json!(["Node", "Named"]));
        assert_eq!(user["fields"][0]["description"], "Identifier");
        assert_eq!(user["fields"][1]["type"], "[Post!]!");
        assert_eq!(user["fields"][1]["arguments"][0]["default"], "10");
        assert_eq!(
            user["fields"][1]["arguments"][1]["default"],
            "{tags: [\"a\", \"b\"], flag: true, level: HIGH, n: null}"
        );
        assert_eq!(
            user["fields"][1]["directives"],
            json!(["@deprecated(reason: \"use feed\")"])
        );
        assert_eq!(types[2]["extension"], true);
        assert_eq!(types[3]["interfaces"], json!(["Node"]));
        assert_eq!(types[4]["members"], json!(["User", "Post"]));
        assert_eq!(types[5]["members"], json!(["Comment"]));
        assert_eq!(types[6]["values"][0]["description"], "low");
        assert_eq!(types[6]["values"][0]["directives"], json!(["@deprecated"]));
        assert_eq!(types[8]["fields"][0]["default"], "[]");
        assert_eq!(types[9]["directives"], json!(["@oneOf"]));
        assert_eq!(types[10]["kind"], "scalar");
        let directives = tree["directives"].as_array().unwrap();
        assert_eq!(directives[0]["repeatable"], true);
        assert_eq!(directives[0]["locations"], json!(["OBJECT", "INTERFACE"]));
        assert_eq!(directives[1]["description"], "Auth");
        assert_eq!(types.last().unwrap()["fields"], json!([]));
        assert_eq!(parse("").unwrap()["types"], json!([]));
    }

    #[test]
    fn executable_documents_are_not_schemas() {
        for text in [
            "{ me { id } }",
            "query Me { me { id } }",
            "type A { a: Int }\nmutation { x }",
            "subscription S { s }",
            "fragment F on User { id }",
        ] {
            assert!(
                matches!(parse(text), Err(ParseError::Executable { .. })),
                "{text}"
            );
        }
        assert_eq!(
            parse("type A { a: Int }\n\nquery Q { a }"),
            Err(ParseError::Executable { line: 3 })
        );
    }

    #[test]
    fn syntax_errors_name_what_was_expected() {
        assert_eq!(syntax("type { a: Int }"), "expected a name");
        assert_eq!(syntax("type A { a Int }"), "expected `:`");
        assert_eq!(
            syntax("\"d\" extend type A"),
            "an extension cannot have a description"
        );
        assert_eq!(
            syntax("object A"),
            "`object` does not start a type system definition"
        );
        assert_eq!(
            syntax("extend directive @a on FIELD"),
            "`directive` does not start a type system definition"
        );
        assert_eq!(syntax("schema { query Query }"), "expected `:`");
        assert_eq!(
            syntax("schema { root: Query }"),
            "expected query, mutation or subscription"
        );
        assert_eq!(
            syntax("schema { }"),
            "a schema definition lists at least one root operation"
        );
        assert_eq!(syntax("schema @a"), "expected `{`");
        assert_eq!(syntax("directive @a FIELD"), "expected `on`");
        assert_eq!(syntax("directive a on FIELD"), "expected `@`");
        assert_eq!(syntax("type A { a: [Int }"), "expected `]`");
        assert_eq!(
            syntax("input A { a: Int = $x }"),
            "a variable is not a constant value"
        );
        assert_eq!(syntax("input A { a: Int = }"), "expected a value");
        assert_eq!(syntax("type A @d(x 1) { a: Int }"), "expected `:`");
        assert_eq!(syntax("input A { a: Int = {b 1} }"), "expected `:`");
        assert_eq!(syntax("type A { a: Int"), "expected a name");
        assert_eq!(syntax("%"), "unexpected character '%'");
        let deep = format!("type A {{ a: {}Int{} }}", "[".repeat(70), "]".repeat(70));
        assert_eq!(
            syntax(&deep),
            "nested deeper than the built-in parser reads"
        );
        let deep = format!(
            "input A {{ a: Int = {}1{} }}",
            "[".repeat(70),
            "]".repeat(70)
        );
        assert_eq!(
            syntax(&deep),
            "nested deeper than the built-in parser reads"
        );
        assert_eq!(syntax("a"), "`a` does not start a type system definition");
        assert!(matches!(
            parse("type A { a: Int"),
            Err(ParseError::Syntax { line: 1, .. })
        ));
    }
}
