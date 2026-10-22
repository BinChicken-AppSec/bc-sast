//! A Protocol Buffers parser (proto2, proto3 and editions syntax) for
//! validation only, producing a stable JSON tree. It is written here
//! because the supply-chain policy rules out a protobuf library for one
//! check, and because this step never generates or rewrites a `.proto`
//! file: the definition is normally the source of truth, and code is
//! generated from it.
//!
//! It reads `syntax`, `edition`, `package`, `import` and `option`
//! statements; messages with fields, `map<K, V>` fields, `oneof`s,
//! proto2 groups, nested messages and enums, `reserved` numbers, ranges
//! and names, `extensions` ranges and `extend` blocks; enums with values;
//! and services with (streaming) RPCs. Option values, including
//! aggregate `{ ... }` values, are skipped rather than interpreted.
//!
//! ```json
//! {"syntax": "proto3", "edition": null, "package": "shop.v1",
//!  "imports": [{"path": "google/protobuf/timestamp.proto", "modifier": null}],
//!  "messages": [{"name": "Order", "fields": [{"name": "id", "number": 1,
//!    "label": null, "type": "string", "key": null, "value": null,
//!    "oneof": null, "group": false}], "reserved_numbers": [[5, 5]],
//!    "reserved_names": ["legacy"], "extensions": [], "messages": [],
//!    "enums": [], "extends": []}],
//!  "enums": [{"name": "State", "values": [{"name": "STATE_UNSPECIFIED",
//!    "number": 0}], "allow_alias": false, "reserved_numbers": [],
//!    "reserved_names": []}],
//!  "services": [{"name": "Orders", "rpcs": [{"name": "Get", "input": "GetRequest",
//!    "output": "Order", "client_streaming": false, "server_streaming": true}]}],
//!  "extends": []}
//! ```

use serde_json::{json, Value};

/// Largest field number protobuf allows (2^29 - 1).
pub const MAX_FIELD_NUMBER: i64 = 536_870_911;
/// Nesting beyond this (messages, option aggregates) is refused.
const MAX_DEPTH: usize = 64;

/// Why text is not a `.proto` file this parser reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Ident(String),
    Int(i64),
    Float,
    Str(String),
    Punct(char),
}

fn tokenize(text: &str) -> Result<Vec<(Token, usize)>> {
    let chars: Vec<char> = text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .chars()
        .collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut line = 1;
    let error = |line: usize, message: &str| ParseError {
        line,
        message: message.into(),
    };
    while index < chars.len() {
        let character = chars[index];
        let next = chars.get(index + 1).copied();
        match character {
            '\n' => {
                line += 1;
                index += 1;
            }
            c if c.is_whitespace() => index += 1,
            '/' if next == Some('/') => {
                while index < chars.len() && chars[index] != '\n' {
                    index += 1;
                }
            }
            '/' if next == Some('*') => {
                index += 2;
                loop {
                    match chars.get(index) {
                        None => return Err(error(line, "unterminated block comment")),
                        Some('*') if chars.get(index + 1) == Some(&'/') => {
                            index += 2;
                            break;
                        }
                        Some(c) => {
                            line += usize::from(*c == '\n');
                            index += 1;
                        }
                    }
                }
            }
            '"' | '\'' => {
                let quote = character;
                let mut value = String::new();
                index += 1;
                loop {
                    match chars.get(index) {
                        None | Some('\n') => return Err(error(line, "unterminated string")),
                        Some(c) if *c == quote => {
                            index += 1;
                            break;
                        }
                        Some('\\') => {
                            // Escapes are kept as written; only import
                            // paths are read, and they need none.
                            value.push('\\');
                            value.extend(chars.get(index + 1));
                            index += 2;
                        }
                        Some(c) => {
                            value.push(*c);
                            index += 1;
                        }
                    }
                }
                tokens.push((Token::Str(value), line));
            }
            c if c.is_ascii_digit() || (c == '.' && next.is_some_and(|n| n.is_ascii_digit())) => {
                let start = index;
                while chars
                    .get(index)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_')
                    || (matches!(chars.get(index), Some('+' | '-'))
                        && matches!(chars.get(index - 1), Some('e' | 'E'))
                        && !chars[start..index].iter().any(|c| matches!(c, 'x' | 'X')))
                {
                    index += 1;
                }
                let text: String = chars[start..index].iter().collect();
                let parsed = if let Some(hex) = text.strip_prefix("0x").or(text.strip_prefix("0X"))
                {
                    i64::from_str_radix(hex, 16).ok()
                } else if text.len() > 1
                    && text.starts_with('0')
                    && text.chars().all(|c| c.is_ascii_digit())
                {
                    i64::from_str_radix(&text[1..], 8).ok()
                } else {
                    text.parse::<i64>().ok()
                };
                let token = match parsed {
                    Some(number) => Token::Int(number),
                    None if text.parse::<f64>().is_ok() => Token::Float,
                    None => return Err(error(line, &format!("invalid number `{text}`"))),
                };
                tokens.push((token, line));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = index;
                while chars
                    .get(index)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
                {
                    index += 1;
                }
                tokens.push((Token::Ident(chars[start..index].iter().collect()), line));
            }
            ';' | ',' | '=' | '{' | '}' | '[' | ']' | '(' | ')' | '<' | '>' | '.' | '-' | '+'
            | ':' | '/' => {
                tokens.push((Token::Punct(character), line));
                index += 1;
            }
            other => return Err(error(line, &format!("unexpected character {other:?}"))),
        }
    }
    Ok(tokens)
}

/// Parse a `.proto` file into the tree described above.
pub fn parse(text: &str) -> Result<Value> {
    let tokens = tokenize(text)?;
    let mut parser = Parser {
        tokens: &tokens,
        position: 0,
        depth: 0,
    };
    parser.file()
}

struct Parser<'a> {
    tokens: &'a [(Token, usize)],
    position: usize,
    depth: usize,
}

type Result<T> = std::result::Result<T, ParseError>;

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position).map(|(token, _)| token)
    }

    fn error<T>(&self, message: impl Into<String>) -> Result<T> {
        let line = self
            .tokens
            .get(self.position)
            .or(self.tokens.last())
            .map_or(1, |(_, line)| *line);
        Err(ParseError {
            line,
            message: message.into(),
        })
    }

    fn at(&self, punct: char) -> bool {
        self.peek() == Some(&Token::Punct(punct))
    }

    fn at_word(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Token::Ident(found)) if found == word)
    }

    fn eat(&mut self, punct: char) -> bool {
        let found = self.at(punct);
        self.position += usize::from(found);
        found
    }

    fn eat_word(&mut self, word: &str) -> bool {
        let found = self.at_word(word);
        self.position += usize::from(found);
        found
    }

    fn expect(&mut self, punct: char) -> Result<()> {
        if self.eat(punct) {
            Ok(())
        } else {
            self.error(format!("expected `{punct}`"))
        }
    }

    fn ident(&mut self) -> Result<String> {
        match self.peek() {
            Some(Token::Ident(name)) => {
                let name = name.clone();
                self.position += 1;
                Ok(name)
            }
            _ => self.error("expected a name"),
        }
    }

    /// A dotted name, optionally fully qualified with a leading `.`.
    fn full_ident(&mut self) -> Result<String> {
        let mut name = if self.eat('.') {
            ".".to_string()
        } else {
            String::new()
        };
        name.push_str(&self.ident()?);
        while self.eat('.') {
            name.push('.');
            name.push_str(&self.ident()?);
        }
        Ok(name)
    }

    fn string(&mut self) -> Result<String> {
        let mut value = match self.peek() {
            Some(Token::Str(value)) => value.clone(),
            _ => return self.error("expected a string"),
        };
        self.position += 1;
        // Adjacent string literals concatenate.
        while let Some(Token::Str(more)) = self.peek() {
            value.push_str(more);
            self.position += 1;
        }
        Ok(value)
    }

    fn integer(&mut self) -> Result<i64> {
        let negative = self.eat('-');
        match self.peek() {
            Some(Token::Int(number)) => {
                let number = *number;
                self.position += 1;
                Ok(if negative { -number } else { number })
            }
            _ => self.error("expected an integer"),
        }
    }

    fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return self.error("nested deeper than the built-in parser reads");
        }
        Ok(())
    }

    /// Skip an option value: a scalar, or a balanced aggregate.
    fn skip_value(&mut self) -> Result<()> {
        if !self.eat('{') {
            self.eat('-');
            return match self.peek() {
                Some(Token::Str(_)) => self.string().map(drop),
                Some(Token::Ident(_)) => self.full_ident().map(drop),
                Some(Token::Int(_) | Token::Float) => {
                    self.position += 1;
                    Ok(())
                }
                _ => self.error("expected an option value"),
            };
        }
        let mut depth = 1;
        while depth > 0 {
            match self.peek() {
                None => return self.error("unterminated option value"),
                Some(Token::Punct('{')) => depth += 1,
                Some(Token::Punct('}')) => depth -= 1,
                Some(_) => {}
            }
            self.position += 1;
        }
        Ok(())
    }

    /// `option name = value;` after `option` was read, returning the
    /// name and, for a boolean, its value.
    fn option(&mut self) -> Result<(String, Option<bool>)> {
        let mut name = String::new();
        loop {
            if self.eat('(') {
                name.push('(');
                name.push_str(&self.full_ident()?);
                self.expect(')')?;
                name.push(')');
            } else {
                name.push_str(&self.ident()?);
            }
            if !self.eat('.') {
                break;
            }
            name.push('.');
        }
        self.expect('=')?;
        let flag = match self.peek() {
            Some(Token::Ident(word)) if word == "true" => Some(true),
            Some(Token::Ident(word)) if word == "false" => Some(false),
            _ => None,
        };
        self.skip_value()?;
        Ok((name, flag))
    }

    /// `[a = 1, (b).c = "x"]` field options.
    fn field_options(&mut self) -> Result<()> {
        if self.eat('[') {
            loop {
                self.option()?;
                if !self.eat(',') {
                    break;
                }
            }
            self.expect(']')?;
        }
        Ok(())
    }

    fn file(&mut self) -> Result<Value> {
        let mut syntax = Value::Null;
        let mut edition = Value::Null;
        let mut package = Value::Null;
        let mut imports = Vec::new();
        let mut body = Body::default();
        while self.position < self.tokens.len() {
            if self.eat(';') {
                continue;
            }
            if self.eat_word("syntax") {
                self.expect('=')?;
                syntax = Value::String(self.string()?);
                self.expect(';')?;
            } else if self.eat_word("edition") {
                self.expect('=')?;
                edition = Value::String(self.string()?);
                syntax = Value::String("editions".into());
                self.expect(';')?;
            } else if self.eat_word("package") {
                package = Value::String(self.full_ident()?);
                self.expect(';')?;
            } else if self.eat_word("import") {
                let modifier = if self.at_word("public") || self.at_word("weak") {
                    Value::String(self.ident()?)
                } else {
                    Value::Null
                };
                let path = self.string()?;
                self.expect(';')?;
                imports.push(json!({"path": path, "modifier": modifier}));
            } else if self.eat_word("option") {
                self.option()?;
                self.expect(';')?;
            } else if self.eat_word("service") {
                body.services.push(self.service()?);
            } else {
                self.definition(&mut body)?;
            }
        }
        Ok(json!({
            "syntax": syntax,
            "edition": edition,
            "package": package,
            "imports": imports,
            "messages": body.messages,
            "enums": body.enums,
            "services": body.services,
            "extends": body.extends,
        }))
    }

    /// A message, enum or extend at file or message level.
    fn definition(&mut self, body: &mut Body) -> Result<()> {
        if self.eat_word("message") {
            body.messages.push(self.message()?);
        } else if self.eat_word("enum") {
            body.enums.push(self.enumeration()?);
        } else if self.eat_word("extend") {
            let extendee = self.full_ident()?;
            let message = self.message_body("")?;
            body.extends
                .push(json!({"extendee": extendee, "fields": message["fields"]}));
        } else {
            return self.error("expected a message, enum, service or extend definition");
        }
        Ok(())
    }

    fn message(&mut self) -> Result<Value> {
        let name = self.ident()?;
        self.message_body(&name)
    }

    fn message_body(&mut self, name: &str) -> Result<Value> {
        self.enter()?;
        self.expect('{')?;
        let mut fields = Vec::new();
        let mut reserved_numbers = Vec::new();
        let mut reserved_names = Vec::new();
        let mut extensions = Vec::new();
        let mut nested = Body::default();
        while !self.eat('}') {
            if self.position >= self.tokens.len() {
                return self.error("expected `}`");
            }
            if self.eat(';') {
                continue;
            }
            if self.eat_word("option") {
                self.option()?;
                self.expect(';')?;
            } else if self.eat_word("reserved") {
                self.reserved(&mut reserved_numbers, &mut reserved_names)?;
            } else if self.eat_word("extensions") {
                self.ranges(&mut extensions)?;
                self.field_options()?;
                self.expect(';')?;
            } else if self.eat_word("oneof") {
                let oneof = self.ident()?;
                self.expect('{')?;
                while !self.eat('}') {
                    if self.eat(';') {
                        continue;
                    }
                    if self.eat_word("option") {
                        self.option()?;
                        self.expect(';')?;
                        continue;
                    }
                    fields.push(self.field(Some(&oneof), &mut nested)?);
                }
            } else if self.at_word("message") || self.at_word("enum") || self.at_word("extend") {
                self.definition(&mut nested)?;
            } else {
                fields.push(self.field(None, &mut nested)?);
            }
        }
        self.depth -= 1;
        Ok(json!({
            "name": name,
            "fields": fields,
            "reserved_numbers": reserved_numbers,
            "reserved_names": reserved_names,
            "extensions": extensions,
            "messages": nested.messages,
            "enums": nested.enums,
            "extends": nested.extends,
        }))
    }

    /// `1, 2 to 5, 9 to max` into `[low, high]` pairs.
    fn ranges(&mut self, out: &mut Vec<Value>) -> Result<()> {
        loop {
            let low = self.integer()?;
            let high = if self.eat_word("to") {
                if self.eat_word("max") {
                    MAX_FIELD_NUMBER
                } else {
                    self.integer()?
                }
            } else {
                low
            };
            out.push(json!([low, high]));
            if !self.eat(',') {
                return Ok(());
            }
        }
    }

    fn reserved(&mut self, numbers: &mut Vec<Value>, names: &mut Vec<Value>) -> Result<()> {
        match self.peek() {
            Some(Token::Str(_)) => loop {
                names.push(Value::String(self.string()?));
                if !self.eat(',') {
                    break;
                }
            },
            // Editions spell reserved names as identifiers.
            Some(Token::Ident(_)) => loop {
                names.push(Value::String(self.ident()?));
                if !self.eat(',') {
                    break;
                }
            },
            _ => self.ranges(numbers)?,
        }
        self.expect(';')
    }

    fn field(&mut self, oneof: Option<&str>, nested: &mut Body) -> Result<Value> {
        let label = ["optional", "required", "repeated"]
            .into_iter()
            .find(|label| self.at_word(label));
        self.position += usize::from(label.is_some());
        let (kind, key, value) = if self.eat_word("map") {
            self.expect('<')?;
            let key = self.full_ident()?;
            self.expect(',')?;
            let value = self.full_ident()?;
            self.expect('>')?;
            (
                format!("map<{key}, {value}>"),
                Value::String(key),
                Value::String(value),
            )
        } else {
            (self.full_ident()?, Value::Null, Value::Null)
        };
        let group = kind == "group";
        let name = self.ident()?;
        self.expect('=')?;
        let number = self.integer()?;
        self.field_options()?;
        let kind = if group {
            // A proto2 group declares a nested message of the same name.
            let mut message = self.message_body(&name)?;
            message["name"] = Value::String(name.clone());
            nested.messages.push(message);
            name.clone()
        } else {
            self.expect(';')?;
            kind
        };
        Ok(json!({
            "name": name,
            "number": number,
            "label": label,
            "type": kind,
            "key": key,
            "value": value,
            "oneof": oneof,
            "group": group,
        }))
    }

    fn enumeration(&mut self) -> Result<Value> {
        let name = self.ident()?;
        self.expect('{')?;
        let mut values = Vec::new();
        let mut allow_alias = false;
        let mut reserved_numbers = Vec::new();
        let mut reserved_names = Vec::new();
        while !self.eat('}') {
            if self.position >= self.tokens.len() {
                return self.error("expected `}`");
            }
            if self.eat(';') {
                continue;
            }
            if self.eat_word("option") {
                let (option, flag) = self.option()?;
                allow_alias |= option == "allow_alias" && flag == Some(true);
                self.expect(';')?;
            } else if self.eat_word("reserved") {
                self.reserved(&mut reserved_numbers, &mut reserved_names)?;
            } else {
                let value = self.ident()?;
                self.expect('=')?;
                let number = self.integer()?;
                self.field_options()?;
                self.expect(';')?;
                values.push(json!({"name": value, "number": number}));
            }
        }
        Ok(json!({
            "name": name,
            "values": values,
            "allow_alias": allow_alias,
            "reserved_numbers": reserved_numbers,
            "reserved_names": reserved_names,
        }))
    }

    fn service(&mut self) -> Result<Value> {
        let name = self.ident()?;
        self.expect('{')?;
        let mut rpcs = Vec::new();
        while !self.eat('}') {
            if self.position >= self.tokens.len() {
                return self.error("expected `}`");
            }
            if self.eat(';') {
                continue;
            }
            if self.eat_word("option") {
                self.option()?;
                self.expect(';')?;
                continue;
            }
            if !self.eat_word("rpc") {
                return self.error("expected `rpc` or `option`");
            }
            let rpc = self.ident()?;
            let mut stream = [false; 2];
            let mut types = [String::new(), String::new()];
            for (index, keyword) in [None, Some("returns")].into_iter().enumerate() {
                if let Some(keyword) = keyword {
                    if !self.eat_word(keyword) {
                        return self.error("expected `returns`");
                    }
                }
                self.expect('(')?;
                // `stream` is a keyword only when a type name follows it.
                stream[index] = self.at_word("stream")
                    && matches!(
                        self.tokens.get(self.position + 1),
                        Some((Token::Ident(_), _)) | Some((Token::Punct('.'), _))
                    );
                self.position += usize::from(stream[index]);
                types[index] = self.full_ident()?;
                self.expect(')')?;
            }
            if self.eat('{') {
                while !self.eat('}') {
                    if self.eat(';') {
                        continue;
                    }
                    if !self.eat_word("option") {
                        return self.error("expected `option`");
                    }
                    self.option()?;
                    self.expect(';')?;
                }
            } else {
                self.expect(';')?;
            }
            let [input, output] = types;
            rpcs.push(json!({
                "name": rpc,
                "input": input,
                "output": output,
                "client_streaming": stream[0],
                "server_streaming": stream[1],
            }));
        }
        Ok(json!({"name": name, "rpcs": rpcs}))
    }
}

#[derive(Default)]
struct Body {
    messages: Vec<Value>,
    enums: Vec<Value>,
    services: Vec<Value>,
    extends: Vec<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(text: &str) -> String {
        parse(text).unwrap_err().message
    }

    #[test]
    fn a_full_proto3_file_is_read() {
        let text = r#"
// Orders.
syntax = "proto3";
package shop.v1;
import "google/protobuf/timestamp.proto";
import public "shop/v1/common.proto";
option java_package = "com.example.shop";
option (custom.opt).nested = { a: 1 b: { c: "x" } };
option optimize_for = SPEED;
option (level) = -3;
;

/* A block
   comment. */
message Order {
  option deprecated = true;
  string id = 1;
  repeated Item items = 2 [packed = true, (validate.rules).repeated.min_items = 1];
  map<string, .shop.v1.Item> by_sku = 3;
  oneof payment {
    option (x) = 1.5;
    string card = 4;
    string wallet = 5;
    ;
  }
  reserved 6, 8 to 10, 100 to max;
  reserved "legacy", 'old';
  google.protobuf.Timestamp created = 11;
  message Item { string sku = 1; }
  enum Kind { KIND_UNSPECIFIED = 0; }
  extend Other { int32 extra = 100; }
  ;
}

enum State {
  option allow_alias = true;
  STATE_UNSPECIFIED = 0;
  ;
  STARTED = 1 [deprecated = true];
  RUNNING = 1;
  reserved 5;
  reserved "GONE";
}

service Orders {
  option (svc) = "x";
  rpc Get (GetRequest) returns (Order);
  rpc Watch (stream WatchRequest) returns (stream .shop.v1.Order) {
    ;
    option (http) = { get: "/v1/orders" };
  }
  rpc Stream (stream) returns (stream);
  ;
}
extend Base { string note = 50; }
"#;
        let tree = parse(text).unwrap();
        assert_eq!(tree["syntax"], "proto3");
        assert_eq!(tree["package"], "shop.v1");
        assert_eq!(
            tree["imports"][1],
            json!({"path": "shop/v1/common.proto", "modifier": "public"})
        );
        let order = &tree["messages"][0];
        assert_eq!(order["fields"][1]["label"], "repeated");
        assert_eq!(order["fields"][2]["type"], "map<string, .shop.v1.Item>");
        assert_eq!(order["fields"][2]["value"], ".shop.v1.Item");
        assert_eq!(order["fields"][3]["oneof"], "payment");
        assert_eq!(
            order["reserved_numbers"],
            json!([[6, 6], [8, 10], [100, MAX_FIELD_NUMBER]])
        );
        assert_eq!(order["reserved_names"], json!(["legacy", "old"]));
        assert_eq!(order["fields"][5]["type"], "google.protobuf.Timestamp");
        assert_eq!(order["messages"][0]["name"], "Item");
        assert_eq!(order["enums"][0]["name"], "Kind");
        assert_eq!(order["extends"][0]["extendee"], "Other");
        let state = &tree["enums"][0];
        assert_eq!(state["allow_alias"], true);
        assert_eq!(state["values"][2], json!({"name": "RUNNING", "number": 1}));
        assert_eq!(state["reserved_names"], json!(["GONE"]));
        let rpcs = &tree["services"][0]["rpcs"];
        assert_eq!(rpcs[0]["server_streaming"], false);
        assert_eq!(rpcs[1]["client_streaming"], true);
        assert_eq!(rpcs[1]["output"], ".shop.v1.Order");
        // A message named `stream` is not a streaming marker.
        assert_eq!(rpcs[2]["input"], "stream");
        assert_eq!(rpcs[2]["client_streaming"], false);
        assert_eq!(tree["extends"][0]["fields"][0]["name"], "note");
    }

    #[test]
    fn proto2_groups_extensions_and_editions_are_read() {
        let text = "syntax = 'proto2';\nmessage A {\n  optional int32 a = 0x1;\n  required int64 b = 017;\n  repeated group Result = 3 { optional string url = 1; }\n  extensions 100 to 199 [verification = UNVERIFIED];\n  optional double d = 4 [default = -1.5e+3];\n  optional float f = 5 [default = inf];\n}\n";
        let tree = parse(text).unwrap();
        let message = &tree["messages"][0];
        assert_eq!(message["fields"][0]["number"], 1);
        assert_eq!(message["fields"][1]["number"], 15);
        assert_eq!(message["fields"][2]["group"], true);
        assert_eq!(message["fields"][2]["type"], "Result");
        assert_eq!(message["messages"][0]["name"], "Result");
        assert_eq!(message["extensions"], json!([[100, 199]]));
        let editions =
            parse("edition = \"2023\";\nmessage B { reserved foo, bar; int32 x = 1; }").unwrap();
        assert_eq!(editions["syntax"], "editions");
        assert_eq!(editions["edition"], "2023");
        assert_eq!(
            editions["messages"][0]["reserved_names"],
            json!(["foo", "bar"])
        );
        assert_eq!(parse("").unwrap()["syntax"], Value::Null);
        let concatenated = parse("import \"a/\" \"b.proto\";").unwrap();
        assert_eq!(concatenated["imports"][0]["path"], "a/b.proto");
        let escaped = parse("option x = \"a\\\"b\";").unwrap();
        assert_eq!(escaped["imports"], json!([]));
        assert_eq!(parse("option x = .5;").unwrap()["imports"], json!([]));
    }

    #[test]
    fn malformed_files_are_errors_with_lines() {
        assert_eq!(error("/* open"), "unterminated block comment");
        assert_eq!(error("syntax = \"proto3;"), "unterminated string");
        assert_eq!(error("option x = 1x;"), "invalid number `1x`");
        assert_eq!(error("#"), "unexpected character '#'");
        assert_eq!(error("syntax \"proto3\";"), "expected `=`");
        assert_eq!(error("syntax = proto3;"), "expected a string");
        assert_eq!(error("package ;"), "expected a name");
        assert_eq!(
            error("widget A {}"),
            "expected a message, enum, service or extend definition"
        );
        assert_eq!(error("message A { int32 a = b; }"), "expected an integer");
        assert_eq!(error("message A { int32 a = 1 }"), "expected `;`");
        assert_eq!(error("message A { int32 a = 1;"), "expected `}`");
        assert_eq!(
            error("message A { map<string int32> m = 1; }"),
            "expected `,`"
        );
        assert_eq!(error("message A { option (a = 1; }"), "expected `)`");
        assert_eq!(error("option x = ;"), "expected an option value");
        assert_eq!(error("option x = { a: 1"), "unterminated option value");
        assert_eq!(error("enum E { A = 0;"), "expected `}`");
        assert_eq!(
            error("service S { get X (A) returns (B); }"),
            "expected `rpc` or `option`"
        );
        assert_eq!(error("service S { rpc X (A) (B); }"), "expected `returns`");
        assert_eq!(
            error("service S { rpc X (A) returns (B) { x; } }"),
            "expected `option`"
        );
        assert_eq!(error("service S { rpc X (A) returns (B);"), "expected `}`");
        let deep = format!("{}{}", "message A { ".repeat(70), "}".repeat(70));
        assert_eq!(error(&deep), "nested deeper than the built-in parser reads");
        assert_eq!(parse("\n\nmessage {").unwrap_err().line, 3);
        assert_eq!(parse("message").unwrap_err().line, 1);
    }
}
