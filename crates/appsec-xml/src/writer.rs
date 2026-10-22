//! Deterministic serialization.
//!
//! The output depends only on the tree: prefixes, attribute order and the
//! self-closing form are written as the tree holds them, attribute values
//! are always double-quoted, and nothing is indented or reformatted (any
//! whitespace the document had is in its text nodes). Every name,
//! character and delimiter is checked first, so the writer returns an
//! error instead of text that would not parse.
//!
//! Namespace bindings are not re-checked: a tree built or edited in code
//! can use a prefix it never declares. Parse the output to verify it.

use crate::chars::{is_ncname, is_whitespace, is_xml_char};
use crate::error::WriteError;
use crate::escape::{escape_attribute, escape_text};
use crate::reader::{is_ascii_compatible_label, is_utf8_label};
use crate::tree::{Document, Element, Node, QName, XmlDeclaration};

type Result<T> = std::result::Result<T, WriteError>;

/// Serialize a whole document.
pub fn write_document(document: &Document) -> Result<String> {
    let mut out = String::new();
    if document.byte_order_mark {
        out.push('\u{FEFF}');
    }
    if let Some(declaration) = &document.declaration {
        write_declaration(declaration, &mut out)?;
    }
    for node in &document.prolog {
        write_misc(node, &mut out)?;
    }
    write_element_into(&document.root, &mut out)?;
    for node in &document.epilog {
        write_misc(node, &mut out)?;
    }
    // A declaration naming an ASCII-compatible legacy encoding is only
    // truthful while the output stays ASCII.
    let label = document
        .declaration
        .as_ref()
        .and_then(|d| d.encoding.as_deref());
    if label.is_some_and(|label| !is_utf8_label(label)) && !out.is_ascii() {
        return Err(WriteError::InvalidDeclaration(
            "non-ASCII output under a non-UTF-8 encoding label".into(),
        ));
    }
    Ok(out)
}

/// Serialize one element and its content, for example as a fragment to
/// insert with [`SpanEdit`](crate::SpanEdit).
pub fn write_element(element: &Element) -> Result<String> {
    let mut out = String::new();
    write_element_into(element, &mut out)?;
    Ok(out)
}

fn write_declaration(declaration: &XmlDeclaration, out: &mut String) -> Result<()> {
    if declaration.version != "1.0" {
        return Err(WriteError::InvalidDeclaration(format!(
            "version {:?} is not 1.0",
            declaration.version
        )));
    }
    out.push_str("<?xml version=\"1.0\"");
    if let Some(encoding) = &declaration.encoding {
        if !is_utf8_label(encoding) && !is_ascii_compatible_label(encoding) {
            return Err(WriteError::InvalidDeclaration(format!(
                "encoding {encoding:?} is not one the reader accepts"
            )));
        }
        out.push_str(&format!(" encoding=\"{encoding}\""));
    }
    match declaration.standalone {
        Some(true) => out.push_str(" standalone=\"yes\""),
        Some(false) => out.push_str(" standalone=\"no\""),
        None => {}
    }
    out.push_str("?>");
    Ok(())
}

/// A node outside the root element.
fn write_misc(node: &Node, out: &mut String) -> Result<()> {
    match node {
        Node::Text(text) if text.chars().all(is_whitespace) => out.push_str(text),
        Node::Text(_) | Node::CData(_) => return Err(WriteError::InvalidMisc),
        _ => write_leaf(node, out)?,
    }
    Ok(())
}

enum Step<'a> {
    Open(&'a Element),
    Close(&'a QName),
    Leaf(&'a Node),
}

/// Iterative, like the reader, so a deep tree built in code cannot
/// overflow the stack.
fn write_element_into(root: &Element, out: &mut String) -> Result<()> {
    let mut steps = vec![Step::Open(root)];
    while let Some(step) = steps.pop() {
        match step {
            Step::Open(element) => {
                out.push('<');
                push_name(&element.name, out)?;
                for attribute in &element.attributes {
                    out.push(' ');
                    push_name(&attribute.name, out)?;
                    check_chars(&attribute.value)?;
                    out.push_str("=\"");
                    out.push_str(&escape_attribute(&attribute.value));
                    out.push('"');
                }
                if element.self_closing && element.children.is_empty() {
                    out.push_str("/>");
                    continue;
                }
                out.push('>');
                steps.push(Step::Close(&element.name));
                for child in element.children.iter().rev() {
                    steps.push(match child {
                        Node::Element(element) => Step::Open(element),
                        leaf => Step::Leaf(leaf),
                    });
                }
            }
            Step::Close(name) => {
                out.push_str("</");
                out.push_str(&name.to_string());
                out.push('>');
            }
            Step::Leaf(node) => write_leaf(node, out)?,
        }
    }
    Ok(())
}

fn write_leaf(node: &Node, out: &mut String) -> Result<()> {
    match node {
        Node::Text(text) => {
            check_chars(text)?;
            out.push_str(&escape_text(text));
        }
        Node::CData(text) => {
            check_chars(text)?;
            if text.contains("]]>") {
                return Err(WriteError::InvalidCData(text.clone()));
            }
            out.push_str("<![CDATA[");
            out.push_str(text);
            out.push_str("]]>");
        }
        Node::Comment(text) => {
            check_chars(text)?;
            if text.contains("--") || text.ends_with('-') {
                return Err(WriteError::InvalidComment(text.clone()));
            }
            out.push_str("<!--");
            out.push_str(text);
            out.push_str("-->");
        }
        Node::ProcessingInstruction(pi) => {
            check_chars(&pi.data)?;
            let valid = is_ncname(&pi.target)
                && !pi.target.eq_ignore_ascii_case("xml")
                && !pi.data.contains("?>");
            if !valid {
                return Err(WriteError::InvalidProcessingInstruction(pi.target.clone()));
            }
            out.push_str("<?");
            out.push_str(&pi.target);
            if !pi.data.is_empty() {
                out.push(' ');
                out.push_str(&pi.data);
            }
            out.push_str("?>");
        }
        // Content elements are written as steps and never get here, so
        // this is an element outside the root.
        Node::Element(_) => return Err(WriteError::InvalidMisc),
    }
    Ok(())
}

fn push_name(name: &QName, out: &mut String) -> Result<()> {
    if !name.is_valid() {
        return Err(WriteError::InvalidName(name.to_string()));
    }
    out.push_str(&name.to_string());
    Ok(())
}

fn check_chars(text: &str) -> Result<()> {
    match text.chars().find(|&c| !is_xml_char(c)) {
        Some(c) => Err(WriteError::InvalidChar(c)),
        None => Ok(()),
    }
}
