//! Minimal edits to the text a document was parsed from.
//!
//! Like `bc-api-spec`'s `edits` module, a repair is a set of exact
//! replacements in the original text rather than a regenerated document:
//! everything an edit does not touch keeps its bytes (quote style,
//! indentation, character references, comments), so the diff a reviewer
//! sees is only the repair. The difference is how an edit is located.
//! There it is found by searching for unique old text; here it is a byte
//! [`Span`] taken from the parsed tree, so it cannot land on a lookalike
//! elsewhere in the file.
//!
//! The constructors take elements and attributes from a tree parsed from
//! the same text the edits are applied to. Fragments are inserted as
//! given: parse the result to confirm it is still well-formed.

use std::fmt;

use crate::escape::escape_attribute;
use crate::tree::{Element, ElementSpan, QName, Span};

/// Most edits one call may apply.
pub const MAX_EDITS: usize = 256;

/// Replace the text in `span` with `replacement`; an empty span inserts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanEdit {
    pub span: Span,
    pub replacement: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EditError {
    /// The element or attribute was built in code, not read from text,
    /// so it has no position to edit at.
    NoSourceSpan,
    TooManyEdits {
        count: usize,
        limit: usize,
    },
    /// A span that ends past the text or does not fall on character
    /// boundaries.
    OutOfBounds(Span),
    /// Two edits that replace overlapping text, or an insertion strictly
    /// inside a replaced span.
    Overlapping(Span, Span),
}

impl fmt::Display for EditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSourceSpan => f.write_str("the node has no position in the source text"),
            Self::TooManyEdits { count, limit } => {
                write!(f, "{count} edits exceed the {limit}-edit limit")
            }
            Self::OutOfBounds(span) => {
                write!(
                    f,
                    "span {}..{} is not inside the text",
                    span.start, span.end
                )
            }
            Self::Overlapping(a, b) => write!(
                f,
                "edits at {}..{} and {}..{} overlap",
                a.start, a.end, b.start, b.end
            ),
        }
    }
}

impl std::error::Error for EditError {}

type Result<T> = std::result::Result<T, EditError>;

fn element_span(element: &Element) -> Result<ElementSpan> {
    element.span.ok_or(EditError::NoSourceSpan)
}

impl SpanEdit {
    pub fn replace(span: Span, replacement: impl Into<String>) -> Self {
        Self {
            span,
            replacement: replacement.into(),
        }
    }

    pub fn insert(offset: usize, text: impl Into<String>) -> Self {
        Self::replace(Span::at(offset), text)
    }

    /// Replace the whole element, tags included, with `fragment`.
    pub fn replace_element(element: &Element, fragment: impl Into<String>) -> Result<Self> {
        Ok(Self::replace(element_span(element)?.outer(), fragment))
    }

    /// Delete the whole element. The whitespace around it stays.
    pub fn remove_element(element: &Element) -> Result<Self> {
        Self::replace_element(element, "")
    }

    pub fn insert_before(element: &Element, fragment: impl Into<String>) -> Result<Self> {
        Ok(Self::insert(element_span(element)?.outer().start, fragment))
    }

    pub fn insert_after(element: &Element, fragment: impl Into<String>) -> Result<Self> {
        Ok(Self::insert(element_span(element)?.outer().end, fragment))
    }

    /// Insert `fragment` as the element's last content. A self-closing
    /// element is opened up: `<a x="1"/>` becomes `<a x="1">fragment</a>`.
    pub fn append_child(element: &Element, fragment: impl Into<String>) -> Result<Self> {
        let span = element_span(element)?;
        match span.end_tag {
            Some(end_tag) => Ok(Self::insert(end_tag.start, fragment)),
            None => Ok(open_up(element, span, fragment.into())),
        }
    }

    /// Insert `fragment` as the element's first content, opening up a
    /// self-closing element like [`SpanEdit::append_child`].
    pub fn prepend_child(element: &Element, fragment: impl Into<String>) -> Result<Self> {
        let span = element_span(element)?;
        match span.end_tag {
            Some(_) => Ok(Self::insert(span.start_tag.end, fragment)),
            None => Ok(open_up(element, span, fragment.into())),
        }
    }

    /// Replace everything between the element's tags, opening up a
    /// self-closing element like [`SpanEdit::append_child`].
    pub fn replace_content(element: &Element, fragment: impl Into<String>) -> Result<Self> {
        let span = element_span(element)?;
        match span.content() {
            Some(content) => Ok(Self::replace(content, fragment)),
            None => Ok(open_up(element, span, fragment.into())),
        }
    }

    /// Set attribute `name` to `value` (escaped here). An existing
    /// attribute is rewritten in place as `name="value"`; a new one is
    /// inserted after the last attribute, or after the element name.
    pub fn set_attribute(element: &Element, name: &QName, value: &str) -> Result<Self> {
        let span = element_span(element)?;
        let written = format!("{name}=\"{}\"", escape_attribute(value));
        if let Some(existing) = element.attributes.iter().find(|a| &a.name == name) {
            let whole = existing.span.ok_or(EditError::NoSourceSpan)?.whole;
            return Ok(Self::replace(whole, written));
        }
        let after = match element.attributes.last() {
            Some(last) => last.span.ok_or(EditError::NoSourceSpan)?.whole.end,
            None => span.start_tag.start + 1 + element.name.to_string().len(),
        };
        Ok(Self::insert(after, format!(" {written}")))
    }

    /// Delete attribute `name` and nothing else; `Ok(None)` if the
    /// element does not have it. The whitespace that separated it stays.
    pub fn remove_attribute(element: &Element, name: &QName) -> Result<Option<Self>> {
        element_span(element)?;
        match element.attributes.iter().find(|a| &a.name == name) {
            Some(attribute) => {
                let whole = attribute.span.ok_or(EditError::NoSourceSpan)?.whole;
                Ok(Some(Self::replace(whole, "")))
            }
            None => Ok(None),
        }
    }
}

/// Turn the `/>` closing a self-closing start tag into `>fragment</name>`.
fn open_up(element: &Element, span: ElementSpan, fragment: String) -> SpanEdit {
    let end = span.start_tag.end;
    let replacement = format!(">{fragment}</{}>", element.name);
    SpanEdit::replace(Span::new(end - "/>".len(), end), replacement)
}

/// Apply `edits` to `original`. Spans refer to `original`, not to the text
/// as earlier edits leave it, so the order edits are listed in does not
/// matter, except that insertions at the same offset keep their order.
pub fn apply_span_edits(original: &str, edits: &[SpanEdit]) -> Result<String> {
    if edits.len() > MAX_EDITS {
        return Err(EditError::TooManyEdits {
            count: edits.len(),
            limit: MAX_EDITS,
        });
    }
    let mut sorted: Vec<&SpanEdit> = edits.iter().collect();
    sorted.sort_by_key(|edit| (edit.span.start, edit.span.end));
    let mut out = String::with_capacity(original.len());
    let mut cursor = 0;
    for edit in sorted {
        let span = edit.span;
        if span.slice(original).is_none() {
            return Err(EditError::OutOfBounds(span));
        }
        if span.start < cursor {
            return Err(EditError::Overlapping(Span::new(span.start, cursor), span));
        }
        out.push_str(&original[cursor..span.start]);
        out.push_str(&edit.replacement);
        cursor = span.end;
    }
    out.push_str(&original[cursor..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_str, Attribute, Limits};

    const DOC: &str =
        "<r xmlns:p=\"urn:p\">\n  <a  x='1' p:y=\"&#65;\">text</a>\n  <b/>\n  <c />\n</r>\n";

    fn apply(edits: &[SpanEdit]) -> String {
        let out = apply_span_edits(DOC, edits).unwrap();
        parse_str(&out, &Limits::new(4096)).expect("edited text still parses");
        out
    }

    fn doc() -> crate::Document {
        parse_str(DOC, &Limits::new(4096)).unwrap()
    }

    fn child<'a>(doc: &'a crate::Document, local: &str) -> &'a Element {
        doc.root.first_child_named(None, local).unwrap()
    }

    #[test]
    fn element_edits_touch_only_their_spans() {
        let doc = doc();
        let (a, b) = (child(&doc, "a"), child(&doc, "b"));
        assert_eq!(
            apply(&[SpanEdit::replace_element(b, "<b2/>").unwrap()]),
            DOC.replace("<b/>", "<b2/>")
        );
        assert_eq!(
            apply(&[SpanEdit::remove_element(b).unwrap()]),
            DOC.replace("<b/>", "")
        );
        assert_eq!(
            apply(&[
                SpanEdit::insert_after(b, "<b3/>").unwrap(),
                SpanEdit::insert_before(b, "<b1/>").unwrap(),
            ]),
            DOC.replace("<b/>", "<b1/><b/><b3/>")
        );
        assert_eq!(
            apply(&[
                SpanEdit::append_child(a, "<z/>").unwrap(),
                SpanEdit::prepend_child(a, "<y/>").unwrap(),
            ]),
            DOC.replace(">text<", "><y/>text<z/><")
        );
        assert_eq!(
            apply(&[SpanEdit::replace_content(a, "new").unwrap()]),
            DOC.replace(">text<", ">new<")
        );
    }

    #[test]
    fn self_closing_elements_are_opened_up_to_take_content() {
        let doc = doc();
        let (b, c) = (child(&doc, "b"), child(&doc, "c"));
        assert_eq!(
            apply(&[SpanEdit::append_child(b, "<i/>").unwrap()]),
            DOC.replace("<b/>", "<b><i/></b>")
        );
        assert_eq!(
            apply(&[SpanEdit::prepend_child(c, "t").unwrap()]),
            DOC.replace("<c />", "<c >t</c>")
        );
        assert_eq!(
            apply(&[SpanEdit::replace_content(b, "t").unwrap()]),
            DOC.replace("<b/>", "<b>t</b>")
        );
    }

    #[test]
    fn attribute_edits_rewrite_or_insert_in_place() {
        let doc = doc();
        let (a, b) = (child(&doc, "a"), child(&doc, "b"));
        let x = QName::new(None, "x");
        assert_eq!(
            apply(&[SpanEdit::set_attribute(a, &x, "\"2\"").unwrap()]),
            DOC.replace("x='1'", "x=\"&quot;2&quot;\"")
        );
        assert_eq!(
            apply(&[SpanEdit::set_attribute(a, &QName::new(None, "n"), "v").unwrap()]),
            DOC.replace("p:y=\"&#65;\"", "p:y=\"&#65;\" n=\"v\"")
        );
        assert_eq!(
            apply(&[SpanEdit::set_attribute(b, &x, "v").unwrap()]),
            DOC.replace("<b/>", "<b x=\"v\"/>")
        );
        let py = QName::new(Some("p"), "y");
        assert_eq!(
            apply(&[SpanEdit::remove_attribute(a, &py).unwrap().unwrap()]),
            DOC.replace(" p:y=\"&#65;\"", " ")
        );
        assert_eq!(SpanEdit::remove_attribute(b, &py).unwrap(), None);
    }

    #[test]
    fn nodes_built_in_code_have_no_span_to_edit() {
        let doc = doc();
        let built = Element::new(QName::new(None, "n"));
        let x = QName::new(None, "x");
        assert_eq!(
            SpanEdit::replace_element(&built, ""),
            Err(EditError::NoSourceSpan)
        );
        assert_eq!(
            SpanEdit::remove_element(&built),
            Err(EditError::NoSourceSpan)
        );
        assert_eq!(
            SpanEdit::insert_before(&built, ""),
            Err(EditError::NoSourceSpan)
        );
        assert_eq!(
            SpanEdit::insert_after(&built, ""),
            Err(EditError::NoSourceSpan)
        );
        assert_eq!(
            SpanEdit::append_child(&built, ""),
            Err(EditError::NoSourceSpan)
        );
        assert_eq!(
            SpanEdit::prepend_child(&built, ""),
            Err(EditError::NoSourceSpan)
        );
        assert_eq!(
            SpanEdit::replace_content(&built, ""),
            Err(EditError::NoSourceSpan)
        );
        assert_eq!(
            SpanEdit::set_attribute(&built, &x, ""),
            Err(EditError::NoSourceSpan)
        );
        assert_eq!(
            SpanEdit::remove_attribute(&built, &x),
            Err(EditError::NoSourceSpan)
        );
        let mut edited = child(&doc, "a").clone();
        edited
            .attributes
            .push(Attribute::new(QName::new(None, "added"), "v"));
        let added = QName::new(None, "added");
        assert_eq!(
            SpanEdit::set_attribute(&edited, &added, ""),
            Err(EditError::NoSourceSpan)
        );
        assert_eq!(
            SpanEdit::set_attribute(&edited, &x, "").unwrap().span.start,
            DOC.find("x='1'").unwrap()
        );
        assert_eq!(
            SpanEdit::set_attribute(&edited, &QName::new(None, "q"), ""),
            Err(EditError::NoSourceSpan)
        );
        assert_eq!(
            SpanEdit::remove_attribute(&edited, &added),
            Err(EditError::NoSourceSpan)
        );
    }

    #[test]
    fn bad_edit_sets_are_refused() {
        let text = "abcdef";
        let edit = |start, end| SpanEdit::replace(Span::new(start, end), "x");
        assert_eq!(apply_span_edits(text, &[]).unwrap(), text);
        assert_eq!(
            apply_span_edits(text, &[edit(4, 5), SpanEdit::insert(1, "y"), edit(1, 2)]).unwrap(),
            "ayxcdxf"
        );
        assert_eq!(
            apply_span_edits(text, &[edit(1, 3), edit(2, 4)]),
            Err(EditError::Overlapping(Span::new(2, 3), Span::new(2, 4)))
        );
        assert!(matches!(
            apply_span_edits(text, &[edit(1, 3), SpanEdit::insert(2, "")]),
            Err(EditError::Overlapping(..))
        ));
        assert_eq!(
            apply_span_edits(text, &[edit(4, 9)]),
            Err(EditError::OutOfBounds(Span::new(4, 9)))
        );
        assert_eq!(
            apply_span_edits(text, &[edit(4, 2)]),
            Err(EditError::OutOfBounds(Span::new(4, 2)))
        );
        assert_eq!(
            apply_span_edits("\u{e9}", &[edit(1, 2)]),
            Err(EditError::OutOfBounds(Span::new(1, 2)))
        );
        let many = vec![SpanEdit::insert(0, ""); MAX_EDITS + 1];
        assert_eq!(
            apply_span_edits(text, &many),
            Err(EditError::TooManyEdits {
                count: MAX_EDITS + 1,
                limit: MAX_EDITS
            })
        );
    }

    #[test]
    fn edit_errors_have_messages() {
        let span = Span::new(1, 2);
        for (error, expected) in [
            (EditError::NoSourceSpan, "no position"),
            (
                EditError::TooManyEdits { count: 3, limit: 2 },
                "3 edits exceed the 2-edit",
            ),
            (EditError::OutOfBounds(span), "1..2 is not inside"),
            (EditError::Overlapping(span, span), "1..2 and 1..2 overlap"),
        ] {
            assert!(error.to_string().contains(expected), "{error}");
        }
        let _: &dyn std::error::Error = &EditError::NoSourceSpan;
    }
}
