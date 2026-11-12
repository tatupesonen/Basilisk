//! Builds a [`Document`] from XML text.
//!
//! `quick-xml` tokenises; this module assembles the tree and applies the
//! rules of Ghidra's `xml.y` that decide the values a decoder sees:
//!
//! - character data, each CDATA section and each reference is passed to the
//!   element separately, and a piece made only of white space is dropped
//!   (`print_content`), so `<a> &amp; </a>` has the content `&`;
//! - attribute values are taken as written, with references expanded and no
//!   white-space normalisation;
//! - a document type declaration is an error.

use std::borrow::Cow;

use quick_xml::Reader;
use quick_xml::escape::{resolve_xml_entity, unescape};
use quick_xml::events::attributes::Attributes;
use quick_xml::events::{BytesStart, Event};

use super::XmlError;
use super::dom::{AttributeData, Document, ElementData, NONE};

/// An element whose end tag has not been seen yet.
struct Open {
    index: u32,
    last_child: u32,
}

struct Builder<'s> {
    source: &'s str,
    doc: Document<'s>,
    open: Vec<Open>,
    root_closed: bool,
}

/// White space as `xml.y` defines it.
fn is_white_space(text: &str) -> bool {
    text.bytes()
        .all(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
}

/// Finds `part`, a slice the tokeniser borrowed from `source`, as a slice
/// with the source's lifetime.
fn reslice<'s>(source: &'s str, part: &str) -> Option<&'s str> {
    let start = part.as_ptr().addr().checked_sub(source.as_ptr().addr())?;
    let end = start.checked_add(part.len())?;
    source.get(start..end)
}

pub(super) fn parse(source: &str) -> Result<Document<'_>, XmlError> {
    if u32::try_from(source.len()).is_err() {
        return Err(XmlError::at(source, 0, "document is larger than 4 GiB"));
    }
    let body = source.strip_prefix('\u{feff}').unwrap_or(source);
    let base = source.len() - body.len();
    let mut reader = Reader::from_str(body);
    // Ghidra's scanner ends a comment at the first "--", so one inside a
    // comment is an error there too.
    reader.config_mut().check_comments = true;
    let mut builder = Builder {
        source,
        doc: Document {
            elements: Vec::new(),
            attributes: Vec::new(),
        },
        open: Vec::new(),
        root_closed: false,
    };
    loop {
        let offset = base + usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX);
        let event = match reader.read_event() {
            Ok(event) => event,
            Err(error) => {
                let at = base + usize::try_from(reader.error_position()).unwrap_or(usize::MAX);
                return Err(XmlError::at(source, at, error.to_string()));
            }
        };
        match event {
            Event::Start(tag) => {
                let index = builder.begin(&tag, offset)?;
                builder.open.push(Open {
                    index,
                    last_child: NONE,
                });
            }
            Event::Empty(tag) => {
                builder.begin(&tag, offset)?;
                if builder.open.is_empty() {
                    builder.root_closed = true;
                }
            }
            Event::End(_) => {
                if builder.open.pop().is_none() {
                    return Err(XmlError::at(source, offset, "end tag without a start tag"));
                }
                if builder.open.is_empty() {
                    builder.root_closed = true;
                }
            }
            Event::Text(text) => builder.piece(text.into_inner(), offset)?,
            Event::CData(data) => builder.piece(data.into_inner(), offset)?,
            Event::GeneralRef(reference) => {
                let resolved = match reference.resolve_char_ref() {
                    Ok(Some(character)) => Cow::Owned(character.to_string()),
                    Ok(None) => {
                        let Some(text) = resolve_xml_entity(&reference) else {
                            let message = format!("unknown entity reference `&{};`", &*reference);
                            return Err(XmlError::at(source, offset, message));
                        };
                        Cow::Borrowed(text)
                    }
                    Err(error) => return Err(XmlError::at(source, offset, error.to_string())),
                };
                builder.piece(resolved, offset)?;
            }
            Event::DocType(_) => {
                return Err(XmlError::at(source, offset, "DTD's not supported"));
            }
            // Ghidra refuses processing instructions; they are legal XML and
            // carry nothing a decoder reads, so they are skipped.
            Event::Comment(_) | Event::PI(_) | Event::Decl(_) => {}
            Event::Eof => break,
        }
    }
    if let Some(unclosed) = builder.open.last() {
        let name = builder
            .doc
            .elements
            .get(unclosed.index as usize)
            .map_or("", |e| e.name);
        return Err(XmlError::at(
            source,
            source.len(),
            format!("element <{name}> is not closed"),
        ));
    }
    if builder.doc.elements.is_empty() {
        return Err(XmlError::at(
            source,
            source.len(),
            "document has no root element",
        ));
    }
    Ok(builder.doc)
}

impl<'s> Builder<'s> {
    /// Adds the element of a start or empty-element tag and links it to its
    /// parent. Returns its index.
    fn begin(&mut self, tag: &BytesStart<'_>, offset: usize) -> Result<u32, XmlError> {
        let source = self.source;
        if self.root_closed {
            return Err(XmlError::at(source, offset, "more than one root element"));
        }
        let internal = || XmlError::at(source, offset, "tag is not part of the source text");
        let text = reslice(source, tag).ok_or_else(internal)?;
        let name_len = tag.name().into_inner().len();
        let name = text.get(..name_len).ok_or_else(internal)?;
        if name.is_empty() {
            return Err(XmlError::at(source, offset, "element without a name"));
        }
        let attr_start = self.attribute_count();
        for attribute in Attributes::new(text, name_len) {
            let attribute = attribute
                .map_err(|error| XmlError::at(source, offset, format!("in <{name}>: {error}")))?;
            // References are expanded; white space stays as written.
            let value = match attribute.value {
                Cow::Borrowed(raw) => unescape(raw),
                Cow::Owned(raw) => unescape(&raw).map(|value| Cow::Owned(value.into_owned())),
            }
            .map_err(|error| XmlError::at(source, offset, format!("in <{name}>: {error}")))?;
            self.doc.attributes.push(AttributeData {
                name: attribute.key.into_inner(),
                value,
            });
        }
        let index = u32::try_from(self.doc.elements.len()).unwrap_or(NONE);
        let parent = self.open.last().map_or(NONE, |open| open.index);
        self.doc.elements.push(ElementData {
            name,
            content: Cow::Borrowed(""),
            attr_start,
            attr_end: self.attribute_count(),
            parent,
            first_child: NONE,
            next_sibling: NONE,
            offset: u32::try_from(offset).unwrap_or(u32::MAX),
        });
        if let Some(open) = self.open.last_mut() {
            let previous = std::mem::replace(&mut open.last_child, index);
            let link = if previous == NONE {
                self.doc
                    .elements
                    .get_mut(parent as usize)
                    .map(|element| &mut element.first_child)
            } else {
                self.doc
                    .elements
                    .get_mut(previous as usize)
                    .map(|element| &mut element.next_sibling)
            };
            if let Some(link) = link {
                *link = index;
            }
        }
        Ok(index)
    }

    fn attribute_count(&self) -> u32 {
        u32::try_from(self.doc.attributes.len()).unwrap_or(u32::MAX)
    }

    /// Hands one piece of character data to the current element, as Ghidra's
    /// `print_content` does: a piece that is only white space is ignored.
    fn piece(&mut self, piece: Cow<'s, str>, offset: usize) -> Result<(), XmlError> {
        if is_white_space(&piece) {
            return Ok(());
        }
        let element = self
            .open
            .last()
            .and_then(|open| self.doc.elements.get_mut(open.index as usize));
        let Some(element) = element else {
            return Err(XmlError::at(
                self.source,
                offset,
                "text outside the root element",
            ));
        };
        if element.content.is_empty() {
            element.content = piece;
        } else {
            element.content.to_mut().push_str(&piece);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::Document;

    fn content(source: &str) -> String {
        Document::parse(source).unwrap().root().content().to_owned()
    }

    #[test]
    fn dom_exposes_names_attributes_children() {
        let doc = Document::parse(
            "<?xml version=\"1.0\"?>\n<root a=\"1\" b='two'><x/>text<y k=\"v\">inner</y><!-- c --></root>\n",
        )
        .unwrap();
        let root = doc.root();
        assert_eq!(doc.element_count(), 3);
        assert_eq!(root.name(), "root");
        assert_eq!(root.attribute_count(), 2);
        assert_eq!(
            root.attributes().collect::<Vec<_>>(),
            [("a", "1"), ("b", "two")]
        );
        assert_eq!(root.attribute_at(1), Some(("b", "two")));
        assert_eq!(root.attribute_at(2), None);
        assert_eq!(root.attribute("b"), Some("two"));
        assert_eq!(root.attribute("c"), None);
        assert_eq!(root.content(), "text");
        let names: Vec<&str> = root.children().map(|c| c.name()).collect();
        assert_eq!(names, ["x", "y"]);
        let x = root.first_child().unwrap();
        assert_eq!(x.content(), "");
        assert_eq!(x.attribute_count(), 0);
        let y = x.next_sibling().unwrap();
        assert_eq!(y.content(), "inner");
        assert_eq!(y.attribute("k"), Some("v"));
        assert!(y.next_sibling().is_none());
        assert_eq!(y.parent(), Some(root));
        assert!(root.parent().is_none());
        assert_eq!(root.source_offset(), 22);
        assert_eq!(y.source_offset(), 50);
        assert!(format!("{doc:?}").contains("root"));
        assert!(format!("{y:?}").contains('y'));
    }

    /// Ghidra hands character data, references and CDATA sections to the
    /// element one piece at a time and drops pieces that are only white space.
    #[test]
    fn content_follows_ghidras_piece_rule() {
        assert_eq!(content("<a>  plain  </a>"), "  plain  ");
        assert_eq!(content("<a> \n\t\r </a>"), "");
        assert_eq!(content("<a> &amp; </a>"), "&");
        assert_eq!(content("<a>p &lt; q</a>"), "p < q");
        assert_eq!(content("<a>  <![CDATA[ x <y> & ]]>  </a>"), " x <y> & ");
        assert_eq!(content("<a>one<![CDATA[two]]>three</a>"), "onetwothree");
        assert_eq!(content("<a><![CDATA[  ]]></a>"), "");
        assert_eq!(content("<a>a<![CDATA[]]>b</a>"), "ab");
        assert_eq!(content("<a>&#32;x&#x20;&#9;</a>"), "x");
        assert_eq!(
            content("<a>&lt;&gt;&amp;&quot;&apos;&#65;&#x42;</a>"),
            "<>&\"'AB"
        );
        // Comments and child elements separate pieces without adding to them.
        assert_eq!(content("<a>foo <!-- c --> bar</a>"), "foo  bar");
        assert_eq!(content("<a>one <b>inner</b> two <c/> </a>"), "one  two ");
        // Line ends are kept as written.
        assert_eq!(content("<a>l1\r\nl2</a>"), "l1\r\nl2");
    }

    #[test]
    fn character_references_are_unicode() {
        // Ghidra's C++ parser truncates the code point to one byte; the Java
        // side and this parser produce the character.
        assert_eq!(content("<a>&#x20AC;&#8364;</a>"), "\u{20ac}\u{20ac}");
        let doc = Document::parse("<a k='&#x20AC;'/>").unwrap();
        assert_eq!(doc.root().attribute("k"), Some("\u{20ac}"));
    }

    #[test]
    fn attribute_values_are_not_normalised() {
        let doc = Document::parse(
            "<a k1 = 'x&amp;y  z' k2=\"line1\n\tline2\r\n\" k3='' k4='&quot;&#x41;\"'/>",
        )
        .unwrap();
        let root = doc.root();
        assert_eq!(root.attribute("k1"), Some("x&y  z"));
        assert_eq!(root.attribute("k2"), Some("line1\n\tline2\r\n"));
        assert_eq!(root.attribute("k3"), Some(""));
        assert_eq!(root.attribute("k4"), Some("\"A\""));
    }

    #[test]
    fn names_keep_their_prefix() {
        let doc = Document::parse("<xi:include xml:space='preserve' a.b-c_d='1'/>").unwrap();
        assert_eq!(doc.root().name(), "xi:include");
        assert_eq!(doc.root().attribute("xml:space"), Some("preserve"));
        assert_eq!(doc.root().attribute("a.b-c_d"), Some("1"));
    }

    #[test]
    fn values_are_borrowed_from_the_source_when_possible() {
        let source = "<a k='v' e='&lt;'>text<b>t1<![CDATA[t2]]></b></a>";
        let doc = Document::parse(source).unwrap();
        let range = source.as_bytes().as_ptr_range();
        let inside = |text: &str| range.contains(&text.as_ptr());
        let root = doc.root();
        assert!(inside(root.name()));
        assert!(inside(root.attribute("k").unwrap()));
        assert!(!inside(root.attribute("e").unwrap()));
        assert!(inside(root.content()));
        assert!(!inside(root.first_child().unwrap().content()));
    }

    #[test]
    fn prolog_and_trailer() {
        // A byte order mark, the XML declaration (with the standalone
        // pseudo-attribute, which Ghidra's grammar lacks), comments and
        // processing instructions around the root element.
        let doc = Document::parse(
            "\u{feff}<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<!-- head -->\n<?pi x?>\n<a><?pi data?>t</a>\n<!-- tail -->\n",
        )
        .unwrap();
        assert_eq!(doc.root().content(), "t");
        assert_eq!(doc.root().source_offset(), 82);
    }

    #[test]
    fn rejections() {
        for source in [
            "",                       // no root element
            "  \n",                   // no root element
            "<a>",                    // unterminated
            "<a><b></a>",             // unterminated child
            "<a></b>",                // Ghidra accepts a mismatched end tag
            "</a>",                   // end without start
            "<a k='1' k='2'/>",       // Ghidra accepts a repeated attribute
            "<a>&nbsp;</a>",          // Ghidra turns an unknown entity into byte 0xff
            "<a k='&nbsp;'/>",        // likewise in an attribute
            "<a k=v/>",               // unquoted value: rejected by Ghidra too
            "<a k/>",                 // attribute without a value
            "<!DOCTYPE a><a/>",       // rejected by Ghidra too ("DTD's not supported")
            "<a/><b/>",               // two roots
            "<a/>text",               // text after the root
            "text<a/>",               // text before the root
            "&amp;<a/>",              // reference outside the root
            "<a>&#0;</a>",            // not a character
            "<a>&#xffffffff;</a>",    // not a character
            "<a><!-- a -- b --></a>", // "--" inside a comment: rejected by Ghidra too
            "<a>&amp</a>",            // unterminated reference
            "< a/>",                  // no name
        ] {
            assert!(
                Document::parse(source).is_err(),
                "{source:?} should be rejected"
            );
        }
    }

    #[test]
    fn errors_carry_position_and_message() {
        let err = Document::parse("<a>\n  <b></a>").unwrap_err();
        assert_eq!(err.line, 2);
        assert!(err.message.contains('b'), "{}", err.message);
        assert_eq!(
            err.to_string(),
            format!("XML error at 2:{}: {}", err.column, err.message)
        );
        let err = Document::parse("<a>\n<!DOCTYPE x>").unwrap_err();
        assert_eq!((err.line, err.column), (2, 1));
        assert_eq!(err.message, "DTD's not supported");
    }

    #[test]
    fn deep_nesting_does_not_overflow_the_stack() {
        let depth = 200_000;
        let mut source = String::new();
        for _ in 0..depth {
            source.push_str("<a>");
        }
        for _ in 0..depth {
            source.push_str("</a>");
        }
        let doc = Document::parse(&source).unwrap();
        let mut count = 0;
        let mut element = Some(doc.root());
        while let Some(current) = element {
            count += 1;
            element = current.first_child();
        }
        assert_eq!(count, depth);
    }
}
