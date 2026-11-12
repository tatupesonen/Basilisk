//! Support shared by the three readers: parsing the XML, checking each
//! element against the grammar tables in [`crate::schema`], positions, and
//! the strict/lenient split.

use std::{fs, path::Path};

use roxmltree::{Document, Node, ParsingOptions};

use crate::{
    error::{Mode, ParseError, ParseErrorKind, Position, ReadError, Violation, Warning},
    schema::{ElementDef, MAX_CHILDREN},
};

/// A value read from a spec file together with the schema violations that
/// were tolerated on the way (always empty in [`Mode::Strict`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed<T> {
    /// The typed model of the file.
    pub value: T,
    /// Violations tolerated in [`Mode::Lenient`], in document order.
    pub warnings: Vec<Warning>,
}

/// The state of one read: the document, the mode and the warnings so far.
pub(crate) struct Reader<'d, 'i> {
    doc: &'d Document<'i>,
    mode: Mode,
    warnings: Vec<Warning>,
}

/// Whether `text` is only XML white space, which RELAX NG ignores between
/// elements.
fn is_xml_space(text: &str) -> bool {
    text.bytes()
        .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
}

/// Child elements of `node` named `name` (in no namespace).
pub(crate) fn children_named<'a, 'i>(
    node: Node<'a, 'i>,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'i>> {
    node.children().filter(move |c| is(*c, name))
}

/// Whether `node` is an element named `name` in no namespace.
pub(crate) fn is(node: Node<'_, '_>, name: &str) -> bool {
    node.is_element() && node.tag_name().namespace().is_none() && node.tag_name().name() == name
}

/// All character data directly inside `node`, concatenated and untrimmed,
/// as Ghidra's pull parser reports an element's text.
pub(crate) fn text_of(node: Node<'_, '_>) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|c| c.text())
        .collect()
}

impl<'d, 'i> Reader<'d, 'i> {
    /// The position of `node`'s start tag.
    pub(crate) fn position(&self, node: Node<'_, '_>) -> Position {
        let pos = self.doc.text_pos_at(node.range().start);
        Position {
            line: pos.row,
            column: pos.col,
        }
    }

    /// An error at `node` that both modes report.
    pub(crate) fn fatal(&self, node: Node<'_, '_>, kind: ParseErrorKind) -> ParseError {
        ParseError {
            position: self.position(node),
            kind,
        }
    }

    /// Reports a schema violation at `node`: an error in strict mode, a
    /// warning in lenient mode.
    pub(crate) fn violation(
        &mut self,
        node: Node<'_, '_>,
        violation: Violation,
    ) -> Result<(), ParseError> {
        let position = self.position(node);
        match self.mode {
            Mode::Strict => Err(ParseError {
                position,
                kind: ParseErrorKind::Schema(violation),
            }),
            Mode::Lenient => {
                self.warnings.push(Warning {
                    position,
                    violation,
                });
                Ok(())
            }
        }
    }

    /// Reports the violation of a rule that the tables cannot express.
    pub(crate) fn rule(
        &mut self,
        node: Node<'_, '_>,
        def: &'static ElementDef,
        rule: &'static str,
    ) -> Result<(), ParseError> {
        self.violation(
            node,
            Violation::Rule {
                element: def.name,
                rule,
            },
        )
    }

    /// The document element, which must be `def`.
    pub(crate) fn root(&mut self, def: &'static ElementDef) -> Result<Node<'d, 'i>, ParseError> {
        let root = self.doc.root_element();
        if !is(root, def.name) {
            return Err(self.fatal(
                root,
                ParseErrorKind::WrongRoot {
                    expected: def.name,
                    found: root.tag_name().name().to_owned(),
                },
            ));
        }
        self.check(root, def)?;
        Ok(root)
    }

    /// Checks `node`'s attributes and immediate content against `def`.
    pub(crate) fn check(
        &mut self,
        node: Node<'_, '_>,
        def: &'static ElementDef,
    ) -> Result<(), ParseError> {
        for attr in node.attributes() {
            let known = if attr.namespace().is_none() {
                def.attr(attr.name())
            } else {
                None
            };
            match known {
                None => self.violation(
                    node,
                    Violation::UnknownAttribute {
                        element: def.name,
                        name: attr.name().to_owned(),
                    },
                )?,
                Some(a) => {
                    if let Some(expected) = a.ty.rejects(attr.value()) {
                        self.violation(
                            node,
                            Violation::InvalidAttributeValue {
                                element: def.name,
                                name: a.name,
                                value: attr.value().to_owned(),
                                expected,
                            },
                        )?;
                    }
                }
            }
        }
        for a in def.attrs {
            if a.required && node.attribute(a.name).is_none() {
                self.violation(
                    node,
                    Violation::MissingAttribute {
                        element: def.name,
                        name: a.name,
                    },
                )?;
            }
        }

        let mut counts = [0u32; MAX_CHILDREN];
        let mut group = 0u8;
        for c in node.children() {
            if c.is_element() {
                let index = if c.tag_name().namespace().is_none() {
                    def.child_index(c.tag_name().name())
                } else {
                    None
                };
                let known = index.and_then(|i| Some((def.children.get(i)?, counts.get_mut(i)?)));
                let Some((child, count)) = known else {
                    self.violation(
                        c,
                        Violation::UnknownElement {
                            parent: def.name,
                            name: c.tag_name().name().to_owned(),
                        },
                    )?;
                    continue;
                };
                *count += 1;
                let repeated = *count == 2 && child.card.at_most_one();
                if child.group < group {
                    self.violation(
                        c,
                        Violation::OutOfOrder {
                            parent: def.name,
                            name: child.def.name,
                        },
                    )?;
                } else {
                    group = child.group;
                }
                if repeated {
                    self.violation(
                        c,
                        Violation::RepeatedElement {
                            parent: def.name,
                            name: child.def.name,
                        },
                    )?;
                }
            } else if c.is_text() && !def.text && !c.text().is_some_and(is_xml_space) {
                self.violation(c, Violation::UnexpectedText { element: def.name })?;
            }
        }
        for (child, count) in def.children.iter().zip(counts) {
            if child.card.at_least_one() && count == 0 {
                self.violation(
                    node,
                    Violation::MissingElement {
                        parent: def.name,
                        name: child.def.name,
                    },
                )?;
            }
        }
        Ok(())
    }

    /// The value of an attribute the reader cannot do without.
    pub(crate) fn required<'a>(
        &self,
        node: Node<'a, '_>,
        def: &'static ElementDef,
        attribute: &'static str,
    ) -> Result<&'a str, ParseError> {
        node.attribute(attribute).ok_or_else(|| {
            self.fatal(
                node,
                ParseErrorKind::MissingAttribute {
                    element: def.name,
                    attribute,
                },
            )
        })
    }

    /// An error for an attribute value that cannot be decoded.
    pub(crate) fn invalid(
        &self,
        node: Node<'_, '_>,
        def: &'static ElementDef,
        attribute: &'static str,
        value: &str,
        expected: &'static str,
    ) -> ParseError {
        self.fatal(
            node,
            ParseErrorKind::InvalidValue {
                element: def.name,
                attribute,
                value: value.to_owned(),
                expected,
            },
        )
    }

    /// Decodes an optional attribute with `decode`, failing with what was
    /// `expected` when the value does not decode.
    pub(crate) fn decode<T>(
        &self,
        node: Node<'_, '_>,
        def: &'static ElementDef,
        attribute: &'static str,
        expected: &'static str,
        decode: impl FnOnce(&str) -> Option<T>,
    ) -> Result<Option<T>, ParseError> {
        match node.attribute(attribute) {
            None => Ok(None),
            Some(value) => decode(value)
                .map(Some)
                .ok_or_else(|| self.invalid(node, def, attribute, value, expected)),
        }
    }

    /// Decodes an optional boolean attribute as `SpecXmlUtils.decodeBoolean`
    /// does: absent or undecidable is `false`.
    pub(crate) fn flag(node: Node<'_, '_>, attribute: &str) -> bool {
        node.attribute(attribute)
            .and_then(crate::value::decode_bool)
            .unwrap_or(false)
    }
}

/// Parses `text` and runs `read` over the document.
pub(crate) fn parse_with<T>(
    text: &str,
    mode: Mode,
    read: impl FnOnce(&mut Reader<'_, '_>) -> Result<T, ParseError>,
) -> Result<Parsed<T>, ParseError> {
    // DTDs stay disabled: no spec file has one, and entity expansion is the
    // classic way to make an XML reader allocate without bound.
    let options = ParsingOptions {
        allow_dtd: false,
        ..ParsingOptions::default()
    };
    let doc = Document::parse_with_options(text, options).map_err(|e| {
        let pos = e.pos();
        ParseError {
            position: Position {
                line: pos.row,
                column: pos.col,
            },
            kind: ParseErrorKind::Xml(e.to_string()),
        }
    })?;
    let mut reader = Reader {
        doc: &doc,
        mode,
        warnings: Vec::new(),
    };
    let value = read(&mut reader)?;
    Ok(Parsed {
        value,
        warnings: reader.warnings,
    })
}

/// Reads `path` as UTF-8 text and parses it with `parse`.
pub(crate) fn read_file_with<T>(
    path: &Path,
    parse: impl FnOnce(&str) -> Result<Parsed<T>, ParseError>,
) -> Result<Parsed<T>, ReadError> {
    let bytes = fs::read(path).map_err(|source| ReadError::Io {
        path: path.to_owned(),
        source,
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|source| ReadError::Encoding {
        path: path.to_owned(),
        source,
    })?;
    parse(text).map_err(|source| ReadError::Parse {
        path: path.to_owned(),
        source,
    })
}
