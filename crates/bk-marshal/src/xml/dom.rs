//! The XML document tree (Ghidra `Document` and `Element` in `xml.hh`).
//!
//! Elements and attributes live in two arenas addressed by `u32` indices;
//! names and most values are borrowed from the source text.

use std::borrow::Cow;

use super::XmlError;
use super::parse;

/// Marks "no element" in the index links.
pub(super) const NONE: u32 = u32::MAX;

/// One element in the arena.
#[derive(Debug, Clone)]
pub(super) struct ElementData<'s> {
    /// The qualified name as written.
    pub(super) name: &'s str,
    /// Text content by Ghidra's rule.
    pub(super) content: Cow<'s, str>,
    /// First attribute in the attribute arena.
    pub(super) attr_start: u32,
    /// One past the last attribute in the attribute arena.
    pub(super) attr_end: u32,
    /// Parent element, or `NONE` for the root.
    pub(super) parent: u32,
    /// First child element, or `NONE`.
    pub(super) first_child: u32,
    /// Next element with the same parent, or `NONE`.
    pub(super) next_sibling: u32,
    /// Byte offset of the start tag in the source.
    pub(super) offset: u32,
}

/// One attribute in the arena.
#[derive(Debug, Clone)]
pub(super) struct AttributeData<'s> {
    pub(super) name: &'s str,
    pub(super) value: Cow<'s, str>,
}

/// A parsed XML document (Ghidra `Document`).
///
/// Names are borrowed from the source text, and so are attribute values and
/// text content unless they contain references or are assembled from several
/// pieces.
#[derive(Debug, Clone)]
pub struct Document<'s> {
    pub(super) elements: Vec<ElementData<'s>>,
    pub(super) attributes: Vec<AttributeData<'s>>,
}

impl<'s> Document<'s> {
    /// Parses XML text.
    ///
    /// The values produced follow Ghidra's `xml.y`: attribute values are taken
    /// as written (references expanded, white space not normalised), and an
    /// element's content is the concatenation of its character data, CDATA
    /// sections and references, leaving out every piece that consists only of
    /// white space. See `docs/features/core-marshal.md` for the cases where
    /// the accepted language differs from Ghidra's.
    pub fn parse(source: &'s str) -> Result<Self, XmlError> {
        parse::parse(source)
    }

    /// The root element.
    pub fn root(&self) -> ElementRef<'_> {
        ElementRef {
            doc: self.shrink(),
            index: 0,
        }
    }

    /// The number of elements in the document.
    pub fn element_count(&self) -> usize {
        self.elements.len()
    }

    /// The same document with its source lifetime shortened to the borrow, so
    /// that element handles need only one lifetime.
    fn shrink(&self) -> &Document<'_> {
        self
    }
}

/// A handle to an element of a [`Document`] (Ghidra `Element`).
#[derive(Clone, Copy)]
pub struct ElementRef<'a> {
    doc: &'a Document<'a>,
    index: u32,
}

impl std::fmt::Debug for ElementRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElementRef")
            .field("name", &self.name())
            .finish_non_exhaustive()
    }
}

impl PartialEq for ElementRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.doc, other.doc) && self.index == other.index
    }
}

impl Eq for ElementRef<'_> {}

impl<'a> ElementRef<'a> {
    fn data(&self) -> Option<&'a ElementData<'a>> {
        self.doc.elements.get(self.index as usize)
    }

    fn attribute_slice(&self) -> &'a [AttributeData<'a>] {
        self.data()
            .and_then(|data| {
                self.doc
                    .attributes
                    .get(data.attr_start as usize..data.attr_end as usize)
            })
            .unwrap_or_default()
    }

    fn at(&self, index: u32) -> Option<ElementRef<'a>> {
        (index != NONE).then_some(ElementRef {
            doc: self.doc,
            index,
        })
    }

    /// The element's name as written, including any namespace prefix.
    pub fn name(&self) -> &'a str {
        self.data().map_or("", |data| data.name)
    }

    /// The element's text content by Ghidra's rule: the concatenation of its
    /// character data, CDATA sections and references, leaving out every piece
    /// that consists only of white space. Text inside child elements is not
    /// included.
    pub fn content(&self) -> &'a str {
        self.data().map_or("", |data| data.content.as_ref())
    }

    /// The number of attributes.
    pub fn attribute_count(&self) -> usize {
        self.attribute_slice().len()
    }

    /// The attributes as `(name, value)` pairs, in document order.
    pub fn attributes(&self) -> impl ExactSizeIterator<Item = (&'a str, &'a str)> + use<'a> {
        self.attribute_slice()
            .iter()
            .map(|attribute| (attribute.name, attribute.value.as_ref()))
    }

    /// The `index`-th attribute as a `(name, value)` pair.
    pub fn attribute_at(&self, index: usize) -> Option<(&'a str, &'a str)> {
        self.attribute_slice()
            .get(index)
            .map(|attribute| (attribute.name, attribute.value.as_ref()))
    }

    /// The value of the attribute called `name`.
    pub fn attribute(&self, name: &str) -> Option<&'a str> {
        self.attribute_slice()
            .iter()
            .find(|attribute| attribute.name == name)
            .map(|attribute| attribute.value.as_ref())
    }

    /// The child elements, in document order.
    pub fn children(&self) -> impl Iterator<Item = ElementRef<'a>> + use<'a> {
        std::iter::successors(self.first_child(), ElementRef::next_sibling)
    }

    /// The first child element.
    pub fn first_child(&self) -> Option<ElementRef<'a>> {
        self.at(self.data()?.first_child)
    }

    /// The next element with the same parent.
    pub fn next_sibling(&self) -> Option<ElementRef<'a>> {
        self.at(self.data()?.next_sibling)
    }

    /// The parent element; `None` for the root.
    pub fn parent(&self) -> Option<ElementRef<'a>> {
        self.at(self.data()?.parent)
    }

    /// The byte offset of the element's start tag in the source text.
    pub fn source_offset(&self) -> usize {
        self.data().map_or(0, |data| data.offset as usize)
    }
}
