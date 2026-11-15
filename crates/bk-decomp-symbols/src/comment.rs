//! Comments (Ghidra `Comment`, `CommentOrder`, `CommentDatabaseInternal`,
//! comment.cc; spec 4.12). `CommentSorter` is D16b's.

use std::collections::BTreeMap;
use std::ops::Bound;

use bk_core::{Address, SpaceManager};
use bk_marshal::ids::{ATTRIB_CONTENT, ATTRIB_TYPE};
use bk_marshal::{Decoder, Encoder};

use crate::error::{Result, SymbolError};
use crate::ids::{ELEM_COMMENT, ELEM_COMMENTDB, ELEM_TEXT};

/// Comment types (one bit each; Ghidra `Comment::comment_type`).
pub mod kind {
    /// `user1`.
    pub const USER1: u32 = 1;
    /// `user2`.
    pub const USER2: u32 = 2;
    /// `user3`.
    pub const USER3: u32 = 4;
    /// `header`.
    pub const HEADER: u32 = 8;
    /// `warning`.
    pub const WARNING: u32 = 16;
    /// `warningheader`.
    pub const WARNINGHEADER: u32 = 32;
}

/// Ghidra `Comment::encodeCommentType`: a type name to its bit.
pub fn comment_type_by_name(name: &str) -> Result<u32> {
    Ok(match name {
        "user1" => kind::USER1,
        "user2" => kind::USER2,
        "user3" => kind::USER3,
        "header" => kind::HEADER,
        "warning" => kind::WARNING,
        "warningheader" => kind::WARNINGHEADER,
        _ => {
            return Err(SymbolError::UnknownCommentType {
                name: name.to_owned(),
            });
        }
    })
}

/// Ghidra `Comment::decodeCommentType`: a single type bit to its name.
pub fn comment_type_name(value: u32) -> Result<&'static str> {
    Ok(match value {
        kind::USER1 => "user1",
        kind::USER2 => "user2",
        kind::USER3 => "user3",
        kind::HEADER => "header",
        kind::WARNING => "warning",
        kind::WARNINGHEADER => "warningheader",
        _ => return Err(SymbolError::CommentTypeValue),
    })
}

/// One comment (Ghidra `Comment`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comment {
    /// The type bits.
    pub kind: u32,
    /// The function the comment belongs to.
    pub func_addr: Address,
    /// The address the comment is attached to.
    pub addr: Address,
    /// The sub-sort among comments at one address.
    pub uniq: u32,
    /// The text.
    pub text: String,
    /// Whether the printer emitted it.
    pub emitted: bool,
}

type Key = (Address, Address, u32);

/// Comments ordered by function address, address and `uniq` (Ghidra
/// `CommentDatabaseInternal`).
#[derive(Clone, Debug, Default)]
pub struct CommentDb {
    comments: BTreeMap<Key, Comment>,
}

/// The highest `uniq` Ghidra's look-ups use as a bound.
const UNIQ_BOUND: u32 = 65535;

impl CommentDb {
    /// An empty database.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of comments.
    pub fn len(&self) -> usize {
        self.comments.len()
    }

    /// Whether there are no comments.
    pub fn is_empty(&self) -> bool {
        self.comments.is_empty()
    }

    /// Removes every comment (Ghidra `clear`).
    pub fn clear(&mut self) {
        self.comments.clear();
    }

    fn insert(&mut self, c: Comment) -> Result<()> {
        let key = (c.func_addr, c.addr, c.uniq);
        if self.comments.contains_key(&key) {
            // Ghidra's set refuses it silently and leaks it (spec 4.21 #17).
            return Err(SymbolError::CommentKey);
        }
        self.comments.insert(key, c);
        Ok(())
    }

    /// Ghidra `addComment`: `uniq` is one past the last comment at the same
    /// place below the bound, else 0.
    pub fn add_comment(
        &mut self,
        kind: u32,
        func_addr: Address,
        addr: Address,
        text: &str,
    ) -> Result<()> {
        let bound: Key = (func_addr, addr, UNIQ_BOUND);
        // lower_bound then one back: the last element below the bound, or the
        // first element when the bound is first.
        let prev = match self.comments.range(..bound).next_back() {
            Some((k, _)) => Some(*k),
            None => self.comments.keys().next().copied(),
        };
        let uniq = match prev {
            Some((f, a, u)) if f == func_addr && a == addr => u.wrapping_add(1),
            _ => 0,
        };
        self.insert(Comment {
            kind,
            func_addr,
            addr,
            uniq,
            text: text.to_owned(),
            emitted: false,
        })
    }

    /// Ghidra `addCommentNoDuplicate`: `false` when a comment at the same
    /// place has the same text.
    pub fn add_comment_no_duplicate(
        &mut self,
        kind: u32,
        func_addr: Address,
        addr: Address,
        text: &str,
    ) -> Result<bool> {
        let bound: Key = (func_addr, addr, UNIQ_BOUND);
        let mut uniq = 0;
        for ((f, a, u), c) in self.comments.range(..bound).rev() {
            if *f != func_addr || *a != addr {
                break;
            }
            if c.text == text {
                return Ok(false);
            }
            if uniq == 0 {
                uniq = u.wrapping_add(1);
            }
        }
        self.insert(Comment {
            kind,
            func_addr,
            addr,
            uniq,
            text: text.to_owned(),
            emitted: false,
        })?;
        Ok(true)
    }

    /// Ghidra `clearType`: removes the function's comments having a bit of
    /// `mask`.
    pub fn clear_type(&mut self, func_addr: Address, mask: u32) {
        let doomed: Vec<Key> = self
            .function_range(func_addr)
            .filter(|c| c.kind & mask != 0)
            .map(|c| (c.func_addr, c.addr, c.uniq))
            .collect();
        for k in doomed {
            self.comments.remove(&k);
        }
    }

    /// Ghidra `deleteComment`.
    pub fn delete_comment(
        &mut self,
        func_addr: Address,
        addr: Address,
        uniq: u32,
    ) -> Option<Comment> {
        self.comments.remove(&(func_addr, addr, uniq))
    }

    /// The comments of a function in order (Ghidra `beginComment` to
    /// `endComment`).
    pub fn function_range(&self, func_addr: Address) -> impl Iterator<Item = &Comment> {
        let lo: Key = (func_addr, Address::MINIMAL, 0);
        let hi: Key = (func_addr, Address::MAXIMAL, UNIQ_BOUND);
        self.comments
            .range((Bound::Included(lo), Bound::Excluded(hi)))
            .map(|(_, c)| c)
    }

    /// Every comment in order.
    pub fn iter(&self) -> impl Iterator<Item = &Comment> {
        self.comments.values()
    }

    /// Marks a comment emitted.
    pub fn set_emitted(&mut self, func_addr: Address, addr: Address, uniq: u32, emitted: bool) {
        if let Some(c) = self.comments.get_mut(&(func_addr, addr, uniq)) {
            c.emitted = emitted;
        }
    }

    /// Ghidra `encode`: `<commentdb>` of `<comment type>` elements.
    pub fn encode(&self, enc: &mut dyn Encoder, spaces: &SpaceManager) -> Result<()> {
        enc.open_element(ELEM_COMMENTDB);
        for c in self.comments.values() {
            enc.open_element(ELEM_COMMENT);
            enc.write_string(ATTRIB_TYPE, comment_type_name(c.kind)?)?;
            for a in [c.func_addr, c.addr] {
                enc.open_element(bk_core::ids::ELEM_ADDR);
                if let Some(space) = a.space() {
                    spaces.encode_attributes(enc, space, a.offset())?;
                }
                enc.close_element(bk_core::ids::ELEM_ADDR);
            }
            enc.open_element(ELEM_TEXT);
            enc.write_string(ATTRIB_CONTENT, &c.text)?;
            enc.close_element(ELEM_TEXT);
            enc.close_element(ELEM_COMMENT);
        }
        enc.close_element(ELEM_COMMENTDB);
        Ok(())
    }

    /// Ghidra `decode`: each comment goes through `add_comment`, so `uniq`s
    /// are renumbered.
    pub fn decode(&mut self, dec: &mut dyn Decoder<'_>, spaces: &SpaceManager) -> Result<()> {
        let el = dec.open_element_expecting(ELEM_COMMENTDB)?;
        while dec.peek_element().is_some() {
            let c = dec.open_element_expecting(ELEM_COMMENT)?;
            let kind = comment_type_by_name(dec.read_string_attr(ATTRIB_TYPE)?)?;
            let func_addr = Address::decode(dec, spaces)?;
            let addr = Address::decode(dec, spaces)?;
            let mut text = String::new();
            if let Some(sub) = dec.open_element()? {
                text = dec.read_string_attr(ATTRIB_CONTENT)?.to_owned();
                dec.close_element(sub)?;
            }
            dec.close_element(c)?;
            self.add_comment(kind, func_addr, addr, &text)?;
        }
        dec.close_element(el)?;
        Ok(())
    }
}
