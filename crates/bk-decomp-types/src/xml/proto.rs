//! The `<prototype>` element of a function type (Ghidra `FuncProto::encode`,
//! `FuncProto::decode`, `ProtoStoreInternal::encode`/`decode`), reduced to
//! the signature this crate holds (spec 4.7). Storage (addresses, effects,
//! extrapop) belongs to the prototype models of `bk-cspec`, which plugs in
//! through [`PrototypeCodec`].

use bk_marshal::ids::{
    ATTRIB_CONSTRUCTOR, ATTRIB_DESTRUCTOR, ATTRIB_EXTRAPOP, ATTRIB_HIDDENRETPARM, ATTRIB_MODEL,
    ATTRIB_NAME,
};
use bk_marshal::{Decoder, Encoder};

use crate::entry::{CodeSignature, sigflags};
use crate::error::{Result, TypeError};
use crate::factory::TypeFactory;
use crate::xml::ids::{
    ATTRIB_DOTDOTDOT, ATTRIB_FIRST, ELEM_ADDR, ELEM_INTERNALLIST, ELEM_PARAM, ELEM_PROTOTYPE,
    ELEM_RETURNSYM,
};

/// Reads and writes the `<prototype>` of a function type.
pub trait PrototypeCodec: Send + Sync {
    /// Writes the `<prototype>` element for a signature.
    fn encode(&self, f: &TypeFactory, enc: &mut dyn Encoder, sig: &CodeSignature) -> Result<()>;
    /// Reads a `<prototype>` element into a signature.
    fn decode<'a>(&self, f: &mut TypeFactory, dec: &mut dyn Decoder<'a>) -> Result<CodeSignature>;
}

/// The codec used when none is installed: it keeps the signature and drops
/// storage. It writes `<prototype>` with the model, `extrapop="unknown"`,
/// the flags, `<returnsym>` and an `<internallist>` of `<param>`s, each
/// with an empty `<addr/>`; it reads the same elements from Ghidra's form
/// and skips everything else (effects, likely-trash, inject, storage).
#[derive(Clone, Copy, Debug, Default)]
pub struct SignatureCodec;

impl PrototypeCodec for SignatureCodec {
    fn encode(&self, f: &TypeFactory, enc: &mut dyn Encoder, sig: &CodeSignature) -> Result<()> {
        enc.open_element(ELEM_PROTOTYPE);
        enc.write_string(ATTRIB_MODEL, sig.model.as_deref().unwrap_or("default"))?;
        enc.write_string(ATTRIB_EXTRAPOP, "unknown")?;
        if sig.flags & sigflags::DOTDOTDOT != 0 {
            enc.write_bool(ATTRIB_DOTDOTDOT, true);
        }
        if sig.flags & sigflags::IS_CONSTRUCTOR != 0 {
            enc.write_bool(ATTRIB_CONSTRUCTOR, true);
        }
        if sig.flags & sigflags::IS_DESTRUCTOR != 0 {
            enc.write_bool(ATTRIB_DESTRUCTOR, true);
        }
        enc.open_element(ELEM_RETURNSYM);
        f.encode_address(enc, None)?;
        match sig.output {
            Some(o) => f.encode_ref(enc, o)?,
            None => {
                enc.open_element(bk_marshal::ids::ELEM_VOID);
                enc.close_element(bk_marshal::ids::ELEM_VOID);
            }
        }
        enc.close_element(ELEM_RETURNSYM);
        enc.open_element(ELEM_INTERNALLIST);
        if sig.first_vararg >= 0 {
            enc.write_signed(ATTRIB_FIRST, i64::from(sig.first_vararg));
        }
        for (ty, name) in &sig.params {
            enc.open_element(ELEM_PARAM);
            if !name.is_empty() {
                enc.write_string(ATTRIB_NAME, name)?;
            }
            f.encode_address(enc, None)?;
            f.encode_ref(enc, *ty)?;
            enc.close_element(ELEM_PARAM);
        }
        enc.close_element(ELEM_INTERNALLIST);
        enc.close_element(ELEM_PROTOTYPE);
        Ok(())
    }

    fn decode<'a>(&self, f: &mut TypeFactory, dec: &mut dyn Decoder<'a>) -> Result<CodeSignature> {
        let elem = dec.open_element_expecting(ELEM_PROTOTYPE)?;
        let mut sig = CodeSignature {
            first_vararg: -1,
            ..CodeSignature::default()
        };
        let mut model: Option<String> = None;
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_MODEL {
                model = Some(dec.read_string()?.to_owned());
            } else if attr == ATTRIB_DOTDOTDOT {
                if dec.read_bool()? {
                    sig.flags |= sigflags::DOTDOTDOT;
                }
            } else if attr == ATTRIB_CONSTRUCTOR {
                if dec.read_bool()? {
                    sig.flags |= sigflags::IS_CONSTRUCTOR;
                }
            } else if attr == ATTRIB_DESTRUCTOR && dec.read_bool()? {
                sig.flags |= sigflags::IS_DESTRUCTOR;
            }
        }
        sig.model = match model.as_deref() {
            None | Some("" | "default") => f.env.default_model.clone().map(String::into_boxed_str),
            Some(m) => Some(m.into()),
        };
        let first = dec.peek_element();
        if first == Some(ELEM_RETURNSYM.code()) {
            let sub = dec
                .open_element()?
                .ok_or_else(|| TypeError::new("Missing <returnsym> tag"))?;
            dec.skip_element()?; // <addr>
            sig.output = Some(f.decode_type(dec)?);
            dec.close_element(sub)?;
        } else if first == Some(ELEM_ADDR.code()) {
            dec.skip_element()?;
            sig.output = Some(f.decode_type(dec)?);
        } else {
            return Err(TypeError::new("Missing <returnsym> tag"));
        }
        while let Some(sub) = dec.peek_element() {
            if sub != ELEM_INTERNALLIST.code() {
                dec.skip_element()?;
                continue;
            }
            let list = dec
                .open_element()?
                .ok_or_else(|| TypeError::new("Missing <internallist>"))?;
            while let Some(attr) = dec.next_attribute()? {
                if attr == ATTRIB_FIRST {
                    sig.first_vararg = dec.read_signed()? as i32;
                }
            }
            while let Some(p) = dec.open_element()? {
                let mut name = String::new();
                let mut hidden = false;
                while let Some(attr) = dec.next_attribute()? {
                    if attr == ATTRIB_NAME {
                        name = dec.read_string()?.to_owned();
                    } else if attr == ATTRIB_HIDDENRETPARM {
                        hidden = dec.read_bool()?;
                    }
                }
                dec.skip_element()?; // <addr>
                let ty = f.decode_type(dec)?;
                dec.close_element(p)?;
                if p == ELEM_PARAM.code() && !hidden {
                    sig.params.push((ty, name.into()));
                }
            }
            dec.close_element(list)?;
        }
        dec.close_element(elem)?;
        Ok(sig)
    }
}

impl TypeFactory {
    /// Writes a signature through the installed codec (or
    /// [`SignatureCodec`]).
    pub(crate) fn encode_signature(
        &self,
        enc: &mut dyn Encoder,
        sig: &CodeSignature,
        _depth: usize,
    ) -> Result<()> {
        match self.hooks.prototypes.clone() {
            Some(codec) => codec.encode(self, enc, sig),
            None => SignatureCodec.encode(self, enc, sig),
        }
    }

    /// Reads a signature through the installed codec (or
    /// [`SignatureCodec`]).
    pub(crate) fn decode_signature<'a>(
        &mut self,
        dec: &mut dyn Decoder<'a>,
    ) -> Result<CodeSignature> {
        match self.hooks.prototypes.clone() {
            Some(codec) => codec.decode(self, dec),
            None => SignatureCodec.decode(self, dec),
        }
    }
}
