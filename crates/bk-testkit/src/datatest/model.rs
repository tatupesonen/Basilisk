//! The contents of one `<decompilertest>` file.

use std::fmt::Write as _;

/// One decompiler data test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataTest {
    /// The program the script runs on.
    pub image: BinaryImage,
    /// The console commands, in order, one per `<com>` element. Line breaks
    /// inside a command are already folded to spaces, as Ghidra does.
    pub script: Vec<String>,
    /// The checks applied to the script's bulk output.
    pub matches: Vec<StringMatch>,
}

/// A `<binaryimage>`: bytes at addresses, plus loader symbols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryImage {
    /// The architecture: a language id followed by a compiler-spec id, for
    /// example `x86:LE:64:default:gcc`.
    pub arch: String,
    /// The initialised memory, in file order.
    pub chunks: Vec<ByteChunk>,
    /// Names for addresses (function entry points, globals), in file order.
    pub symbols: Vec<ImageSymbol>,
}

/// A `<bytechunk>`: consecutive bytes starting at one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteChunk {
    /// Name of the address space, for example `ram`.
    pub space: String,
    /// Offset of the first byte within the space.
    pub offset: u64,
    /// Whether the chunk is marked read-only, which lets the decompiler
    /// treat its contents as constants.
    pub readonly: bool,
    /// The bytes.
    pub bytes: Vec<u8>,
}

/// A `<symbol>`: a name for one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSymbol {
    /// Name of the address space.
    pub space: String,
    /// Offset within the space.
    pub offset: u64,
    /// The symbol's name.
    pub name: String,
}

/// A `<stringmatch>`: a pattern and how often it must match.
///
/// The pattern is one regular expression per line (ECMAScript syntax, as
/// `std::regex` reads it). A single-line pattern counts the output lines it
/// matches; a multi-line pattern counts the places where consecutive output
/// lines match its lines in order. The check passes when the count is within
/// `min..=max`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringMatch {
    /// The check's name, as the test runner reports it.
    pub name: String,
    /// Fewest matches that pass.
    pub min: u32,
    /// Most matches that pass.
    pub max: u32,
    /// The regular expressions, one per pattern line, leading blanks removed.
    pub lines: Vec<String>,
}

impl StringMatch {
    /// Whether `count` matches satisfy this check.
    pub fn accepts(&self, count: u32) -> bool {
        (self.min..=self.max).contains(&count)
    }
}

impl BinaryImage {
    /// The language id: `arch` without its trailing compiler-spec id.
    pub fn language_id(&self) -> &str {
        match self.arch.match_indices(':').nth(3) {
            Some((index, _)) => self.arch.get(..index).unwrap_or(&self.arch),
            None => &self.arch,
        }
    }

    /// Total number of bytes in all chunks.
    pub fn byte_count(&self) -> usize {
        self.chunks.iter().map(|chunk| chunk.bytes.len()).sum()
    }

    /// Write the image as a standalone `<binaryimage>` document, the form
    /// Ghidra's console loads with `load file`.
    pub fn to_xml(&self) -> String {
        let mut xml = String::new();
        let _ = writeln!(xml, "<binaryimage arch=\"{}\">", escape(&self.arch));
        for chunk in &self.chunks {
            let _ = write!(
                xml,
                "<bytechunk space=\"{}\" offset=\"{:#x}\"",
                escape(&chunk.space),
                chunk.offset
            );
            if chunk.readonly {
                xml.push_str(" readonly=\"true\"");
            }
            xml.push_str(">\n");
            for row in chunk.bytes.chunks(16) {
                for byte in row {
                    let _ = write!(xml, "{byte:02x}");
                }
                xml.push('\n');
            }
            xml.push_str("</bytechunk>\n");
        }
        for symbol in &self.symbols {
            let _ = writeln!(
                xml,
                "<symbol space=\"{}\" offset=\"{:#x}\" name=\"{}\"/>",
                escape(&symbol.space),
                symbol.offset,
                escape(&symbol.name)
            );
        }
        xml.push_str("</binaryimage>\n");
        xml
    }
}

/// Escape a string for use inside a double-quoted XML attribute.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(arch: &str) -> BinaryImage {
        BinaryImage {
            arch: arch.to_owned(),
            chunks: Vec::new(),
            symbols: Vec::new(),
        }
    }

    #[test]
    fn language_id_drops_the_compiler() {
        assert_eq!(
            image("x86:LE:64:default:gcc").language_id(),
            "x86:LE:64:default"
        );
        assert_eq!(
            image("x86:LE:64:default").language_id(),
            "x86:LE:64:default"
        );
        assert_eq!(image("odd").language_id(), "odd");
    }

    #[test]
    fn match_counts_are_inclusive() {
        let check = StringMatch {
            name: "n".to_owned(),
            min: 1,
            max: 2,
            lines: Vec::new(),
        };
        assert!(!check.accepts(0));
        assert!(check.accepts(1));
        assert!(check.accepts(2));
        assert!(!check.accepts(3));
    }

    #[test]
    fn xml_escapes_names() {
        let mut image = image("a<b");
        image.symbols.push(ImageSymbol {
            space: "ram".to_owned(),
            offset: 0x10,
            name: "operator<<\"&".to_owned(),
        });
        let xml = image.to_xml();
        assert!(xml.contains("arch=\"a&lt;b\""), "{xml}");
        assert!(
            xml.contains("name=\"operator&lt;&lt;&quot;&amp;\""),
            "{xml}"
        );
    }
}
