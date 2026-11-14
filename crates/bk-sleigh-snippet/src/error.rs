//! Why a snippet did not compile.

/// A failed compile, in the two forms Ghidra's `parseInject` fails in.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SnippetError {
    /// The compiler refused the snippet (`PcodeSnippet::parseStream`
    /// returned false: a syntax error, an error of a grammar rule, or sizes
    /// that could not be resolved). `messages` holds every error in the
    /// order found; Ghidra reports only the first.
    #[error("Unable to compile pcode: {}", messages.first().map_or("", String::as_str))]
    Rejected {
        /// The errors, in order; never empty.
        messages: Vec<String>,
    },
    /// The compiler stopped with an exception (`SleighError` from
    /// `PcodeCompile`: "Requested bit range out of bounds", "Could not
    /// construct requested bit range", "Localtemp size mismatch",
    /// "Expression has no output"). Ghidra lets it escape `parseInject` as
    /// it is, without the "Unable to compile pcode" prefix.
    #[error("{message}")]
    Aborted {
        /// The exception's message.
        message: String,
        /// Errors reported before it, which Ghidra does not show.
        earlier: Vec<String>,
    },
    /// The text is longer than [`Options::max_text_len`](crate::Options).
    /// Ghidra has no such limit.
    #[error("p-code snippet of {len} bytes exceeds the limit of {limit} bytes")]
    TooLong {
        /// The text's length in bytes.
        len: usize,
        /// The limit.
        limit: usize,
    },
}

impl SnippetError {
    /// The message Ghidra's injection library throws for a payload
    /// described as `source` (`PcodeInjectLibrarySleigh::parseInject`):
    /// `<source>: Unable to compile pcode: <first error>`, or the exception's
    /// message alone.
    pub fn ghidra_message(&self, source: &str) -> String {
        match self {
            Self::Rejected { .. } | Self::TooLong { .. } => format!("{source}: {self}"),
            Self::Aborted { message, .. } => message.clone(),
        }
    }

    /// Every message, in the order found.
    pub fn messages(&self) -> Vec<String> {
        match self {
            Self::Rejected { messages } => messages.clone(),
            Self::Aborted { message, earlier } => {
                let mut all = earlier.clone();
                all.push(message.clone());
                all
            }
            Self::TooLong { .. } => vec![self.to_string()],
        }
    }
}
