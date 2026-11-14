//! Shared by the `bk_testkit_*` targets: the input is either a text of its
//! own (first byte 0) or a list of edits applied to a real sample of the
//! format (any other first byte), so that the fuzzer reaches the deep
//! records of formats whose headers it would rarely guess.

/// The text to parse: `data[1..]` when `data[0] == 0`, else `sample` edited
/// by the operations `data` encodes (each four bytes: kind, position high,
/// position low, argument).
pub fn text(data: &[u8], sample: &str) -> Option<String> {
    match data.split_first() {
        None => Some(String::new()),
        Some((0, rest)) => std::str::from_utf8(rest).ok().map(str::to_owned),
        Some((_, ops)) => {
            let mut bytes = sample.as_bytes().to_vec();
            for op in ops.chunks_exact(4) {
                let len = bytes.len().max(1);
                let pos = (usize::from(op[1]) << 8 | usize::from(op[2])) * 37 % len;
                match op[0] % 6 {
                    0 => {
                        let end = (pos + usize::from(op[3])).min(bytes.len());
                        bytes.drain(pos.min(end)..end);
                    }
                    1 => bytes.insert(pos.min(bytes.len()), op[3]),
                    2 => {
                        if let Some(b) = bytes.get_mut(pos) {
                            *b = op[3];
                        }
                    }
                    3 => bytes.truncate(pos),
                    4 => {
                        // Duplicate the line at pos.
                        let start = bytes[..pos.min(bytes.len())].iter().rposition(|&b| b == b'\n').map_or(0, |p| p + 1);
                        let end = bytes[start..].iter().position(|&b| b == b'\n').map_or(bytes.len(), |p| start + p + 1);
                        let line = bytes[start..end].to_vec();
                        bytes.splice(end..end, line);
                    }
                    _ => {
                        // Put a digit, tab or separator where it may matter.
                        let pick = b"0189af-\t,:x\n"[usize::from(op[3]) % 12];
                        if let Some(b) = bytes.get_mut(pos) {
                            *b = pick;
                        }
                    }
                }
            }
            String::from_utf8(bytes).ok()
        }
    }
}
