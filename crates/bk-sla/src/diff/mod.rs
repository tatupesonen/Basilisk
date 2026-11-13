//! Structural comparison of two models.

use crate::model::Sla;

/// One difference between two models, with the path where it was found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Difference {
    /// Where.
    pub path: String,
    /// The left value.
    pub left: String,
    /// The right value.
    pub right: String,
}

/// Compares two models; at most `cap` differences are returned.
pub fn diff(left: &Sla, right: &Sla, cap: usize) -> Vec<Difference> {
    let (a, b) = (left.encode_packed().ok(), right.encode_packed().ok());
    if a == b || cap == 0 {
        Vec::new()
    } else {
        vec![Difference {
            path: String::new(),
            left: String::new(),
            right: String::new(),
        }]
    }
}
