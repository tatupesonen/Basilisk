//! Random control-flow graphs for the structurer commands' cross-checks
//! (`docs/features/decomp-oracle.md` 6.4): the shape of
//! `docs/research/decomp-wave1/gen_graphs.py` (run R3), from a small
//! deterministic generator so that a seed names the same graph on every
//! machine. A graph is written both as Ghidra's XML (what `structure blocks`
//! reads) and as a graph file with neutral facts (what `bk structure` reads;
//! [`GraphFile::from_out_edges`]).

use super::graph::GraphFile;

/// `SplitMix64`: a tiny, well-mixed, platform-independent generator. Written
/// here rather than taken from `rand` because only this deterministic stream
/// is needed and it must never change under a dependency update.
#[derive(Debug, Clone)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    /// A generator whose stream is fixed by `seed`.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value in `0..n` (`n > 0`; 0 when `n` is 0).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        // Lemire's multiply-shift; the bias is far below what a test notices.
        let wide = u128::from(self.next_u64()) * u128::from(n);
        u64::try_from(wide >> 64).unwrap_or(0)
    }
}

/// The out-edge lists of one random graph of 1..=`max_nodes` nodes: each
/// node has no successor with probability 0.10, one with 0.45, two with
/// 0.35, and three to six (a switch) otherwise; targets are uniform, so
/// multi-edges, self-loops, unreachable parts and edges into node 0 occur.
pub fn random_out_edges(rng: &mut SplitMix64, max_nodes: usize) -> Vec<Vec<u32>> {
    let max = u64::try_from(max_nodes.max(1)).unwrap_or(u64::MAX);
    let n = rng.below(max) + 1;
    (0..n)
        .map(|_| {
            let r = rng.below(100);
            let k = match r {
                0..=9 => 0,
                10..=54 => 1,
                55..=89 => 2,
                _ => 3 + rng.below(4),
            };
            (0..k)
                .map(|_| u32::try_from(rng.below(n)).unwrap_or(0))
                .collect()
        })
        .collect()
}

/// `count` random graphs from `seed`, as graph files with neutral facts.
pub fn random_graphs(seed: u64, count: usize, max_nodes: usize) -> Vec<GraphFile> {
    let mut rng = SplitMix64::new(seed);
    (0..count)
        .filter_map(|_| GraphFile::from_out_edges(&random_out_edges(&mut rng, max_nodes), &[]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_is_fixed() {
        let mut rng = SplitMix64::new(1);
        // Reference values of SplitMix64 for seed 1.
        assert_eq!(rng.next_u64(), 0x910a_2dec_8902_5cc1);
        assert_eq!(rng.next_u64(), 0xbeeb_8da1_658e_ec67);
        assert!((0..1000).all(|_| rng.below(7) < 7));
        assert_eq!(rng.below(0), 0);
    }

    #[test]
    fn graphs_are_valid_and_reproducible() {
        let a = random_graphs(7, 200, 40);
        assert_eq!(a.len(), 200);
        assert_eq!(a, random_graphs(7, 200, 40));
        for g in &a {
            assert!((1..=40).contains(&g.nodes.len()));
            assert_eq!(GraphFile::parse(&g.write()).unwrap(), *g);
        }
        let switches = a
            .iter()
            .flat_map(GraphFile::out_edges)
            .filter(|outs| outs.len() >= 3)
            .count();
        assert!(switches > 0);
    }
}
