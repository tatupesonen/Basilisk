//! Spec 6.4, the `log` table: glibc's `log(k/n)` for every
//! `1 <= k < n <= 16384`, hashed per `n` as
//! `tools/sla-host-diff/containers/logtable/logtable.c` does, must equal
//! the checked-in table. Oracle-free; runs on every platform.

use std::io::Read as _;

use super::log::log;

#[test]
fn log_equals_glibc_on_every_score_argument() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/research/sla-host-dependence/logtable-glibc.txt.gz");
    let file = std::fs::File::open(&path).expect("the log table is checked in");
    let mut text = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut text)
        .expect("gzip text");
    let mut lines = text.lines();
    let first = lines.next().expect("log2 line");
    assert_eq!(first, format!("log2 {:016x}", log(2.0).to_bits()));
    let mut checked = 0;
    let mut wrong = Vec::new();
    for line in lines {
        let (n, hash) = line.split_once(' ').expect("n hash");
        let n: u32 = n.parse().expect("n");
        let mut h: u64 = 1_469_598_103_934_665_603;
        for k in 1..n {
            let p = f64::from(k) / f64::from(n);
            h = (h ^ log(p).to_bits()).wrapping_mul(1_099_511_628_211);
        }
        if format!("{h:016x}") != hash {
            wrong.push(n);
        }
        checked += 1;
    }
    assert_eq!(checked, 16_383);
    assert_eq!(
        wrong,
        Vec::<u32>::new(),
        "{} values of n differ",
        wrong.len()
    );
}
