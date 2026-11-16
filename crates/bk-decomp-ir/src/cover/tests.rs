//! Covers of hand-built functions, expected from `cover.cc`: `addDefPoint`
//! (501–519), `addRefPoint` (565–600), `addRefRecurse` (524–557) and the
//! text of `Cover::print` / `CoverBlock::print` (615–625, 188–214).

use bk_pcode::OpCode;

use crate::testing::fx;

#[test]
fn a_value_live_across_a_block_covers_it_whole() {
    // 0 → 1 → 2: defined in block 0, read in block 2. The def block runs
    // from the def to the end, block 1 is filled (setAll), block 2 runs from
    // its beginning to the read.
    let mut fix = fx(3);
    let def = fix.emit(0, OpCode::Copy, 0x100, Some(0), &[]);
    let vn = fix.ssa.op_output(def).unwrap();
    fix.emit(1, OpCode::Copy, 0x200, None, &[]);
    let read = fix.emit(2, OpCode::Copy, 0x300, None, &[vn]);
    let d = fix.ssa.op_time(def);
    let r = fix.ssa.op_time(read);
    assert_eq!(
        fix.ssa.print_cover(vn).unwrap(),
        format!("0: 0x00000100:{d:x}-end\n1: begin-end\n2: begin-0x00000300:{r:x}\n")
    );
}

#[test]
fn a_value_read_in_its_own_block_is_a_segment_and_an_input_starts_at_begin() {
    let mut fix = fx(1);
    let x = fix.regvn(0, 4);
    let x = fix.ssa.set_input_varnode(&mut fix.env, x).unwrap();
    let def = fix.emit(0, OpCode::Copy, 0x100, Some(4), &[x]);
    let vn = fix.ssa.op_output(def).unwrap();
    let read = fix.emit(0, OpCode::Copy, 0x104, None, &[vn]);
    let (d, r) = (fix.ssa.op_time(def), fix.ssa.op_time(read));
    assert_eq!(
        fix.ssa.print_cover(vn).unwrap(),
        format!("0: 0x00000100:{d:x}-0x00000104:{r:x}\n")
    );
    // An input's def point is the special mark 2, printed through
    // getUIndex as "begin" (cover.cc:38–39).
    assert_eq!(
        fix.ssa.print_cover(x).unwrap(),
        format!("0: begin-0x00000100:{d:x}\n")
    );
    // A free varnode has no cover (Varnode::hasCover).
    let free = fix.regvn(8, 4);
    assert_eq!(fix.ssa.print_cover(free), None);
}
