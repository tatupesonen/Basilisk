//! Unit tests of the entry map are in `tests/entrymap_props.rs` (property
//! test against a transliteration) and below.

use super::*;

#[test]
fn empty_map_answers_nothing() {
    let map: EntryMap<u32, u64, EntrySubsort> = EntryMap::new();
    assert!(map.is_empty());
    assert_eq!(map.find(3).count(), 0);
    assert!(map.find_end(3).is_none());
    assert!(map.find_last_before(3).is_none());
    assert!(map.find_first_after(3).is_none());
    assert!(map.find_overlap(0, u64::MAX).is_none());
}

#[test]
fn top_of_the_domain_and_null_subsorts() {
    let mut map: EntryMap<u32, u64, NullSubsort> = EntryMap::new();
    let r = map.insert(1, u64::MAX - 1, u64::MAX, NullSubsort);
    let s = map.insert(2, 0, 0, NullSubsort);
    map.insert(3, u64::MAX, u64::MAX, NullSubsort);
    assert_eq!(
        map.find(u64::MAX).map(|f| f.value).collect::<Vec<_>>(),
        [3, 1, 3]
    );
    assert_eq!(map.bounds(r), Some((u64::MAX - 1, u64::MAX)));
    map.erase(s);
    map.erase(s);
    assert_eq!(map.value(s), None);
    map.erase(r);
    assert_eq!(map.find(u64::MAX - 1).count(), 0);
    assert_eq!(map.len(), 1);
    map.clear();
    assert!(map.is_empty());
}
