//! Arbitrary bytes as a B+Tree page: decode must never panic; valid nodes must round-trip.
#![no_main]
use libfuzzer_sys::fuzz_target;
use novadb_storage::btree::Node;
use novadb_storage::page::{PAGE_SIZE, new_page_buf};

fuzz_target!(|data: &[u8]| {
    let mut p = new_page_buf();
    let n = data.len().min(PAGE_SIZE);
    p[..n].copy_from_slice(&data[..n]);
    if let Ok(node) = Node::decode(&p) {
        let mut q = p.clone();
        node.encode_into(&mut q).expect("decoded node must re-encode");
        assert_eq!(Node::decode(&q).expect("re-encoded node must decode"), node);
    }
});
