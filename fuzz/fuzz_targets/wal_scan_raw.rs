//! Arbitrary bytes as a WAL file, replayed into a valid empty data file. Must never panic.
//! (Mostly exercises framing/CRC/length handling; see `wal_replay` for CRC-valid input.)
#![no_main]
use libfuzzer_sys::fuzz_target;
use novadb_storage::pager::Pager;
use novadb_storage::recovery::recover;
use novadb_storage::vfs::MemFile;
use novadb_storage::wal::{REC_HEADER_SIZE, WalHeader};

fuzz_target!(|data: &[u8]| {
    // Half the time, prepend a valid header so the record parser is reached.
    let mut wal = Vec::new();
    if data.first().is_some_and(|b| b & 1 == 1) {
        wal.extend_from_slice(&WalHeader { salt: 7, start_lsn: 1, db_id: 1 }.encode());
        wal.extend_from_slice(&data[1..]);
    } else {
        wal.extend_from_slice(data);
    }
    let _ = REC_HEADER_SIZE;
    let mut pager = Pager::new(Box::new(MemFile::default()));
    let _ = recover(&mut MemFile(wal), &mut pager);
});
