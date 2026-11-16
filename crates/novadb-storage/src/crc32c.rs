//! CRC-32C (Castagnoli), slicing-by-8, table generated at compile time.
//! Used for page and WAL record checksums (detects torn writes and bit rot; not a MAC).

const POLY: u32 = 0x82F6_3B78; // reflected 0x1EDC6F41

const fn make_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut i = 0;
    while i < 256 {
        let mut s = 1;
        while s < 8 {
            let prev = t[s - 1][i];
            t[s][i] = (prev >> 8) ^ t[0][(prev & 0xFF) as usize];
            s += 1;
        }
        i += 1;
    }
    t
}

static TABLES: [[u32; 256]; 8] = make_tables();

/// Incremental CRC-32C state.
#[derive(Clone, Copy, Debug)]
pub struct Crc32c(u32);

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32c {
    /// New hasher.
    pub const fn new() -> Self {
        Crc32c(!0)
    }

    /// Feed bytes.
    pub fn update(&mut self, data: &[u8]) {
        let t = &TABLES;
        let mut crc = self.0;
        let (chunks, rem) = data.as_chunks::<8>();
        for c in chunks {
            let lo = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) ^ crc;
            let hi = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
            crc = t[7][(lo & 0xFF) as usize]
                ^ t[6][((lo >> 8) & 0xFF) as usize]
                ^ t[5][((lo >> 16) & 0xFF) as usize]
                ^ t[4][(lo >> 24) as usize]
                ^ t[3][(hi & 0xFF) as usize]
                ^ t[2][((hi >> 8) & 0xFF) as usize]
                ^ t[1][((hi >> 16) & 0xFF) as usize]
                ^ t[0][(hi >> 24) as usize];
        }
        for &b in rem {
            crc = (crc >> 8) ^ t[0][((crc ^ b as u32) & 0xFF) as usize];
        }
        self.0 = crc;
    }

    /// Final value.
    pub fn finish(self) -> u32 {
        !self.0
    }
}

/// One-shot CRC-32C.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut h = Crc32c::new();
    h.update(data);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bitwise(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ POLY
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[test]
    fn known_vectors() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
    }

    #[test]
    fn matches_bitwise_and_incremental() {
        let data: Vec<u8> = (0..1000u32)
            .map(|i| (i.wrapping_mul(31) ^ (i >> 3)) as u8)
            .collect();
        for len in [0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 999, 1000] {
            assert_eq!(crc32c(&data[..len]), bitwise(&data[..len]), "len {len}");
        }
        let mut h = Crc32c::new();
        for part in data.chunks(13) {
            h.update(part);
        }
        assert_eq!(h.finish(), crc32c(&data));
    }
}
