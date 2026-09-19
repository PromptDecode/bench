//! Dependency-free SHA-256, implemented exactly as specified in FIPS 180-4.
//!
//! A repository whose whole point is auditability should not need a binary
//! blob (or even a third-party crate) to hash its own corpus. This is ~80
//! lines of well-specified, well-tested code instead of a dependency.
//!
//! Only the bare incremental API is exposed: [`Sha256::new`], [`Sha256::update`],
//! [`Sha256::finalize`], plus the one-shot convenience [`sha256`] and
//! [`to_hex`].

/// Round constants K[0..64] from FIPS 180-4 section 4.2.2 (fractional parts
/// of the cube roots of the first 64 primes).
const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Initial hash value H[0..8] from FIPS 180-4 section 5.3.3 (fractional parts
/// of the square roots of the first 8 primes).
const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// An incremental SHA-256 hasher.
#[derive(Debug, Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_bytes: u64,
}

impl Sha256 {
    /// Creates a fresh hasher.
    pub fn new() -> Self {
        Sha256 {
            state: INITIAL_STATE,
            buf: [0u8; 64],
            buf_len: 0,
            total_bytes: 0,
        }
    }

    /// Feeds more data into the hasher. May be called any number of times;
    /// the result is independent of how the input was chunked.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Pads, processes the final block(s), and returns the 32-byte digest.
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_bytes.wrapping_mul(8);
        self.push_byte(0x80);
        while self.buf_len != 56 {
            self.push_byte(0x00);
        }
        let mut block = self.buf;
        block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        self.compress(&block);
        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Appends one byte to the internal buffer, compressing when it fills.
    /// Used by [`Sha256::finalize`] for padding; deliberately does not touch
    /// `total_bytes`, since padding is not message data.
    fn push_byte(&mut self, byte: u8) {
        self.buf[self.buf_len] = byte;
        self.buf_len += 1;
        if self.buf_len == 64 {
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
        }
    }

    /// Runs the 64-round compression function over one 512-bit block.
    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(ROUND_CONSTANTS[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        let final_state = [a, b, c, d, e, f, g, h];
        for (slot, value) in self.state.iter_mut().zip(final_state) {
            *slot = slot.wrapping_add(value);
        }
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256::new()
    }
}

/// One-shot convenience: SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Lowercase hexadecimal rendering of a byte string (no separators).
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(data: &[u8]) -> String {
        to_hex(&sha256(data))
    }

    #[test]
    fn fips_vector_empty_string() {
        assert_eq!(
            hex_of(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn fips_vector_abc() {
        assert_eq!(
            hex_of(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn fips_vector_896_bit_message() {
        // The two-block 896-bit message from FIPS 180-4 appendix B.2.
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            hex_of(msg),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn chunked_update_matches_one_shot() {
        // Padding has to cope with a message that straddles block boundaries
        // at every awkward offset, so sweep all of them.
        let data: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        let whole = sha256(&data);
        for split in [0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 999, 1000] {
            let mut hasher = Sha256::new();
            hasher.update(&data[..split]);
            hasher.update(&data[split..]);
            assert_eq!(hasher.finalize(), whole, "mismatch when split at {split}");
        }
    }
}
