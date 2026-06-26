// MD4 hash (hashcat -m 900) = MD4(raw bytes)
pub struct RawMd4;

use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

impl HashModule for RawMd4 {
    fn name(&self) -> &'static str { "md4" }
    fn mode(&self) -> u32 { 900 }
    fn digest_words(&self) -> u32 { 4 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, _salt: &[u8], hash: &[u32]) -> bool {
        let computed = raw_md4(password.as_bytes());
        let mut computed_words = [0u32; 4];
        for i in 0..4 {
            computed_words[i] = u32::from_le_bytes(computed[i * 4..i * 4 + 4].try_into().unwrap());
        }
        computed_words == hash[..4]
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../md4_crack.wgsl"),
            AttackModeType::Mask => include_str!("../md4_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../md4_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(32), priority: 95 }] // Lower priority than MD5 for hex length collision
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if clean.len() != 32 {
            return Err(format!("Expected 32 hex chars for MD4, got {}", clean.len()));
        }
        let mut target = [0u32; 8];
        for i in 0..4 {
            let word = u32::from_str_radix(&clean[i * 8..i * 8 + 8], 16)
                .map_err(|_| format!("Invalid hex at position {}", i * 8))?;
            target[i] = word.swap_bytes();
        }
        Ok(ParsedHash {
            hash_words: target,
            extra_words: [0u32; 8],
            salt: Vec::new(),
            digest_words: 4,
        })
    }
}

/// Pure Rust MD4 hash
pub fn raw_md4(data: &[u8]) -> [u8; 16] {
    use md4::{Md4, Digest};
    let mut hasher = Md4::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

#[test]
fn test_md4_hash_known() {
    // MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
    let hash = raw_md4(b"");
    assert_eq!(hex::encode(hash), "31d6cfe0d16ae931b73c59d7e0c089c0");
}

#[test]
fn test_md4_hash_abc() {
    // MD4("abc") = a448017aaf21d8525fc10ae87aa6729d
    let hash = raw_md4(b"abc");
    assert_eq!(hex::encode(hash), "a448017aaf21d8525fc10ae87aa6729d");
}

#[test]
fn test_md4_hash_password() {
    // MD4("password") - known value
    let hash = raw_md4(b"password");
    assert_eq!(hex::encode(hash), "8a9d093f14f8701df17732b2bb182c74");
}
