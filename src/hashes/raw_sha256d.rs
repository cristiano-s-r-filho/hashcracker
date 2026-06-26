use sha2::{Digest, Sha256};

use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawSha256d;

impl HashModule for RawSha256d {
    fn name(&self) -> &'static str { "raw-sha256d" }
    fn mode(&self) -> u32 { 1411 }
    fn digest_words(&self) -> u32 { 8 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        let mut h1 = Sha256::new();
        h1.update(password.as_bytes());
        h1.update(salt);
        let r1 = h1.finalize();
        let mut h2 = Sha256::new();
        h2.update(&r1);
        let r2 = h2.finalize();
        let mut computed = [0u32; 8];
        for i in 0..8 {
            computed[i] = u32::from_be_bytes(r2[i * 4..i * 4 + 4].try_into().unwrap());
        }
        computed == hash
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../sha256d_crack.wgsl"),
            AttackModeType::Mask => include_str!("../sha256d_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../sha256d_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(64), priority: 90 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if clean.len() != 64 {
            return Err(format!("Expected 64 hex chars for SHA-256d, got {}", clean.len()));
        }
        let mut target = [0u32; 8];
        for i in 0..8 {
            target[i] = u32::from_str_radix(&clean[i * 8..i * 8 + 8], 16)
                .map_err(|_| format!("Invalid hex at position {}", i * 8))?;
        }
        Ok(ParsedHash {
            hash_words: target,
            extra_words: [0u32; 8],
            salt: Vec::new(),
            digest_words: 8,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sha256d_roundtrip() {
        let m = RawSha256d;
        let pw = "abc";
        let mut h1 = sha2::Sha256::new();
        h1.update(pw.as_bytes());
        h1.update(b"");
        let r1 = h1.finalize();
        let mut h2 = sha2::Sha256::new();
        h2.update(&r1);
        let r2 = h2.finalize();
        let hex_str = hex::encode(r2);
        let parsed = m.parse_hash_string(&hex_str).unwrap();
        assert!(m.cpu_verify(pw, &[], &parsed.hash_words));
    }
}
