use sha1::{Digest, Sha1};

use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawMysql41;

impl HashModule for RawMysql41 {
    fn name(&self) -> &'static str { "mysql41" }
    fn mode(&self) -> u32 { 300 }
    fn digest_words(&self) -> u32 { 5 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        let mut h1 = Sha1::new();
        h1.update(password.as_bytes());
        h1.update(salt);
        let r1 = h1.finalize();
        let mut h2 = Sha1::new();
        h2.update(&r1);
        let r2 = h2.finalize();
        let mut computed = [0u32; 8];
        for i in 0..5 {
            computed[i] = u32::from_be_bytes(r2[i * 4..i * 4 + 4].try_into().unwrap());
        }
        computed[..5] == hash[..5]
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../mysql41_crack.wgsl"),
            AttackModeType::Mask => include_str!("../mysql41_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../mysql41_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(40), priority: 90 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if clean.len() != 40 {
            return Err(format!("Expected 40 hex chars for MySQL4.1, got {}", clean.len()));
        }
        let mut target = [0u32; 8];
        for i in 0..5 {
            target[i] = u32::from_str_radix(&clean[i * 8..i * 8 + 8], 16)
                .map_err(|_| format!("Invalid hex at position {}", i * 8))?;
        }
        Ok(ParsedHash {
            hash_words: target,
            extra_words: [0u32; 8],
            salt: Vec::new(),
            digest_words: 5,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mysql41_roundtrip() {
        let m = RawMysql41;
        let pw = "abc";
        let mut h1 = sha1::Sha1::new();
        h1.update(pw.as_bytes());
        h1.update(b"");
        let r1 = h1.finalize();
        let mut h2 = sha1::Sha1::new();
        h2.update(&r1);
        let r2 = h2.finalize();
        let hex_str = hex::encode(r2);
        let parsed = m.parse_hash_string(&hex_str).unwrap();
        assert!(m.cpu_verify(pw, &[], &parsed.hash_words));
    }
}
