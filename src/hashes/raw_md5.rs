pub struct RawMd5;

use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

impl HashModule for RawMd5 {
    fn name(&self) -> &'static str { "raw-md5" }
    fn mode(&self) -> u32 { 0 }
    fn digest_words(&self) -> u32 { 4 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let result = hasher.finalize();
        let mut computed = [0u32; 4];
        for i in 0..4 {
            computed[i] = u32::from_le_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
        }
        computed == hash[..4]
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../md5_crack.wgsl"),
            AttackModeType::Mask => include_str!("../md5_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../md5_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(32), priority: 100 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if clean.len() != 32 {
            return Err(format!("Expected 32 hex chars for MD5, got {}", clean.len()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashes::HashModule;
    use md5::Digest;

    #[test]
    fn test_md5_roundtrip() {
        let m = RawMd5;
        let pw = "hello";
        let mut hasher = md5::Md5::new();
        hasher.update(pw.as_bytes());
        let result = hasher.finalize();
        let hex_str = hex::encode(result);
        let parsed = m.parse_hash_string(&hex_str).unwrap();
        assert!(m.cpu_verify(pw, &[], &parsed.hash_words));
        assert!(!m.cpu_verify("wrong", &[], &parsed.hash_words));
    }
}
