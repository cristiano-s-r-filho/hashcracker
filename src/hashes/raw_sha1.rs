use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawSha1;

impl HashModule for RawSha1 {
    fn name(&self) -> &'static str { "raw-sha1" }
    fn mode(&self) -> u32 { 100 }
    fn digest_words(&self) -> u32 { 5 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let result = hasher.finalize();
        let mut computed = [0u32; 8];
        for i in 0..5 {
            computed[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
        }
        computed[..5] == hash[..5]
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../sha1_crack.wgsl"),
            AttackModeType::Mask => include_str!("../sha1_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../sha1_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(40), priority: 100 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if clean.len() != 40 {
            return Err(format!("Expected 40 hex chars for SHA-1, got {}", clean.len()));
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
    use crate::hashes::HashModule;
    use sha1::Digest;

    #[test]
    fn test_sha1_roundtrip() {
        let m = RawSha1;
        let pw = "hello";
        let mut hasher = sha1::Sha1::new();
        hasher.update(pw.as_bytes());
        let result = hasher.finalize();
        let hex_str = hex::encode(result);
        let parsed = m.parse_hash_string(&hex_str).unwrap();
        assert!(m.cpu_verify(pw, &[], &parsed.hash_words));
        assert!(!m.cpu_verify("wrong", &[], &parsed.hash_words));
    }
}
