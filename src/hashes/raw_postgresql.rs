use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawPostgresql;

impl HashModule for RawPostgresql {
    fn name(&self) -> &'static str { "postgresql" }
    fn mode(&self) -> u32 { 12 }
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
        &[HashPattern { prefix: Some("md5"), hex_len: None, priority: 90 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let trimmed = s.trim();
        let hex_part = if let Some(rest) = trimmed.strip_prefix("md5") {
            rest
        } else {
            trimmed
        };
        let clean = hex_part.strip_prefix("0x").unwrap_or(hex_part);
        if clean.len() != 32 {
            return Err(format!("Expected 32 hex chars for PostgreSQL MD5, got {}", clean.len()));
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
    fn test_postgresql_roundtrip() {
        let m = RawPostgresql;
        let pw = "password";
        let salt = b"username";
        let mut hasher = md5::Md5::new();
        hasher.update(pw.as_bytes());
        hasher.update(salt);
        let result = hasher.finalize();
        let hex_str = format!("md5{}", hex::encode(result));
        let parsed = m.parse_hash_string(&hex_str).unwrap();
        assert!(m.cpu_verify(pw, salt, &parsed.hash_words));
        assert!(!m.cpu_verify("wrong", salt, &parsed.hash_words));
    }
}
