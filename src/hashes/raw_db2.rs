use sha1::{Digest, Sha1};
use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawDb2;

impl HashModule for RawDb2 {
    fn name(&self) -> &'static str { "db2" }
    fn mode(&self) -> u32 { 8500 }
    fn digest_words(&self) -> u32 { 5 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        let mut computed = [0u32; 8];
        for i in 0..5 {
            computed[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
        }
        computed[..5] == hash[..5]
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../db2_crack.wgsl"),
            AttackModeType::Mask => include_str!("../db2_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../db2_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(40), priority: 85 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        if let Some(colon_pos) = s.find(':') {
            let hash_part = &s[..colon_pos];
            let salt_part = &s[colon_pos + 1..];
            let clean = hash_part.strip_prefix("0x").unwrap_or(hash_part);
            if clean.len() != 40 {
                return Err(format!("Expected 40 hex chars for DB2, got {}", clean.len()));
            }
            let mut target = [0u32; 8];
            for i in 0..5 {
                target[i] = u32::from_str_radix(&clean[i * 8..i * 8 + 8], 16)
                    .map_err(|_| format!("Invalid hex at position {}", i * 8))?;
            }
            Ok(ParsedHash {
                hash_words: target,
                extra_words: [0u32; 8],
                salt: salt_part.as_bytes().to_vec(),
                digest_words: 5,
            })
        } else {
            Err("DB2 hash requires hash:salt format".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_db2_roundtrip() {
        let m = RawDb2;
        let pw = "abc";
        let salt = "mysalt";
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(pw.as_bytes());
        hasher.update(salt.as_bytes());
        hasher.update(pw.as_bytes());
        let result = hasher.finalize();
        let hash_str = format!("{}:{}", hex::encode(result), salt);
        let parsed = m.parse_hash_string(&hash_str).unwrap();
        assert!(m.cpu_verify(pw, &parsed.salt, &parsed.hash_words));
    }
}
