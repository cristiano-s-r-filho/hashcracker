use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawSha384;

impl HashModule for RawSha384 {
    fn name(&self) -> &'static str { "raw-sha384" }
    fn mode(&self) -> u32 { 10810 }
    fn digest_words(&self) -> u32 { 12 }
    fn needs_int64(&self) -> bool { true }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        use sha2::{Digest, Sha384};
        let mut hasher = Sha384::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let result = hasher.finalize();
        // parse_hash_string stores target[i] = lo32, extra[i] = hi32 of each u64 word
        // full_hash_slice builds: [lo0..lo5, 0, 0, hi0..hi3]
        for i in 0..6 {
            let word = u64::from_be_bytes(result[i * 8..i * 8 + 8].try_into().unwrap());
            if word as u32 != hash[i] { return false; }
        }
        for i in 0..4 {
            let word = u64::from_be_bytes(result[i * 8..i * 8 + 8].try_into().unwrap());
            if (word >> 32) as u32 != hash[8 + i] { return false; }
        }
        true
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../sha384_crack.wgsl"),
            AttackModeType::Mask => include_str!("../sha384_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../sha384_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(96), priority: 100 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if clean.len() != 96 {
            return Err(format!("Expected 96 hex chars for SHA-384, got {}", clean.len()));
        }
        let mut target = [0u32; 8];
        let mut extra = [0u32; 8];
        for i in 0..6 {
            let word = u64::from_str_radix(&clean[i * 16..i * 16 + 16], 16)
                .map_err(|_| format!("Invalid hex at position {}", i * 16))?;
            target[i] = word as u32;
            extra[i] = (word >> 32) as u32;
        }
        Ok(ParsedHash {
            hash_words: target,
            extra_words: extra,
            salt: Vec::new(),
            digest_words: 12,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_backend::full_hash_slice;
    use crate::hashes::HashModule;
    use sha2::Digest;

    #[test]
    fn test_sha384_roundtrip() {
        let m = RawSha384;
        let pw = "hello";
        let mut hasher = sha2::Sha384::new();
        hasher.update(pw.as_bytes());
        let result = hasher.finalize();
        let hex_str = hex::encode(result);
        let parsed = m.parse_hash_string(&hex_str).unwrap();
        let dw = m.digest_words() as usize;
        let full = full_hash_slice(&parsed, dw);
        assert!(m.cpu_verify(pw, &[], &full[..dw]));
        assert!(!m.cpu_verify("wrong", &[], &full[..dw]));
    }
}
