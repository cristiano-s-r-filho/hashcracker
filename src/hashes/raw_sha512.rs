use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawSha512;

impl HashModule for RawSha512 {
    fn name(&self) -> &'static str { "raw-sha512" }
    fn mode(&self) -> u32 { 1700 }
    fn digest_words(&self) -> u32 { 16 }
    fn needs_int64(&self) -> bool { true }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        use sha2::{Digest, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let result = hasher.finalize();
        let mut computed = [0u32; 16];
        for i in 0..8 {
            let word = u64::from_be_bytes(result[i * 8..i * 8 + 8].try_into().unwrap());
            let hi = (word >> 32) as u32;
            let lo = word as u32;
            if i < 4 {
                computed[i * 2] = hi;
                computed[i * 2 + 1] = lo;
            } else {
                let j = i - 4;
                computed[8 + j * 2] = hi;
                computed[8 + j * 2 + 1] = lo;
            }
        }
        computed[..8] == hash[..8] && computed[8..16] == hash[8..16]
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../sha512_crack.wgsl"),
            AttackModeType::Mask => include_str!("../sha512_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../sha512_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(128), priority: 100 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if clean.len() != 128 {
            return Err(format!("Expected 128 hex chars for SHA-512, got {}", clean.len()));
        }
        let mut target = [0u32; 8];
        let mut extra = [0u32; 8];
        for i in 0..8 {
            let word = u32::from_str_radix(&clean[i * 8..i * 8 + 8], 16)
                .map_err(|_| format!("Invalid hex at position {}", i * 8))?;
            target[i] = word;
        }
        for i in 8..16 {
            let word = u32::from_str_radix(&clean[i * 8..i * 8 + 8], 16)
                .map_err(|_| format!("Invalid hex at position {}", i * 8))?;
            extra[i - 8] = word;
        }
        Ok(ParsedHash {
            hash_words: target,
            extra_words: extra,
            salt: Vec::new(),
            digest_words: 16,
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
    fn test_sha512_roundtrip() {
        let m = RawSha512;
        let pw = "hello";
        let mut hasher = sha2::Sha512::new();
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
