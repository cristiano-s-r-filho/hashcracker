use sha2::{Digest, Sha512};
use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawMssql12;

impl HashModule for RawMssql12 {
    fn name(&self) -> &'static str { "mssql12" }
    fn mode(&self) -> u32 { 1731 }
    fn digest_words(&self) -> u32 { 16 }
    fn needs_int64(&self) -> bool { true }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        let mut hasher = Sha512::new();
        hasher.update(salt);
        for b in password.as_bytes() {
            hasher.update(&[b.to_ascii_uppercase()]);
        }
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
            AttackModeType::BruteForce => include_str!("../mssql12_crack.wgsl"),
            AttackModeType::Mask => include_str!("../mssql12_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../mssql12_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: Some("0x0200"), hex_len: None, priority: 100 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim();
        if !clean.starts_with("0x0200") {
            return Err("MSSQL 2012 hash must start with 0x0200".to_string());
        }
        let hex_body = &clean[6..];
        if hex_body.len() < 128 {
            return Err("MSSQL 2012 hash too short".to_string());
        }
        let salt_len = hex_body.len() - 128;
        let salt_hex = &hex_body[..salt_len];
        let hash_hex = &hex_body[salt_len..];

        let mut target = [0u32; 8];
        let mut extra = [0u32; 8];
        for i in 0..8 {
            target[i] = u32::from_str_radix(&hash_hex[i * 8..i * 8 + 8], 16)
                .map_err(|_| format!("Invalid hex at position {}", i * 8))?;
        }
        for i in 8..16 {
            extra[i - 8] = u32::from_str_radix(&hash_hex[i * 8..i * 8 + 8], 16)
                .map_err(|_| format!("Invalid hex at position {}", i * 8))?;
        }

        let salt_bytes = hex::decode(salt_hex).map_err(|e| format!("Invalid salt hex: {}", e))?;

        Ok(ParsedHash {
            hash_words: target,
            extra_words: extra,
            salt: salt_bytes,
            digest_words: 16,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mssql12_parse() {
        let m = RawMssql12;
        let pw = "abc";
        let salt = "5678";
        let mut hasher = sha2::Sha512::new();
        hasher.update(salt.as_bytes());
        for b in pw.as_bytes() {
            hasher.update(&[b.to_ascii_uppercase()]);
        }
        let r = hasher.finalize();
        let hex_str = format!("0x0200{}{}", hex::encode(salt), hex::encode(r));
        let parsed = m.parse_hash_string(&hex_str).unwrap();
        let mut combined = [0u32; 16];
        combined[..8].copy_from_slice(&parsed.hash_words);
        combined[8..16].copy_from_slice(&parsed.extra_words);
        assert!(m.cpu_verify(pw, &parsed.salt, &combined));
    }
}
