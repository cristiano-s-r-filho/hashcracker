use sha2::{Digest, Sha256};
use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawMssql05;

impl HashModule for RawMssql05 {
    fn name(&self) -> &'static str { "mssql05" }
    fn mode(&self) -> u32 { 132 }
    fn digest_words(&self) -> u32 { 8 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        for b in password.as_bytes() {
            hasher.update(&[b.to_ascii_uppercase()]);
        }
        let result = hasher.finalize();
        let mut computed = [0u32; 8];
        for i in 0..8 {
            computed[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
        }
        computed == hash
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../mssql05_crack.wgsl"),
            AttackModeType::Mask => include_str!("../mssql05_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../mssql05_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: Some("0x0100"), hex_len: None, priority: 100 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim();
        if !clean.starts_with("0x0100") {
            return Err("MSSQL 2005 hash must start with 0x0100".to_string());
        }
        let hex_body = &clean[6..];
        if hex_body.len() < 64 {
            return Err("MSSQL 2005 hash too short".to_string());
        }
        let salt_len = hex_body.len() - 64;
        let salt_hex = &hex_body[..salt_len];
        let hash_hex = &hex_body[salt_len..];

        let mut target = [0u32; 8];
        for i in 0..8 {
            target[i] = u32::from_str_radix(&hash_hex[i * 8..i * 8 + 8], 16)
                .map_err(|_| format!("Invalid hex at position {}", i * 8))?;
        }

        let salt_bytes = hex::decode(salt_hex).map_err(|e| format!("Invalid salt hex: {}", e))?;

        Ok(ParsedHash {
            hash_words: target,
            extra_words: [0u32; 8],
            salt: salt_bytes,
            digest_words: 8,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mssql05_parse() {
        let m = RawMssql05;
        let pw = "abc";
        let salt = "1234";
        let mut hasher = sha2::Sha256::new();
        hasher.update(salt.as_bytes());
        for b in pw.as_bytes() {
            hasher.update(&[b.to_ascii_uppercase()]);
        }
        let r = hasher.finalize();
        let hex_str = format!("0x0100{}{}", hex::encode(salt), hex::encode(r));
        let parsed = m.parse_hash_string(&hex_str).unwrap();
        assert!(m.cpu_verify(pw, &parsed.salt, &parsed.hash_words));
    }
}
