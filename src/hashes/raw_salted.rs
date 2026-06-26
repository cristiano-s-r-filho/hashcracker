pub struct RawSaltedSha1;
pub struct RawSaltedSha256;
pub struct RawSaltedSha512;

use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

fn parse_salted_hash(s: &str, hash_hex_len: usize) -> Result<(Vec<u8>, Vec<u8>), String> {
    let trimmed = s.trim();
    let sep = trimmed.find(':').ok_or_else(|| format!("Expected ':' separator in salted hash"))?;
    let hash_hex = &trimmed[..sep];
    let salt_raw = &trimmed[sep + 1..];
    if hash_hex.len() != hash_hex_len {
        return Err(format!("Expected {} hex chars for hash, got {}", hash_hex_len, hash_hex.len()));
    }
    if salt_raw.is_empty() || salt_raw.len() > 16 {
        return Err(format!("Salt must be 1-16 characters, got {}", salt_raw.len()));
    }
    let hash_bytes = hex::decode(hash_hex).map_err(|e| format!("Invalid hash hex: {}", e))?;
    let salt_bytes = salt_raw.as_bytes().to_vec();
    Ok((hash_bytes, salt_bytes))
}

impl HashModule for RawSaltedSha1 {
    fn name(&self) -> &'static str { "salted-sha1" }
    fn mode(&self) -> u32 { 111 }
    fn digest_words(&self) -> u32 { 5 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        use sha1::{Digest, Sha1};
        let mut ctx = Sha1::new();
        ctx.update(password.as_bytes());
        ctx.update(salt);
        let result = ctx.finalize();
        let mut words = [0u32; 5];
        for i in 0..5 {
            words[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
        }
        words == hash[..5]
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../sha1_crack.wgsl"),
            AttackModeType::Mask => include_str!("../sha1_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../sha1_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(40), priority: 5 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let (hash_bytes, salt_bytes) = parse_salted_hash(s, 40)?;
        let mut target = [0u32; 8];
        for i in 0..5 {
            target[i] = u32::from_be_bytes(hash_bytes[i * 4..i * 4 + 4].try_into().unwrap());
        }
        Ok(ParsedHash { hash_words: target, extra_words: [0u32; 8], salt: salt_bytes, digest_words: 5 })
    }
}

impl HashModule for RawSaltedSha256 {
    fn name(&self) -> &'static str { "salted-sha256" }
    fn mode(&self) -> u32 { 1410 }
    fn digest_words(&self) -> u32 { 8 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        use sha2::{Digest, Sha256};
        let mut ctx = Sha256::new();
        ctx.update(password.as_bytes());
        ctx.update(salt);
        let result = ctx.finalize();
        let mut words = [0u32; 8];
        for i in 0..8 {
            words[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
        }
        words == hash[..8]
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../sha256_crack.wgsl"),
            AttackModeType::Mask => include_str!("../sha256_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../sha256_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(64), priority: 5 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let (hash_bytes, salt_bytes) = parse_salted_hash(s, 64)?;
        let mut target = [0u32; 8];
        for i in 0..8 {
            target[i] = u32::from_be_bytes(hash_bytes[i * 4..i * 4 + 4].try_into().unwrap());
        }
        Ok(ParsedHash { hash_words: target, extra_words: [0u32; 8], salt: salt_bytes, digest_words: 8 })
    }
}

impl HashModule for RawSaltedSha512 {
    fn name(&self) -> &'static str { "salted-sha512" }
    fn mode(&self) -> u32 { 1710 }
    fn digest_words(&self) -> u32 { 16 }
    fn needs_int64(&self) -> bool { true }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        use sha2::{Digest, Sha512};
        let mut ctx = Sha512::new();
        ctx.update(password.as_bytes());
        ctx.update(salt);
        let result = ctx.finalize();
        let mut words = [0u32; 16];
        for i in 0..8 {
            let word = u64::from_be_bytes(result[i * 8..i * 8 + 8].try_into().unwrap());
            words[i] = word as u32;
            words[i + 8] = (word >> 32) as u32;
        }
        words == hash[..16]
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../sha512_crack.wgsl"),
            AttackModeType::Mask => include_str!("../sha512_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../sha512_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(128), priority: 5 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let (hash_bytes, salt_bytes) = parse_salted_hash(s, 128)?;
        let mut target = [0u32; 8];
        let mut extra = [0u32; 8];
        for i in 0..8 {
            let word = u64::from_be_bytes(hash_bytes[i * 8..i * 8 + 8].try_into().unwrap());
            target[i] = word as u32;
            extra[i] = (word >> 32) as u32;
        }
        Ok(ParsedHash { hash_words: target, extra_words: extra, salt: salt_bytes, digest_words: 16 })
    }
}
