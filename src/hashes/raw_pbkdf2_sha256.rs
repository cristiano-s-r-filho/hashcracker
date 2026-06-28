pub struct RawPbkdf2Sha256;

use sha2::{Digest, Sha256};
use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let key = if key.len() > 64 {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let result = hasher.finalize();
        result.to_vec()
    } else {
        key.to_vec()
    };

    let mut padded_key = [0u8; 64];
    for (i, &b) in key.iter().enumerate() {
        padded_key[i] = b;
    }

    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = padded_key[i] ^ 0x36;
        opad[i] = padded_key[i] ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_result = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_result);
    outer.finalize().into()
}

pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut msg = Vec::with_capacity(salt.len() + 4);
    msg.extend_from_slice(salt);
    msg.extend_from_slice(&1u32.to_be_bytes());

    let mut u = hmac_sha256(password, &msg);
    let mut result = u;

    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for i in 0..32 {
            result[i] ^= u[i];
        }
    }

    result
}

fn parse_pbkdf2_string(s: &str) -> Result<(u32, Vec<u8>, [u32; 8], [u32; 8]), String> {
    let trimmed = s.trim();

    if trimmed.starts_with("$pbkdf2-sha256$") {
        let inner = &trimmed["$pbkdf2-sha256$".len()..];
        let parts: Vec<&str> = inner.split('$').collect();
        if parts.len() < 3 {
            return Err("Expected format: $pbkdf2-sha256$iterations$salt_hex$hash_hex".to_string());
        }
        let iterations: u32 = parts[0].parse().map_err(|_| format!("Invalid iterations: '{}'", parts[0]))?;
        let salt_bytes = hex::decode(parts[1]).map_err(|e| format!("Invalid salt hex: {}", e))?;
        let hash_hex = parts[2].split(':').next().unwrap_or(parts[2]);
        let hash_bytes = hex::decode(hash_hex).map_err(|e| format!("Invalid hash hex: {}", e))?;
        if hash_bytes.len() != 32 {
            return Err(format!("Expected 32 bytes for SHA-256 hash, got {}", hash_bytes.len()));
        }
        let mut target = [0u32; 8];
        for i in 0..8 {
            target[i] = u32::from_be_bytes(hash_bytes[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let mut extra = [0u32; 8];
        extra[0] = iterations;
        return Ok((iterations, salt_bytes, target, extra));
    }

    if let Some(colon_pos) = trimmed.find(':') {
        let prefix = &trimmed[..colon_pos];
        if prefix == "sha256" || prefix == "sha-256" {
            let rest = &trimmed[colon_pos + 1..];
            let colon2 = rest.find(':').ok_or_else(|| "Expected sha256:iterations:salt_hex:hash_hex".to_string())?;
            let iterations: u32 = rest[..colon2].parse().map_err(|_| format!("Invalid iterations: '{}'", &rest[..colon2]))?;
            let rest2 = &rest[colon2 + 1..];
            let colon3 = rest2.find(':').ok_or_else(|| "Expected sha256:iterations:salt_hex:hash_hex".to_string())?;
            let salt_hex = &rest2[..colon3];
            let hash_hex = rest2[colon3 + 1..].split(':').next().unwrap_or(&rest2[colon3 + 1..]);
            let salt_bytes = hex::decode(salt_hex).map_err(|e| format!("Invalid salt hex: {}", e))?;
            let hash_bytes = hex::decode(hash_hex).map_err(|e| format!("Invalid hash hex: {}", e))?;
            if hash_bytes.len() != 32 {
                return Err(format!("Expected 32 bytes for SHA-256 hash, got {}", hash_bytes.len()));
            }
            let mut target = [0u32; 8];
            for i in 0..8 {
                target[i] = u32::from_be_bytes(hash_bytes[i * 4..i * 4 + 4].try_into().unwrap());
            }
            let mut extra = [0u32; 8];
            extra[0] = iterations;
            return Ok((iterations, salt_bytes, target, extra));
        }
    }

    Err(format!("Unrecognized PBKDF2-SHA256 format: '{}'", s))
}

impl HashModule for RawPbkdf2Sha256 {
    fn name(&self) -> &'static str { "pbkdf2-sha256" }
    fn mode(&self) -> u32 { 10900 }
    fn digest_words(&self) -> u32 { 8 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, _password: &str, _salt: &[u8], _hash: &[u32]) -> bool {
        false
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../pbkdf2_sha256_crack.wgsl"),
            AttackModeType::Mask => include_str!("../pbkdf2_sha256_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../pbkdf2_sha256_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: Some("$pbkdf2-sha256$"), hex_len: None, priority: 1 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let (_iterations, salt_bytes, target, extra) = parse_pbkdf2_string(s)?;
        Ok(ParsedHash { hash_words: target, extra_words: extra, salt: salt_bytes, digest_words: 8 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_words(hex: &str) -> [u32; 8] {
        let bytes = hex::decode(hex).unwrap();
        let mut words = [0u32; 8];
        for i in 0..8 {
            words[i] = u32::from_be_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
        }
        words
    }

    #[test]
    fn test_pbkdf2_vec_c1() {
        let dk = pbkdf2_hmac_sha256(b"password", b"salt", 1);
        let expected = hex::decode("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b").unwrap();
        assert_eq!(dk.to_vec(), expected);
    }

    #[test]
    fn test_pbkdf2_vec_c1000() {
        let dk = pbkdf2_hmac_sha256(b"password", b"salt", 1000);
        let expected = hex::decode("632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3").unwrap();
        assert_eq!(dk.to_vec(), expected);
    }

    #[test]
    fn test_pbkdf2_vec_c4096() {
        let dk = pbkdf2_hmac_sha256(b"password", b"salt", 4096);
        let expected = hex::decode("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a").unwrap();
        assert_eq!(dk.to_vec(), expected);
    }

    #[test]
    fn test_pbkdf2_vec_long_pwd_salt() {
        let dk = pbkdf2_hmac_sha256(b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096);
        let expected = hex::decode("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1").unwrap();
        assert_eq!(dk.to_vec(), expected);
    }

    #[test]
    fn test_parse_dollar_format() {
        let hash_str = "$pbkdf2-sha256$1000$73616c74$632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3";
        let parsed = RawPbkdf2Sha256.parse_hash_string(hash_str).unwrap();
        assert_eq!(parsed.salt, b"salt");
        assert_eq!(parsed.extra_words[0], 1000);
        let expected_target = hex_to_words("632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3");
        assert_eq!(parsed.hash_words, expected_target);
    }

    #[test]
    fn test_parse_colon_format() {
        let hash_str = "sha256:1000:73616c74:632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3";
        let parsed = RawPbkdf2Sha256.parse_hash_string(hash_str).unwrap();
        assert_eq!(parsed.salt, b"salt");
        assert_eq!(parsed.extra_words[0], 1000);
    }

    #[test]
    fn test_roundtrip_dollar() {
        let password = b"abc";
        let salt = b"mysalt";
        let iterations = 1000;
        let dk = pbkdf2_hmac_sha256(password, salt, iterations);
        let format = format!("$pbkdf2-sha256${}${}${}",
            iterations,
            hex::encode(salt),
            hex::encode(dk));
        let parsed = RawPbkdf2Sha256.parse_hash_string(&format).unwrap();
        assert_eq!(parsed.salt, salt);
        assert_eq!(parsed.extra_words[0], iterations);
        let mut computed = [0u32; 8];
        for i in 0..8 {
            computed[i] = u32::from_be_bytes(dk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        assert_eq!(parsed.hash_words, computed);
    }
}
