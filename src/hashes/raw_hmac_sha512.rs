use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawHmacSha512;

impl RawHmacSha512 {
    fn hmac_sha512(password: &str, salt: &[u8]) -> ([u32; 8], [u32; 8]) {
        use sha2::{Digest, Sha512};
        const BLOCK_SIZE: usize = 128;
        let key = password.as_bytes();
        let mut ipad = [0x36u8; BLOCK_SIZE];
        let mut opad = [0x5Cu8; BLOCK_SIZE];
        let k = if key.len() > BLOCK_SIZE {
            let mut h = Sha512::new();
            h.update(key);
            h.finalize().to_vec()
        } else {
            key.to_vec()
        };
        for i in 0..k.len() {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Sha512::new();
        inner.update(&ipad);
        inner.update(salt);
        let inner_hash = inner.finalize();
        let mut outer = Sha512::new();
        outer.update(&opad);
        outer.update(&inner_hash);
        let result = outer.finalize();
        let mut target = [0u32; 8];
        let mut extra = [0u32; 8];
        for i in 0..8 {
            let word = u64::from_be_bytes(result[i * 8..i * 8 + 8].try_into().unwrap());
            target[i] = word as u32;
            extra[i] = (word >> 32) as u32;
        }
        (target, extra)
    }
}

impl HashModule for RawHmacSha512 {
    fn name(&self) -> &'static str { "hmac-sha512" }
    fn mode(&self) -> u32 { 1750 }
    fn digest_words(&self) -> u32 { 16 }
    fn needs_int64(&self) -> bool { true }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        let (target, extra) = Self::hmac_sha512(password, salt);
        target[..] == hash[..8] && extra[..] == hash[8..16]
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../hmac_sha512_crack.wgsl"),
            AttackModeType::Mask => include_str!("../hmac_sha512_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../hmac_sha512_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(128), priority: 85 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim();
        if clean.len() != 128 {
            return Err(format!("Expected 128 hex chars, got {}", clean.len()));
        }
        let mut target = [0u32; 8];
        let mut extra = [0u32; 8];
        for i in 0..8 {
            let hi = u32::from_str_radix(&clean[i * 16..i * 16 + 8], 16)
                .map_err(|_| "Invalid hex")?;
            let lo = u32::from_str_radix(&clean[i * 16 + 8..i * 16 + 16], 16)
                .map_err(|_| "Invalid hex")?;
            target[i] = lo;
            extra[i] = hi;
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

    fn hex_to_u32_pairs(hex: &str) -> ([u32; 8], [u32; 8]) {
        let mut target = [0u32; 8];
        let mut extra = [0u32; 8];
        for i in 0..8 {
            let hi = u32::from_str_radix(&hex[i * 16..i * 16 + 8], 16).unwrap();
            let lo = u32::from_str_radix(&hex[i * 16 + 8..i * 16 + 16], 16).unwrap();
            target[i] = lo;
            extra[i] = hi;
        }
        (target, extra)
    }

    #[test]
    fn test_rfc4231_case2() {
        let password = "Jefe";
        let salt = "what do ya want for nothing?";
        let expected_hex = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
        let (expected_target, expected_extra) = hex_to_u32_pairs(expected_hex);
        let (computed_target, computed_extra) = RawHmacSha512::hmac_sha512(password, salt.as_bytes());
        assert_eq!(computed_target, expected_target, "target mismatch\n  computed: {:?}\n  expected: {:?}", computed_target, expected_target);
        assert_eq!(computed_extra, expected_extra, "extra mismatch\n  computed: {:?}\n  expected: {:?}", computed_extra, expected_extra);
    }

    #[test]
    fn test_cpu_verify_roundtrip() {
        let password = "abcd";
        let salt = "mysalt";
        let (target, extra) = RawHmacSha512::hmac_sha512(password, salt.as_bytes());
        let mut hash = [0u32; 16];
        for i in 0..8 {
            hash[i] = target[i];
            hash[i + 8] = extra[i];
        }
        let module = RawHmacSha512;
        assert!(module.cpu_verify(password, salt.as_bytes(), &hash));
    }

    #[test]
    fn test_empty_key() {
        let password = "";
        let salt = "";
        let (target, extra) = RawHmacSha512::hmac_sha512(password, salt.as_bytes());
        let mut hash = [0u32; 16];
        for i in 0..8 {
            hash[i] = target[i];
            hash[i + 8] = extra[i];
        }
        let module = RawHmacSha512;
        assert!(module.cpu_verify(password, salt.as_bytes(), &hash));
    }

    #[test]
    fn test_parse_and_verify() {
        let hex = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
        let parsed = RawHmacSha512.parse_hash_string(hex).unwrap();
        let mut hash = [0u32; 16];
        for i in 0..8 {
            hash[i] = parsed.hash_words[i];
            hash[i + 8] = parsed.extra_words[i];
        }
        assert!(RawHmacSha512.cpu_verify("Jefe", "what do ya want for nothing?".as_bytes(), &hash));
    }
}
