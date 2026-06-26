use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawHmacSha1;

pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    const BLOCK_SIZE: usize = 64;
    let k = if key.len() > BLOCK_SIZE {
        let mut h = Sha1::new();
        h.update(key);
        h.finalize().to_vec()
    } else {
        key.to_vec()
    };
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5Cu8; BLOCK_SIZE];
    for i in 0..k.len() {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha1::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();
    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize().into()
}

impl HashModule for RawHmacSha1 {
    fn name(&self) -> &'static str { "hmac-sha1" }
    fn mode(&self) -> u32 { 150 }
    fn digest_words(&self) -> u32 { 5 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        let result = hmac_sha1(password.as_bytes(), salt);
        let mut computed = [0u32; 8];
        for i in 0..5 {
            computed[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
        }
        computed[..5] == hash[..5]
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../hmac_sha1_crack.wgsl"),
            AttackModeType::Mask => include_str!("../hmac_sha1_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../hmac_sha1_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(40), priority: 110 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if clean.len() != 40 {
            return Err(format!("Expected 40 hex chars for HMAC-SHA1, got {}", clean.len()));
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

    #[test]
    fn test_hmac_sha1_rfc2202_case2() {
        // RFC 2202 Test Case 2: key="Jefe", data="what do ya want for nothing?"
        let result = hmac_sha1(b"Jefe", b"what do ya want for nothing?");
        let expected = hex::decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79").unwrap();
        assert_eq!(result.to_vec(), expected);
    }

    #[test]
    fn test_hmac_sha1_rfc2202_case3() {
        // RFC 2202 Test Case 3: key=20 bytes of 0xaa, data=50 bytes of 0xdd
        let key = [0xaa; 20];
        let data = [0xdd; 50];
        let result = hmac_sha1(&key, &data);
        let expected = hex::decode("125d7342b9ac11cd91a39af48aa17b4f63f175d3").unwrap();
        assert_eq!(result.to_vec(), expected);
    }

    #[test]
    fn test_hmac_sha1_cpu_verify() {
        let module = RawHmacSha1;
        let result = hmac_sha1(b"abc", b"");
        let mut words = [0u32; 8];
        for i in 0..5 {
            words[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
        }
        assert!(module.cpu_verify("abc", &[], &words));
    }
}
