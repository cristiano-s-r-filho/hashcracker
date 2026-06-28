use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawHmacSha256;

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOCK_SIZE: usize = 64;
    let k = if key.len() > BLOCK_SIZE {
        let mut h = Sha256::new();
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
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize().into()
}

impl HashModule for RawHmacSha256 {
    fn name(&self) -> &'static str { "hmac-sha256" }
    fn mode(&self) -> u32 { 1450 }
    fn digest_words(&self) -> u32 { 8 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        let result = hmac_sha256(password.as_bytes(), salt);
        let mut computed = [0u32; 8];
        for i in 0..8 {
            computed[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
        }
        computed == hash
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../hmac_sha256_crack.wgsl"),
            AttackModeType::Mask => include_str!("../hmac_sha256_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../hmac_sha256_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(64), priority: 110 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if clean.len() != 64 {
            return Err(format!("Expected 64 hex chars for HMAC-SHA256, got {}", clean.len()));
        }
        let mut target = [0u32; 8];
        for i in 0..8 {
            target[i] = u32::from_str_radix(&clean[i * 8..i * 8 + 8], 16)
                .map_err(|_| format!("Invalid hex at position {}", i * 8))?;
        }
        Ok(ParsedHash {
            hash_words: target,
            extra_words: [0u32; 8],
            salt: Vec::new(),
            digest_words: 8,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_rfc4231_case2() {
        let result = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let expected = hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843").unwrap();
        assert_eq!(result.to_vec(), expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_case3() {
        let key = [0xaa; 20];
        let data = [0xdd; 50];
        let result = hmac_sha256(&key, &data);
        let expected = hex::decode("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe").unwrap();
        assert_eq!(result.to_vec(), expected);
    }

    #[test]
    fn test_hmac_sha256_cpu_verify() {
        let module = RawHmacSha256;
        let result = hmac_sha256(b"abc", b"");
        let mut words = [0u32; 8];
        for i in 0..8 {
            words[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
        }
        assert!(module.cpu_verify("abc", &[], &words));
    }
}
