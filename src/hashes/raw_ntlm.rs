pub struct RawNtlm;

use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

impl HashModule for RawNtlm {
    fn name(&self) -> &'static str { "ntlm" }
    fn mode(&self) -> u32 { 1000 }
    fn digest_words(&self) -> u32 { 4 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, _salt: &[u8], hash: &[u32]) -> bool {
        let computed = ntlm_hash(password);
        let mut computed_words = [0u32; 4];
        for i in 0..4 {
            computed_words[i] = u32::from_le_bytes(computed[i * 4..i * 4 + 4].try_into().unwrap());
        }
        computed_words == hash[..4]
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../ntlm_crack.wgsl"),
            AttackModeType::Mask => include_str!("../ntlm_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../ntlm_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(32), priority: 90 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if clean.len() != 32 {
            return Err(format!("Expected 32 hex chars for NTLM, got {}", clean.len()));
        }
        let mut target = [0u32; 8];
        for i in 0..4 {
            let word = u32::from_str_radix(&clean[i * 8..i * 8 + 8], 16)
                .map_err(|_| format!("Invalid hex at position {}", i * 8))?;
            target[i] = word.swap_bytes();
        }
        Ok(ParsedHash {
            hash_words: target,
            extra_words: [0u32; 8],
            salt: Vec::new(),
            digest_words: 4,
        })
    }
}

pub fn ntlm_hash(password: &str) -> [u8; 16] {
    let utf16: Vec<u16> = password.encode_utf16().collect();
    let mut data = Vec::with_capacity(utf16.len() * 2);
    for &c in &utf16 {
        data.extend_from_slice(&c.to_le_bytes());
    }
    md4_hash(&data)
}

fn md4_hash(data: &[u8]) -> [u8; 16] {
    use md4::{Md4, Digest};
    let mut hasher = Md4::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

#[test]
fn test_ntlm_hash_known() {
    let hash = ntlm_hash("password");
    assert_eq!(hex::encode(hash), "8846f7eaee8fb117ad06bdd830b7586c");
}

#[test]
fn test_ntlm_hash_abc() {
    let hash = ntlm_hash("abc");
    assert_eq!(hex::encode(hash), "e0fba38268d0ec66ef1cb452d5885e53");
}
