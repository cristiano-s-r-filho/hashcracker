use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use generic_array::GenericArray;
use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawLm;

fn lm_key_expand(key7: &[u8; 7]) -> [u8; 8] {
    let mut key8 = [0u8; 8];
    key8[0] = key7[0];
    key8[1] = (key7[0] >> 7) | (key7[1] << 1);
    key8[2] = (key7[1] >> 6) | (key7[2] << 2);
    key8[3] = (key7[2] >> 5) | (key7[3] << 3);
    key8[4] = (key7[3] >> 4) | (key7[4] << 4);
    key8[5] = (key7[4] >> 3) | (key7[5] << 5);
    key8[6] = (key7[5] >> 2) | (key7[6] << 6);
    key8[7] = key7[6] >> 1;
    for b in &mut key8 {
        if b.count_ones() % 2 == 0 {
            *b ^= 0x01;
        }
    }
    key8
}

pub fn lm_hash(password: &str) -> [u8; 16] {
    let mut pw_upper = password.to_uppercase();
    pw_upper.retain(|c| c.is_ascii());
    let mut key = pw_upper.as_bytes().to_vec();
    key.truncate(14);
    key.resize(14, 0);

    let magic = *b"KGS!@#$%";
    let block = GenericArray::from_slice(&magic);
    let expanded1 = lm_key_expand(&key[..7].try_into().unwrap());
    let k1 = GenericArray::from_slice(&expanded1);
    let cipher1 = Des::new(k1);
    let mut result1 = *block;
    cipher1.encrypt_block(&mut result1);
    let expanded2 = lm_key_expand(&key[7..14].try_into().unwrap());
    let k2 = GenericArray::from_slice(&expanded2);
    let cipher2 = Des::new(k2);
    let mut result2 = *block;
    cipher2.encrypt_block(&mut result2);
    let mut result = [0u8; 16];
    result[..8].copy_from_slice(&result1);
    result[8..].copy_from_slice(&result2);
    result
}

impl HashModule for RawLm {
    fn name(&self) -> &'static str { "lm" }
    fn mode(&self) -> u32 { 3000 }
    fn digest_words(&self) -> u32 { 4 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, _salt: &[u8], hash: &[u32]) -> bool {
        let computed = lm_hash(password);
        let mut target = [0u32; 8];
        for i in 0..4 {
            target[i] = u32::from_le_bytes(computed[i * 4..i * 4 + 4].try_into().unwrap());
        }
        target[..4] == hash[..4]
    }

    fn shader_source(&self, _mode: &AttackModeType) -> &'static str { "" }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(32), priority: 70 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if clean.len() != 32 {
            return Err(format!("Expected 32 hex chars for LM, got {}", clean.len()));
        }
        let mut target = [0u32; 8];
        for i in 0..4 {
            let word = u32::from_str_radix(&clean[i * 8..i * 8 + 8], 16)
                .map_err(|_| format!("Invalid hex at position {}", i * 8))?;
            target[i] = word.swap_bytes();
        }
        Ok(ParsedHash { hash_words: target, extra_words: [0u32; 8], salt: Vec::new(), digest_words: 4 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lm_hash_known() {
        let result = lm_hash("abcd");
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_lm_roundtrip() {
        let m = RawLm;
        let result = lm_hash("abcd");
        let mut words = [0u32; 8];
        for i in 0..4 {
            words[i] = u32::from_le_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
        }
        assert!(m.cpu_verify("abcd", &[], &words));
    }

    #[test]
    fn test_lm_parse_hash() {
        let m = RawLm;
        let result = lm_hash("abcd");
        let mut words = [0u32; 8];
        for i in 0..4 {
            words[i] = u32::from_le_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let hex_str = hex::encode(result);
        let parsed = m.parse_hash_string(&hex_str).unwrap();
        assert_eq!(parsed.hash_words[..4], words[..4]);
    }
}
