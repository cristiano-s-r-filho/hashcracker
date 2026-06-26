#![allow(deprecated)]
use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};
use aes::Aes256Dec;
use cipher::block::BlockCipherDecrypt;
use cipher::typenum::consts::U32;
use cipher::{Block, KeyInit};
use sha2::{Digest, Sha256};

pub struct RawSevenZip;

impl HashModule for RawSevenZip {
    fn name(&self) -> &'static str { "7z" }
    fn mode(&self) -> u32 { 11600 }
    fn digest_words(&self) -> u32 { 4 }
    fn needs_int64(&self) -> bool { false }
    fn shader_source(&self, _mode: &AttackModeType) -> &'static str { "" }
    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: Some("$7z$"), hex_len: None, priority: 100 }]
    }
    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let parts: Vec<&str> = s.split('*').collect();
        if parts.len() < 5 || parts[0] != "$7z$" {
            return Err("Invalid 7z format".to_string());
        }
        let salt_hex = parts[1];
        let encrypted_data = hex::decode(parts[2]).map_err(|_| "Invalid encrypted hex".to_string())?;
        let iv = hex::decode(parts[3]).map_err(|_| "Invalid IV hex".to_string())?;
        let expected_hash = hex::decode(parts[4]).map_err(|_| "Invalid hash hex".to_string())?;
        let salt_bytes = hex::decode(salt_hex).map_err(|_| "Invalid salt hex".to_string())?;

        let mut salt = Vec::new();
        salt.extend_from_slice(&salt_bytes);
        salt.push(b'*');
        salt.extend_from_slice(&iv);
        salt.push(b'*');
        salt.extend_from_slice(&encrypted_data);
        salt.push(b'*');
        salt.extend_from_slice(&expected_hash);

        let hash_words = if expected_hash.len() >= 4 {
            let w0 = u32::from_le_bytes(expected_hash[..4].try_into().unwrap());
            let w1 = if expected_hash.len() >= 8 {
                u32::from_le_bytes(expected_hash[4..8].try_into().unwrap())
            } else { 0 };
            let w2 = if expected_hash.len() >= 12 {
                u32::from_le_bytes(expected_hash[8..12].try_into().unwrap())
            } else { 0 };
            let w3 = if expected_hash.len() >= 16 {
                u32::from_le_bytes(expected_hash[12..16].try_into().unwrap())
            } else { 0 };
            [w0, w1, w2, w3, 0, 0, 0, 0]
        } else {
            [0; 8]
        };
        Ok(ParsedHash { hash_words, extra_words: [0u32; 8], salt, digest_words: 4 })
    }
    fn cpu_verify(&self, password: &str, salt: &[u8], _hash: &[u32]) -> bool {
        let mut pos = 0;
        let salt_end = salt[pos..].iter().position(|&b| b == b'*').unwrap_or(salt.len());
        let salt_bytes = &salt[..salt_end];
        pos += salt_end + 1;
        if pos + 16 > salt.len() { return false; }
        let iv = &salt[pos..pos + 16];
        pos += 16;
        if pos >= salt.len() || salt[pos] != b'*' { return false; }
        pos += 1;
        let enc_end = salt[pos..].iter().position(|&b| b == b'*').unwrap_or(salt.len() - pos) + pos;
        if enc_end <= pos { return false; }
        let encrypted_data = &salt[pos..enc_end];
        pos = enc_end + 1;
        if pos > salt.len() { return false; }
        let expected_hash_bytes = &salt[pos..];

        if encrypted_data.len() % 16 != 0 || encrypted_data.is_empty() { return false; }

        let mut hasher = Sha256::new();
        hasher.update(salt_bytes);
        hasher.update(password.as_bytes());
        let k = hasher.finalize();

        let cipher = Aes256Dec::new(cipher::Array::<u8, U32>::from_slice(&k));

        let n = encrypted_data.len();
        let mut result = vec![0u8; n];
        for i in (0..n).step_by(16) {
            let mut block = *Block::<Aes256Dec>::from_slice(&encrypted_data[i..i + 16]);
            cipher.decrypt_block(&mut block);
            let prev = if i == 0 { iv } else { &encrypted_data[i - 16..i] };
            for j in 0..16 {
                result[i + j] = block[j] ^ prev[j];
            }
        }

        let mut h2 = Sha256::new();
        h2.update(&result);
        let computed = h2.finalize();
        let min_len = expected_hash_bytes.len().min(computed.len());
        min_len > 0 && computed[..min_len] == expected_hash_bytes[..min_len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes256Enc;
    use cipher::block::BlockCipherEncrypt;

    fn aes256_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Enc::new(cipher::Array::<u8, U32>::from_slice(key));
        let n = plaintext.len();
        let mut result = vec![0u8; n];
        let mut prev = iv.to_vec();
        for i in (0..n).step_by(16) {
            let mut block = *Block::<Aes256Enc>::from_slice(&plaintext[i..i + 16]);
            for j in 0..16 { block[j] ^= prev[j]; }
            cipher.encrypt_block(&mut block);
            result[i..i + 16].copy_from_slice(&block);
            prev.copy_from_slice(&block);
        }
        result
    }

    #[test]
    fn test_7z_verify() {
        let salt_bytes = b"\x01\x02\x03\x04";
        let password = "testpassword";
        let iv = b"\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14";
        let plaintext = b"1234567890abcdef";

        let mut hasher = Sha256::new();
        hasher.update(&salt_bytes[..]);
        hasher.update(password.as_bytes());
        let k = hasher.finalize();

        let encrypted = aes256_cbc_encrypt(&k, iv, plaintext);

        let mut h2 = Sha256::new();
        h2.update(&plaintext[..]);
        let expected_hash = h2.finalize();

        let format_str = format!(
            "$7z$*{}*{}*{}*{}",
            hex::encode(salt_bytes),
            hex::encode(&encrypted),
            hex::encode(iv),
            hex::encode(expected_hash)
        );

        let r = RawSevenZip;
        let parsed = r.parse_hash_string(&format_str).unwrap();
        assert!(r.cpu_verify(password, &parsed.salt, &parsed.hash_words));
        assert!(!r.cpu_verify("wrongpassword", &parsed.salt, &parsed.hash_words));
    }

    #[test]
    fn test_7z_prefix() {
        let r = RawSevenZip;
        assert_eq!(r.detect_patterns()[0].prefix.unwrap(), "$7z$");
    }
}
