#![allow(deprecated)]
use aes::Aes256Dec;
use cipher::block::BlockCipherDecrypt;
use cipher::typenum::consts::U32;
use cipher::{Block, KeyInit};
use sha2::{Digest, Sha256};

use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawRar5;

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let key = if key.len() > 64 {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.finalize().to_vec()
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

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
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

impl HashModule for RawRar5 {
    fn name(&self) -> &'static str { "rar5" }
    fn mode(&self) -> u32 { 13000 }
    fn digest_words(&self) -> u32 { 4 }
    fn needs_int64(&self) -> bool { false }
    fn shader_source(&self, _mode: &AttackModeType) -> &'static str { "" }
    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: Some("$rar5$"), hex_len: None, priority: 100 }]
    }
    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let parts: Vec<&str> = s.split('*').collect();
        if parts.len() < 6 || parts[0] != "$rar5$" {
            return Err("Invalid RAR5 format".to_string());
        }
        let salt_hex = parts[1];
        let encrypted_data = hex::decode(parts[2]).map_err(|_| "Invalid encrypted hex".to_string())?;
        let iv = hex::decode(parts[3]).map_err(|_| "Invalid IV hex".to_string())?;
        let expected_hash = hex::decode(parts[4]).map_err(|_| "Invalid hash hex".to_string())?;
        let iterations: u32 = parts[5].parse().map_err(|_| "Invalid iterations".to_string())?;
        let salt_bytes = hex::decode(salt_hex).map_err(|_| "Invalid salt hex".to_string())?;

        let mut salt = Vec::new();
        salt.extend_from_slice(&salt_bytes);
        salt.push(b'*');
        salt.extend_from_slice(&iv);
        salt.push(b'*');
        salt.extend_from_slice(&encrypted_data);
        salt.push(b'*');
        salt.extend_from_slice(&expected_hash);
        salt.push(b'*');
        salt.extend_from_slice(&iterations.to_le_bytes());

        let hash_words = [
            if expected_hash.len() >= 4 { u32::from_le_bytes(expected_hash[..4].try_into().unwrap()) } else { 0 },
            if expected_hash.len() >= 8 { u32::from_le_bytes(expected_hash[4..8].try_into().unwrap()) } else { 0 },
            if expected_hash.len() >= 12 { u32::from_le_bytes(expected_hash[8..12].try_into().unwrap()) } else { 0 },
            if expected_hash.len() >= 16 { u32::from_le_bytes(expected_hash[12..16].try_into().unwrap()) } else { 0 },
            0, 0, 0, 0,
        ];
        Ok(ParsedHash { hash_words, extra_words: [0u32; 8], salt, digest_words: 4 })
    }
    fn cpu_verify(&self, password: &str, salt: &[u8], _hash: &[u32]) -> bool {
        let stars: Vec<usize> = salt.iter()
            .enumerate()
            .filter(|(_, &b)| b == b'*')
            .map(|(i, _)| i)
            .collect();

        if stars.len() != 4 { return false; }

        let salt_bytes = &salt[..stars[0]];
        let iv = &salt[stars[0] + 1..stars[1]];
        let encrypted_data = &salt[stars[1] + 1..stars[2]];
        let expected_hash = &salt[stars[2] + 1..stars[3]];

        if stars[3] + 5 > salt.len() { return false; }
        let iterations = u32::from_le_bytes(salt[stars[3] + 1..stars[3] + 5].try_into().unwrap());

        if encrypted_data.len() % 16 != 0 { return false; }

        let key = pbkdf2_hmac_sha256(password.as_bytes(), salt_bytes, iterations);

        let cipher = Aes256Dec::new(cipher::Array::<u8, U32>::from_slice(&key));
        let n = encrypted_data.len();
        let mut decrypted = vec![0u8; n];
        for i in (0..n).step_by(16) {
            let mut block = *Block::<Aes256Dec>::from_slice(&encrypted_data[i..i + 16]);
            cipher.decrypt_block(&mut block);
            let prev = if i == 0 { iv } else { &encrypted_data[i - 16..i] };
            for j in 0..16 {
                decrypted[i + j] = block[j] ^ prev[j];
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(&decrypted);
        let computed = hasher.finalize();
        computed[..] == expected_hash[..]
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
    fn test_rar5_self_consistent() {
        let password = "testpassword";
        let pwd_bytes = password.as_bytes();
        let salt_bytes = hex::decode("aabbccdd").unwrap();
        let iv = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
        let plaintext = b"Hello RAR5 World!!!"; // 17 bytes
        let iterations = 4096u32;

        let key = pbkdf2_hmac_sha256(pwd_bytes, &salt_bytes, iterations);

        let mut pt = plaintext.to_vec();
        while pt.len() % 16 != 0 {
            pt.push(0u8);
        }
        let encrypted = aes256_cbc_encrypt(&key, &iv, &pt);

        let mut hasher = Sha256::new();
        hasher.update(&pt);
        let hash = hasher.finalize();

        let hash_str = format!(
            "$rar5$*{}*{}*{}*{}*{}",
            hex::encode(&salt_bytes),
            hex::encode(&encrypted),
            hex::encode(&iv),
            hex::encode(&hash),
            iterations,
        );

        let r = RawRar5;
        let parsed = r.parse_hash_string(&hash_str).unwrap();
        assert!(r.cpu_verify(password, &parsed.salt, &parsed.hash_words));
        assert!(!r.cpu_verify("wrongpassword", &parsed.salt, &parsed.hash_words));
    }

    #[test]
    fn test_rar5_prefix() {
        let r = RawRar5;
        assert_eq!(r.detect_patterns()[0].prefix.unwrap(), "$rar5$");
    }
}
