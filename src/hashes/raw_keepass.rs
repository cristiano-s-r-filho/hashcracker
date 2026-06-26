#![allow(deprecated)]
use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};
use aes::Aes256Dec;
use cipher::block::BlockCipherDecrypt;
use cipher::typenum::consts::U32;
use cipher::{Block, KeyInit};

pub struct RawKeePass;

impl HashModule for RawKeePass {
    fn name(&self) -> &'static str { "keepass" }
    fn mode(&self) -> u32 { 13400 }
    fn digest_words(&self) -> u32 { 4 }
    fn needs_int64(&self) -> bool { false }
    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        use sha2::{Digest, Sha256};

        let mut pos = 0;
        let version_end = salt[pos..].iter().position(|&b| b == b'*').unwrap_or(0);
        pos += version_end + 1;

        let master_seed = match salt.get(pos..pos + 32) { Some(s) => s, None => return false };
        pos += 32 + 1;
        let encrypted_key = match salt.get(pos..pos + 32) { Some(s) => s, None => return false };
        pos += 32 + 1;
        let iv = match salt.get(pos..pos + 16) { Some(s) => s, None => return false };
        pos += 16 + 1;
        let content_hash = match salt.get(pos..pos + 32) { Some(s) => s, None => return false };
        pos += 32 + 1;
        let transform_seed = match salt.get(pos..pos + 32) { Some(s) => s, None => return false };
        pos += 32 + 1;
        let rounds_bytes: [u8; 8] = match salt.get(pos..pos + 8) {
            Some(b) => match b.try_into() { Ok(r) => r, Err(_) => return false },
            None => return false,
        };
        let transform_rounds = u64::from_le_bytes(rounds_bytes);

        let key = Sha256::digest(password.as_bytes());
        let mut current = key;
        for _ in 0..transform_rounds {
            let mut hasher = Sha256::new();
            hasher.update(transform_seed);
            hasher.update(current);
            current = hasher.finalize();
        }

        let mut hasher = Sha256::new();
        hasher.update(master_seed);
        hasher.update(current);
        hasher.update(content_hash);
        let final_key = hasher.finalize();

        if encrypted_key.len() % 16 != 0 { return false; }
        let cipher = Aes256Dec::new(cipher::Array::<u8, U32>::from_slice(&final_key));
        let n = encrypted_key.len();
        let mut decrypted = vec![0u8; n];
        for i in (0..n).step_by(16) {
            let mut block = *Block::<Aes256Dec>::from_slice(&encrypted_key[i..i + 16]);
            cipher.decrypt_block(&mut block);
            let prev = if i == 0 { iv } else { &encrypted_key[i - 16..i] };
            for j in 0..16 {
                decrypted[i + j] = block[j] ^ prev[j];
            }
        }

        let computed_hash = Sha256::digest(&decrypted);
        computed_hash[..] == content_hash[..]
            && computed_hash[..16].chunks_exact(4).enumerate().all(|(i, chunk)| {
                u32::from_le_bytes(chunk.try_into().unwrap()) == hash[i]
            })
    }

    fn shader_source(&self, _mode: &AttackModeType) -> &'static str { "" }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: Some("$keepass$"), hex_len: None, priority: 100 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let parts: Vec<&str> = s.split('*').collect();
        if parts.len() < 7 || parts[0] != "$keepass$" {
            return Err("Invalid KeePass format".to_string());
        }
        let _version = parts[1];
        let master_seed = hex::decode(parts[2]).map_err(|_| "Invalid master seed hex".to_string())?;
        let encrypted_key = hex::decode(parts[3]).map_err(|_| "Invalid encrypted key hex".to_string())?;
        let iv = hex::decode(parts[4]).map_err(|_| "Invalid IV hex".to_string())?;
        let content_hash = hex::decode(parts[5]).map_err(|_| "Invalid content hash hex".to_string())?;
        let transform_seed = hex::decode(parts[6]).map_err(|_| "Invalid transform seed hex".to_string())?;
        let transform_rounds = if parts.len() > 7 {
            parts[7].parse::<u64>().map_err(|_| "Invalid transform rounds".to_string())?
        } else {
            6000
        };

        if master_seed.len() != 32 {
            return Err("master seed must be 32 bytes".to_string());
        }
        if encrypted_key.len() != 32 {
            return Err("encrypted key must be 32 bytes".to_string());
        }
        if iv.len() != 16 {
            return Err("IV must be 16 bytes".to_string());
        }
        if content_hash.len() != 32 {
            return Err("content hash must be 32 bytes".to_string());
        }
        if transform_seed.len() != 32 {
            return Err("transform seed must be 32 bytes".to_string());
        }

        let mut salt = Vec::new();
        salt.extend_from_slice(_version.as_bytes());
        salt.push(b'*');
        salt.extend_from_slice(&master_seed);
        salt.push(b'*');
        salt.extend_from_slice(&encrypted_key);
        salt.push(b'*');
        salt.extend_from_slice(&iv);
        salt.push(b'*');
        salt.extend_from_slice(&content_hash);
        salt.push(b'*');
        salt.extend_from_slice(&transform_seed);
        salt.push(b'*');
        salt.extend_from_slice(&transform_rounds.to_le_bytes());

        let hash_words = [
            u32::from_le_bytes(content_hash[0..4].try_into().unwrap()),
            u32::from_le_bytes(content_hash[4..8].try_into().unwrap()),
            u32::from_le_bytes(content_hash[8..12].try_into().unwrap()),
            u32::from_le_bytes(content_hash[12..16].try_into().unwrap()),
            0, 0, 0, 0,
        ];

        Ok(ParsedHash { hash_words, extra_words: [0u32; 8], salt, digest_words: 4 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes256Enc;
    use cipher::block::BlockCipherEncrypt;
    use sha2::{Digest, Sha256};

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

    fn make_keepass_hash(
        password: &str,
        master_seed_hex: &str,
        iv_hex: &str,
        transform_seed_hex: &str,
        transform_rounds: u64,
    ) -> String {
        let master_seed = hex::decode(master_seed_hex).unwrap();
        let iv = hex::decode(iv_hex).unwrap();
        let transform_seed = hex::decode(transform_seed_hex).unwrap();

        let plaintext_key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
            0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
        ];

        let content_hash = Sha256::digest(&plaintext_key);

        let key = Sha256::digest(password.as_bytes());
        let mut current = key;
        for _ in 0..transform_rounds {
            let mut hasher = Sha256::new();
            hasher.update(&transform_seed);
            hasher.update(current);
            current = hasher.finalize();
        }
        let mut hasher = Sha256::new();
        hasher.update(&master_seed);
        hasher.update(current);
        hasher.update(&content_hash);
        let final_key = hasher.finalize();

        let encrypted = aes256_cbc_encrypt(&final_key, &iv, &plaintext_key);

        format!(
            "$keepass$*1*{}*{}*{}*{}*{}*{}",
            hex::encode(master_seed),
            hex::encode(&encrypted[..32]),
            hex::encode(iv),
            hex::encode(content_hash),
            hex::encode(transform_seed),
            transform_rounds,
        )
    }

    #[test]
    fn test_keepass_parse_valid_format() {
        let m = RawKeePass;
        let hash_str = make_keepass_hash(
            "testpassword",
            "90DFF48AD45DB0F5E0FC8B0A9B1C1F5A90DFF48AD45DB0F5E0FC8B0A9B1C1F5A",
            "D7B3A5F2E8C4A0B1D6E9F3C8B2A5D4E7",
            "B1C3D5E7F9A0B2C4D6E8F0A2B4C6D8E0B1C3D5E7F9A0B2C4D6E8F0A2B4C6D8E0",
            6000,
        );

        let parsed = m.parse_hash_string(&hash_str).unwrap();
        assert_eq!(parsed.digest_words, 4);
        assert!(parsed.salt.len() > 0);
        assert!(m.cpu_verify("testpassword", &parsed.salt, &parsed.hash_words));
        assert!(!m.cpu_verify("wrongpassword", &parsed.salt, &parsed.hash_words));
    }

    #[test]
    fn test_keepass_starts_with_prefix() {
        let m = RawKeePass;
        assert_eq!(m.detect_patterns()[0].prefix.unwrap(), "$keepass$");
    }

    #[test]
    fn test_keepass_parse_bad_hex() {
        let m = RawKeePass;
        let s = "$keepass$*1*ZZ*encrypted_key_hex*iv_hex*content_hash_hex*transform_seed_hex*6000";
        assert!(m.parse_hash_string(s).is_err());
    }

    #[test]
    fn test_keepass_parse_wrong_prefix() {
        let m = RawKeePass;
        let s = "$invalid$*1*aa*bb*cc*dd*ee*6000";
        assert!(m.parse_hash_string(s).is_err());
    }
}
