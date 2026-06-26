// bcrypt (hashcat -m 3200)
pub struct RawBcrypt;

use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

impl HashModule for RawBcrypt {
    fn name(&self) -> &'static str { "bcrypt" }
    fn mode(&self) -> u32 { 3200 }
    fn digest_words(&self) -> u32 { 6 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, _salt: &[u8], hash: &[u32]) -> bool {
        let raw = bcrypt_hash(password, "", 4);
        let mut words = [0u32; 6];
        for i in 0..6 {
            words[i] = u32::from_be_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap());
        }
        words == hash[..6]
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../bcrypt_crack.wgsl"),
            AttackModeType::Mask => include_str!("../bcrypt_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../bcrypt_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: Some("$2"), hex_len: None, priority: 80 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        use std::str::FromStr;
        let parts = bcrypt::HashParts::from_str(s)
            .map_err(|e| format!("Failed to parse bcrypt hash: {}", e))?;
        let salt_str = parts.get_salt();
        let _cost = parts.get_cost();

        // Decode base64 salt (22 chars -> 16 bytes)
        let salt_vec = decode_bcrypt_base64(&salt_str, 16)
            .map_err(|e| format!("Failed to decode bcrypt salt: {}", e))?;
        let mut salt_arr = [0u8; 16];
        salt_arr.copy_from_slice(&salt_vec);

        // Decode base64 hash (last 31 chars after the 22-char salt -> 23 bytes, padded to 24)
        let combined = s.rsplit('$').next().unwrap_or("");
        if combined.len() < 22 + 31 {
            return Err("Bcrypt hash string too short".to_string());
        }
        let hash_b64 = &combined[22..];  // skip 22-char salt
        let hash_vec = decode_bcrypt_base64(hash_b64, 23)
            .map_err(|e| format!("Failed to decode bcrypt hash: {}", e))?;

        let mut hash_bytes = [0u8; 24];
        hash_bytes[..23].copy_from_slice(&hash_vec);
        // 24th byte is zero (base64 encoding of 23 bytes + 2 bits padding)

        let mut hash_words = [0u32; 8];
        for i in 0..6 {
            let start = i * 4;
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&hash_bytes[start..start + 4]);
            // bcrypt stores output in big-endian u32 order
            hash_words[i] = u32::from_be_bytes(buf);
        }

        Ok(ParsedHash {
            hash_words,
            extra_words: [0u32; 8],
            salt: salt_arr.to_vec(),
            digest_words: 6,
        })
    }
}

/// Compute bcrypt hash: returns 24 raw bytes
/// Password is null-terminated internally (matching bcrypt crate's _hash_password)
pub fn bcrypt_hash(password: &str, salt: &str, cost: u32) -> [u8; 24] {
    let salt_bytes = if salt.len() == 16 {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(salt.as_bytes());
        arr
    } else if !salt.is_empty() {
        if let Ok(decoded) = decode_bcrypt_base64(salt, 16) {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&decoded);
            arr
        } else {
            let mut arr = [0u8; 16];
            let b = salt.as_bytes();
            let n = b.len().min(16);
            arr[..n].copy_from_slice(&b[..n]);
            arr
        }
    } else {
        [0u8; 16]
    };

    let pwd_bytes = {
        let pwd = password.as_bytes();
        let mut v = Vec::with_capacity(pwd.len() + 1);
        v.extend_from_slice(pwd);
        v.push(0);
        if v.len() > 72 {
            v.truncate(72);
        }
        v
    };

    bcrypt::bcrypt(cost, salt_bytes, &pwd_bytes)
}

/// Decode bcrypt custom base64 (standard crypt alphabet: ./A-Za-z0-9)
fn decode_bcrypt_base64_impl(chars: &[u8], expected_bytes: usize) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    fn idx(c: u8, alph: &[u8]) -> Result<u32, String> {
        alph.iter().position(|&x| x == c).map(|i| i as u32).ok_or_else(|| format!("Invalid base64 char: {}", c as char))
    }
    let mut out = Vec::with_capacity(expected_bytes);
    let mut i = 0;

    while out.len() < expected_bytes && i + 4 <= chars.len() {
        let c0 = idx(chars[i], ALPHABET)?;
        let c1 = idx(chars[i + 1], ALPHABET)?;
        let c2 = idx(chars[i + 2], ALPHABET)?;
        let c3 = idx(chars[i + 3], ALPHABET)?;
        let val = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
        out.push((val >> 16) as u8);
        if out.len() < expected_bytes { out.push((val >> 8) as u8); }
        if out.len() < expected_bytes { out.push(val as u8); }
        i += 4;
    }

    // Handle trailing 2-3 chars (bcrypt: 22-char salt, 31-char hash)
    if out.len() < expected_bytes && i + 2 <= chars.len() {
        let c0 = idx(chars[i], ALPHABET)?;
        let c1 = idx(chars[i + 1], ALPHABET)?;
        let val = (c0 << 18) | (c1 << 12);
        out.push((val >> 16) as u8);
        if out.len() < expected_bytes && i + 3 <= chars.len() {
            let c2 = idx(chars[i + 2], ALPHABET)?;
            let val = (c0 << 18) | (c1 << 12) | (c2 << 6);
            out.push((val >> 8) as u8);
        }
    }

    if out.len() != expected_bytes {
        return Err(format!("Expected {} bytes from base64, got {}", expected_bytes, out.len()));
    }
    Ok(out)
}

fn decode_bcrypt_base64(s: &str, expected_bytes: usize) -> Result<Vec<u8>, String> {
    decode_bcrypt_base64_impl(s.as_bytes(), expected_bytes)
}

/// Encode bytes to bcrypt custom base64
#[allow(dead_code)]
fn encode_bcrypt_base64(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let val = (data[i] as u32) << 16 | (data[i + 1] as u32) << 8 | data[i + 2] as u32;
        out.push(ALPHABET[(val >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(val >> 12 & 0x3f) as usize] as char);
        out.push(ALPHABET[(val >> 6 & 0x3f) as usize] as char);
        out.push(ALPHABET[(val & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let val = (data[i] as u32) << 16;
        out.push(ALPHABET[(val >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(val >> 12 & 0x3f) as usize] as char);
    } else if rem == 2 {
        let val = (data[i] as u32) << 16 | (data[i + 1] as u32) << 8;
        out.push(ALPHABET[(val >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(val >> 12 & 0x3f) as usize] as char);
        out.push(ALPHABET[(val >> 6 & 0x3f) as usize] as char);
    }
    out
}

#[test]
fn test_bcrypt_verify() {
    // Use the crate's hash function to generate, then verify
    let hash = bcrypt::hash("abc", 4).unwrap();
    eprintln!("BCRYPT HASH FOR abc: {}", hash);
    // Hash should start with $2b$04$ or $2a$04$
    assert!(hash.starts_with("$2"));
    assert!(bcrypt::verify("abc", &hash).unwrap());
    assert!(!bcrypt::verify("wrong_password", &hash).unwrap());
}

#[test]
fn test_bcrypt_parse_and_verify() {
    let hash_str = "$2b$04$crMTmHIF5jdy0n07vh/3ROpLLyDF6ah99PaO/xuI2dazgYeDlMJ82";
    // Parse the salt from the hash
    use std::str::FromStr;
    let parts = bcrypt::HashParts::from_str(hash_str).unwrap();
    let salt_str = parts.get_salt();
    let cost = parts.get_cost();
    eprintln!("Salt string (22 chars): '{}', cost: {}", salt_str, cost);
    
    // Decode salt from base64
    let salt_vec = decode_bcrypt_base64(&salt_str, 16).unwrap();
    eprintln!("Decoded salt (16 bytes): {:02x?}", salt_vec);
    
    let mut salt_arr = [0u8; 16];
    salt_arr.copy_from_slice(&salt_vec);
    
    // Compute hash with bcrypt crate (null-terminated, matching _hash_password)
    let raw = bcrypt::bcrypt(cost, salt_arr, b"abc\0");
    eprintln!("Raw bcrypt hash (24 bytes): {:02x?}", raw);
    
    // Decode the hash from the hash string
    let combined = hash_str.rsplit('$').next().unwrap_or("");
    let hash_b64 = &combined[22..];  // skip 22-char salt
    eprintln!("Hash part (31 chars): '{}'", hash_b64);
    let hash_bytes = decode_bcrypt_base64(hash_b64, 23).unwrap();
    eprintln!("Decoded hash from string (23 bytes): {:02x?}", hash_bytes);
    
    // Re-encode the decoded hash bytes (23 bytes) to base64 to compare with original
    let encoded_hash_bytes = encode_bcrypt_base64(&hash_bytes);
    eprintln!("Encoded decoded hash (23→31 chars): '{}'", encoded_hash_bytes);
    eprintln!("Expected hash b64 (31 chars):          '{}'", hash_b64);
    
    // Also re-encode the raw bcrypt hash (only first 23 bytes, matching the hash string)
    let encoded_raw = encode_bcrypt_base64(&raw[..23]);
    eprintln!("Encoded raw[..23] (23→31 chars): '{}'", encoded_raw);
    let encoded_truncated = &encoded_raw;
    
    // Verify truncated match
    assert_eq!(encoded_truncated, hash_b64, "Encoded hash should match hash part");
    
    // Test: re-encode the salt and verify it matches the salt from the hash
    let encoded_salt = encode_bcrypt_base64(&salt_arr);
    eprintln!("Encoded salt (16→22 chars):  '{}'", encoded_salt);
    eprintln!("Expected salt (22 chars):    '{}'", salt_str);
    assert_eq!(encoded_salt, salt_str, "Salt roundtrip should match");
    
    // Now test our bcrypt_hash function
    let our_result = bcrypt_hash("abc", &salt_str, cost);
    eprintln!("Our bcrypt_hash result (24 bytes): {:02x?}", our_result);
    assert_eq!(our_result, raw, "Our bcrypt_hash should match crate's bcrypt");
    
    // Test with default salt (empty string)
    let default_result = bcrypt_hash("abc", "", 4);
    eprintln!("Default salt result: {:02x?}", default_result);
}

#[test]
fn test_bcrypt_raw() {
    let salt = [0u8; 16];
    let result = bcrypt::bcrypt(4, salt, b"abc");
    assert_eq!(result.len(), 24);
    let result2 = bcrypt::bcrypt(4, salt, b"abc");
    assert_eq!(result, result2);
}

#[test]
fn test_bcrypt_base64_roundtrip() {
    let data = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let encoded = encode_bcrypt_base64(&data);
    let decoded = decode_bcrypt_base64(&encoded, 24).unwrap();
    assert_eq!(data.as_slice(), decoded.as_slice());
}

#[test]
fn test_bcrypt_debug_target_words() {
    let hash_str = "$2b$04$crMTmHIF5jdy0n07vh/3ROpLLyDF6ah99PaO/xuI2dazgYeDlMJ82";
    // Parse salt
    use std::str::FromStr;
    let parts = bcrypt::HashParts::from_str(hash_str).unwrap();
    let salt_str = parts.get_salt();
    let cost = parts.get_cost();
    let salt_vec = decode_bcrypt_base64(&salt_str, 16).unwrap();
    let mut salt_arr = [0u8; 16];
    salt_arr.copy_from_slice(&salt_vec);
    
    // Compute full 24-byte hash
    let raw = bcrypt::bcrypt(cost, salt_arr, b"abc\0");
    eprintln!("Full 24-byte hash: {:02x?}", raw);
    
    // Target hash words from 23-byte (truncated) decoded hash
    let combined = hash_str.rsplit('$').next().unwrap_or("");
    let hash_b64 = &combined[22..];
    let hash_bytes_decoded = decode_bcrypt_base64(hash_b64, 23).unwrap();
    let mut target_hash_bytes = [0u8; 24];
    target_hash_bytes[..23].copy_from_slice(&hash_bytes_decoded);
    let mut target_words = [0u32; 6];
    for i in 0..6 {
        let start = i * 4;
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&target_hash_bytes[start..start+4]);
        target_words[i] = u32::from_be_bytes(buf);
    }
    
    // GPU computed words (from full 24-byte)
    let mut gpu_words = [0u32; 6];
    for i in 0..6 {
        gpu_words[i] = u32::from_be_bytes(raw[i*4..i*4+4].try_into().unwrap());
    }
    
    eprintln!("Target words (23-byte):  {:08x?}", target_words);
    eprintln!("GPU words (24-byte):     {:08x?}", gpu_words);
    
    // Check comparison with the mask
    let masked_gpu5 = gpu_words[5] & 0xFFFFFF00;
    eprintln!("Masked gpu[5] ({:08x} & FFFFFF00 = {:08x}) vs target[5] ({:08x})", 
        gpu_words[5], masked_gpu5, target_words[5]);
    eprintln!("All 6 match (masked): {}", target_words == gpu_words);
    eprintln!("First 5 match: {}", target_words[..5] == gpu_words[..5]);
    eprintln!("Word 5 match masked: {}", masked_gpu5 == target_words[5]);
}


