pub struct RawDrupal7;

use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};
use sha2::{Digest, Sha512};
use std::sync::LazyLock;

const ITOA64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static ITOA64_MAP: LazyLock<[u8; 256]> = LazyLock::new(|| {
    let mut map = [0xFFu8; 256];
    for (i, &c) in ITOA64.iter().enumerate() {
        map[c as usize] = i as u8;
    }
    map
});

fn itoa64_idx(c: u8) -> Option<u8> {
    let idx = ITOA64_MAP[c as usize];
    if idx == 0xFF { None } else { Some(idx) }
}

fn drupal7_encode64(hash: &[u8]) -> String {
    let count = hash.len();
    let mut out = Vec::new();
    let mut bi = 0usize;
    while bi + 3 <= count {
        let value = (hash[bi] as u32) | ((hash[bi + 1] as u32) << 8) | ((hash[bi + 2] as u32) << 16);
        out.push(ITOA64[(value & 0x3f) as usize]);
        out.push(ITOA64[((value >> 6) & 0x3f) as usize]);
        out.push(ITOA64[((value >> 12) & 0x3f) as usize]);
        out.push(ITOA64[((value >> 18) & 0x3f) as usize]);
        bi += 3;
    }
    if bi < count {
        let remaining = count - bi;
        if remaining == 1 {
            let value = hash[bi] as u32;
            out.push(ITOA64[(value & 0x3f) as usize]);
            out.push(ITOA64[((value >> 6) & 0x3f) as usize]);
        } else {
            let value = (hash[bi] as u32) | ((hash[bi + 1] as u32) << 8);
            out.push(ITOA64[(value & 0x3f) as usize]);
            out.push(ITOA64[((value >> 6) & 0x3f) as usize]);
            out.push(ITOA64[((value >> 12) & 0x3f) as usize]);
            out.push(ITOA64[((value >> 18) & 0x3f) as usize]);
        }
    }
    String::from_utf8(out).unwrap()
}

fn drupal7_decode64(encoded: &str) -> Result<Vec<u8>, String> {
    let bytes = encoded.as_bytes();
    let mut out = Vec::new();
    let mut ci = 0usize;
    while ci + 4 <= bytes.len() {
        let c0 = itoa64_idx(bytes[ci]).ok_or("Invalid base64 char")? as u32;
        let c1 = itoa64_idx(bytes[ci + 1]).ok_or("Invalid base64 char")? as u32;
        let c2 = itoa64_idx(bytes[ci + 2]).ok_or("Invalid base64 char")? as u32;
        let c3 = itoa64_idx(bytes[ci + 3]).ok_or("Invalid base64 char")? as u32;
        ci += 4;
        let value = c0 | (c1 << 6) | (c2 << 12) | (c3 << 18);
        out.push((value & 0xff) as u8);
        out.push(((value >> 8) & 0xff) as u8);
        out.push(((value >> 16) & 0xff) as u8);
    }
    if ci < bytes.len() {
        let c0 = itoa64_idx(bytes[ci]).ok_or("Invalid base64 char")? as u32;
        let c1 = itoa64_idx(bytes[ci + 1]).ok_or("Invalid base64 char")? as u32;
        let value = c0 | (c1 << 6);
        out.push((value & 0xff) as u8);
    }
    Ok(out)
}

pub fn drupal7_hash(password: &str, setting: &str) -> String {
    let s = if setting.starts_with("$S$") { &setting[3..] } else { setting };
    if s.len() < 9 { return String::new(); }
    let count_log2 = itoa64_idx(s.as_bytes()[0]).unwrap_or(7) as u32;
    let count = 1u32 << count_log2;
    let salt_bytes = &s.as_bytes()[1..9];
    let pwd = password.as_bytes();

    let mut hash = {
        let mut ctx = Sha512::new();
        ctx.update(salt_bytes);
        ctx.update(pwd);
        let result = ctx.finalize();
        let mut h = vec![0u8; 64];
        h.copy_from_slice(&result);
        h
    };

    for _ in 0..count {
        let mut ctx = Sha512::new();
        ctx.update(&hash);
        ctx.update(pwd);
        let result = ctx.finalize();
        hash.copy_from_slice(&result);
    }

    let encoded_hash = drupal7_encode64(&hash[..40]);
    format!("{}{}", &setting[..12], encoded_hash)
}

impl RawDrupal7 {
    pub fn count_log2_from_char(&self, c: u8) -> u32 {
        itoa64_idx(c).unwrap_or(7) as u32
    }
}

impl HashModule for RawDrupal7 {
    fn name(&self) -> &'static str { "drupal7" }
    fn mode(&self) -> u32 { 7900 }
    fn digest_words(&self) -> u32 { 10 }
    fn needs_int64(&self) -> bool { true }

    fn cpu_verify(&self, password: &str, _salt: &[u8], hash: &[u32]) -> bool {
        let full_hash = drupal7_hash(password, "$S$");
        if let Ok(parsed) = self.parse_hash_string(&full_hash) {
            parsed.hash_words[..5] == hash[..5]
                && parsed.extra_words[..5] == hash[5..10]
        } else {
            false
        }
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../drupal7_crack.wgsl"),
            AttackModeType::Mask => include_str!("../drupal7_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../drupal7_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: Some("$S$"), hex_len: None, priority: 50 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let s = s.trim();
        if !s.starts_with("$S$") {
            return Err("Expected $S$ prefix for Drupal 7".to_string());
        }
        let rest = &s[3..];
        if rest.len() < 63 {
            return Err(format!("Invalid Drupal 7 format '{}': too short", s));
        }
        let _count_char = rest.as_bytes()[0];
        let salt_str = &rest[1..9];
        let hash_encoded = &rest[9..63];
        if hash_encoded.len() != 54 {
            return Err(format!("Expected 54-char Drupal 7 hash, got {}", hash_encoded.len()));
        }

        let salt_bytes = salt_str.as_bytes().to_vec();
        let hash_bytes = drupal7_decode64(hash_encoded)?;
        if hash_bytes.len() != 40 {
            return Err(format!("Expected 40 bytes decoded, got {}", hash_bytes.len()));
        }

        let mut target = [0u32; 8];
        let mut extra = [0u32; 8];
        // 40 bytes = 5 u64 words (big-endian)
        for i in 0..5 {
            let word = u64::from_be_bytes(hash_bytes[i * 8..i * 8 + 8].try_into().unwrap());
            target[i] = word as u32;
            extra[i] = (word >> 32) as u32;
        }

        Ok(ParsedHash {
            hash_words: target,
            extra_words: extra,
            salt: salt_bytes,
            digest_words: 10,
        })
    }
}

#[test]
fn test_drupal7_basic() {
    let hash = drupal7_hash("test", "$S$Dabc12345");
    assert!(hash.starts_with("$S$D"));
    assert_eq!(hash.len(), 66);
}

#[test]
fn test_drupal7_starts_with_prefix() {
    let hash = drupal7_hash("test", "$S$Cabc12345");
    assert!(hash.starts_with("$S$C"));
    assert_eq!(hash.len(), 66);
}

#[test]
fn test_drupal7_encode_decode_roundtrip() {
    let test_bytes: Vec<u8> = (0..40).map(|i| (i * 17 + 3) as u8).collect();
    let encoded = drupal7_encode64(&test_bytes);
    assert_eq!(encoded.len(), 54);
    let decoded = drupal7_decode64(&encoded).unwrap();
    assert_eq!(test_bytes, decoded);
}

#[test]
fn test_drupal7_known() {
    let hash = drupal7_hash("test123", "$S$Cabc12345");
    assert!(hash.starts_with("$S$Cabc12345"));
    assert_eq!(hash.len(), 66);
}
