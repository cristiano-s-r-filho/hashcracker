pub struct RawPhpass;

use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};
use md5::{Digest, Md5};
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

fn phpass_encode64(hash: &[u8; 16]) -> String {
    let mut out = [0u8; 22];
    let mut bi = 0usize;
    let mut oi = 0usize;
    while bi < 15 {
        let value = (hash[bi] as u32) | ((hash[bi + 1] as u32) << 8) | ((hash[bi + 2] as u32) << 16);
        out[oi] = ITOA64[(value & 0x3f) as usize];
        out[oi + 1] = ITOA64[((value >> 6) & 0x3f) as usize];
        out[oi + 2] = ITOA64[((value >> 12) & 0x3f) as usize];
        out[oi + 3] = ITOA64[((value >> 18) & 0x3f) as usize];
        bi += 3;
        oi += 4;
    }
    let value = hash[15] as u32;
    out[oi] = ITOA64[(value & 0x3f) as usize];
    out[oi + 1] = ITOA64[((value >> 6) & 0x3f) as usize];
    String::from_utf8(out.to_vec()).unwrap()
}

fn phpass_decode64(encoded: &str) -> Result<[u8; 16], String> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 22 {
        return Err(format!("phpass hash must be 22 chars, got {}", bytes.len()));
    }
    let mut out = [0u8; 16];
    let mut ci = 0usize;
    let mut oi = 0usize;
    while ci < 20 {
        let c0 = itoa64_idx(bytes[ci]).ok_or("Invalid base64 char")? as u32;
        let c1 = itoa64_idx(bytes[ci + 1]).ok_or("Invalid base64 char")? as u32;
        let c2 = itoa64_idx(bytes[ci + 2]).ok_or("Invalid base64 char")? as u32;
        let c3 = itoa64_idx(bytes[ci + 3]).ok_or("Invalid base64 char")? as u32;
        ci += 4;
        let value = c0 | (c1 << 6) | (c2 << 12) | (c3 << 18);
        out[oi] = (value & 0xff) as u8;
        out[oi + 1] = ((value >> 8) & 0xff) as u8;
        out[oi + 2] = ((value >> 16) & 0xff) as u8;
        oi += 3;
    }
    let c0 = itoa64_idx(bytes[ci]).ok_or("Invalid base64 char")? as u32;
    let c1 = itoa64_idx(bytes[ci + 1]).ok_or("Invalid base64 char")? as u32;
    let value = c0 | (c1 << 6);
    out[oi] = (value & 0xff) as u8;
    Ok(out)
}

fn itoa64_char_to_count(c: u8) -> u32 {
    let idx = itoa64_idx(c).unwrap_or(5);
    1u32 << idx
}

pub fn itoa64_char_to_log2(c: u8) -> u32 {
    itoa64_idx(c).unwrap_or(5) as u32
}

#[allow(dead_code)]
fn count_to_itoa64_char(count: u32) -> u8 {
    let mut log2 = 0u32;
    let mut c = count;
    while c > 1 { c >>= 1; log2 += 1; }
    ITOA64[log2 as usize]
}

pub fn phpass_hash(password: &str, encoded: &str) -> String {
    let pwd = password.as_bytes();
    let _pwd_len = pwd.len();

    let s = if encoded.starts_with("$P$") || encoded.starts_with("$H$") {
        &encoded[3..]
    } else {
        encoded
    };

    if s.len() < 9 {
        return String::new();
    }

    let count_char = s.as_bytes()[0];
    let count = itoa64_char_to_count(count_char);
    let salt_bytes = s[1..9].as_bytes();
    let salt_len = salt_bytes.len().min(8);

    let mut ctx = Md5::new();
    ctx.update(&salt_bytes[..salt_len]);
    ctx.update(pwd);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&ctx.finalize_reset());

    for _ in 0..count {
        ctx.update(&hash);
        ctx.update(pwd);
        hash.copy_from_slice(&ctx.finalize_reset());
    }

    let encoded_hash = phpass_encode64(&hash);
    format!("{}{}{}", &encoded[..3], &s[..9], encoded_hash)
}

impl RawPhpass {
    pub fn count_log2_from_char(&self, c: u8) -> u32 {
        itoa64_char_to_log2(c)
    }
}

impl HashModule for RawPhpass {
    fn name(&self) -> &'static str { "phpass" }
    fn mode(&self) -> u32 { 400 }
    fn digest_words(&self) -> u32 { 4 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, _salt: &[u8], hash: &[u32]) -> bool {
        let full_hash = phpass_hash(password, "$P$");
        if let Ok(parsed) = self.parse_hash_string(&full_hash) {
            parsed.hash_words[..4] == hash[..4]
        } else {
            false
        }
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../phpass_crack.wgsl"),
            AttackModeType::Mask => include_str!("../phpass_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../phpass_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[
            HashPattern { prefix: Some("$P$"), hex_len: None, priority: 50 },
            HashPattern { prefix: Some("$H$"), hex_len: None, priority: 50 },
        ]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let s = s.trim();
        if !s.starts_with("$P$") && !s.starts_with("$H$") {
            return Err("Expected $P$ or $H$ prefix for phpass".to_string());
        }
        let rest = &s[3..];
        if rest.len() < 31 {
            return Err(format!("Invalid phpass format '{}': too short", s));
        }
        let _count_char = rest.as_bytes()[0];
        let salt_str = &rest[1..9];
        let hash_encoded = &rest[9..31];
        if hash_encoded.len() != 22 {
            return Err(format!("Expected 22-char phpass hash, got {}", hash_encoded.len()));
        }

        let salt_bytes = salt_str.as_bytes().to_vec();
        let hash_bytes = phpass_decode64(hash_encoded)?;
        let mut target = [0u32; 8];
        for i in 0..4 {
            target[i] = u32::from_le_bytes(hash_bytes[i * 4..i * 4 + 4].try_into().unwrap());
        }

        Ok(ParsedHash {
            hash_words: target,
            extra_words: [0u32; 8],
            salt: salt_bytes,
            digest_words: 4,
        })
    }
}

#[test]
fn test_phpass_hashcat() {
    let hash = phpass_hash("hashcat", "$P$9I2pgToWU");
    assert_eq!(hash, "$P$9I2pgToWUrbGvOGBJVY1UE54NILgRQ.");
}

#[test]
fn test_phpass_12345() {
    let hash = phpass_hash("12345", "$P$B5b5HfkMS");
    assert_eq!(hash, "$P$B5b5HfkMS13sz43hDGKyWBWtMpgpO31");
}

#[test]
fn test_phpass_format() {
    let hash = phpass_hash("password", "$P$Babcdefgh");
    assert!(hash.starts_with("$P$B"));
    assert_eq!(hash.len(), 34);
}

#[test]
fn test_phpass_roundtrip() {
    let module = RawPhpass;
    let hash = phpass_hash("test123", "$P$Babc12345");
    let parsed = module.parse_hash_string(&hash).unwrap();
    assert_eq!(parsed.digest_words, 4);
    assert_eq!(parsed.salt, b"abc12345");
    let re_encoded = phpass_encode64(&{
        let mut h = [0u8; 16];
        for i in 0..4 {
            let w = parsed.hash_words[i].to_le_bytes();
            h[i*4..i*4+4].copy_from_slice(&w);
        }
        h
    });
    assert_eq!(re_encoded, &hash[12..]);
}

#[test]
fn test_phpass_encode_decode_roundtrip() {
    let test_bytes = [0x12u8, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let encoded = phpass_encode64(&test_bytes);
    let decoded = phpass_decode64(&encoded).unwrap();
    assert_eq!(test_bytes, decoded);
}
