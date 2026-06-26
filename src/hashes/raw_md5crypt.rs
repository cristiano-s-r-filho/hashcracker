pub struct RawMd5Crypt;

use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

impl HashModule for RawMd5Crypt {
    fn name(&self) -> &'static str { "md5crypt" }
    fn mode(&self) -> u32 { 500 }
    fn digest_words(&self) -> u32 { 4 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        let salt_str = std::str::from_utf8(salt).unwrap_or("");
        let full_hash = md5crypt(password, salt_str);
        // Parse the hash to compare raw words
        if let Ok(parsed) = self.parse_hash_string(&full_hash) {
            parsed.hash_words[..4] == hash[..4]
        } else {
            false
        }
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../md5crypt_crack.wgsl"),
            AttackModeType::Mask => include_str!("../md5crypt_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../md5crypt_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: Some("$1$"), hex_len: None, priority: 50 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let s = s.trim();
        if !s.starts_with("$1$") {
            return Err("Expected $1$ prefix for md5crypt".to_string());
        }
        let rest = &s[3..];
        let parts: Vec<&str> = rest.split('$').collect();
        if parts.len() != 2 || parts[1].is_empty() {
            return Err(format!("Invalid md5crypt format '{}'. Expected $1$salt$hash", s));
        }
        let salt_str = parts[0];
        if salt_str.len() > 8 {
            return Err(format!("md5crypt salt too long (max 8 chars): {}", salt_str.len()));
        }
        let hash_encoded = parts[1];
        if hash_encoded.len() != 22 {
            return Err(format!("Expected 22-char md5crypt hash, got {}", hash_encoded.len()));
        }

        let salt_bytes = salt_str.as_bytes().to_vec();
        let hash_bytes = decode_md5crypt_hash(hash_encoded)?;
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

const B64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn b64_idx(c: u8) -> Option<usize> {
    B64.iter().position(|&x| x == c)
}

fn decode_md5crypt_hash(encoded: &str) -> Result<[u8; 16], String> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 22 {
        return Err("md5crypt hash must be 22 chars".to_string());
    }

    let v: Result<Vec<u8>, String> = bytes.iter().map(|&c| {
        b64_idx(c).map(|p| p as u8).ok_or_else(|| format!("Invalid base64 char: {}", c as char))
    }).collect();
    let v = v?;

    // 5 groups of 4 chars each = 20 chars => 15 bytes
    // 1 group of 2 chars => 1 byte
    // Total: 22 chars -> 16 bytes
    let mut out = [0u8; 16];

    for i in 0..5 {
        let a = v[i * 4] as u32;
        let b = v[i * 4 + 1] as u32;
        let c = v[i * 4 + 2] as u32;
        let d = v[i * 4 + 3] as u32;
        let value = a | (b << 6) | (c << 12) | (d << 18);
        out[i] = ((value >> 16) & 0xFF) as u8;
        out[i + 6] = ((value >> 8) & 0xFF) as u8;
        if i < 4 {
            out[i + 12] = (value & 0xFF) as u8;
        } else {
            out[5] = (value & 0xFF) as u8;
        }
    }

    // Last 2 chars produce byte 11
    let a = v[20] as u32;
    let b = v[21] as u32;
    out[11] = (a | (b << 6)) as u8;

    Ok(out)
}

pub fn encode_md5crypt_hash(hash: &[u8; 16]) -> String {
    let mut out = [0u8; 22];

    for i in 0..5 {
        let value = (hash[i] as u32) << 16
            | (hash[i + 6] as u32) << 8
            | if i < 4 { hash[i + 12] as u32 } else { hash[5] as u32 };
        out[i * 4] = B64[(value & 0x3F) as usize];
        out[i * 4 + 1] = B64[((value >> 6) & 0x3F) as usize];
        out[i * 4 + 2] = B64[((value >> 12) & 0x3F) as usize];
        out[i * 4 + 3] = B64[((value >> 18) & 0x3F) as usize];
    }

    // Last group: byte 11 -> 2 chars
    let value = hash[11] as u32;
    out[20] = B64[(value & 0x3F) as usize];
    out[21] = B64[((value >> 6) & 0x3F) as usize];

    String::from_utf8(out.to_vec()).unwrap()
}

pub fn md5crypt(password: &str, salt: &str) -> String {
    use md5::{Md5, Digest};

    let pwd = password.as_bytes();
    let salt_bytes = salt.as_bytes();

    // Step 1: digest_a = MD5(password + "$1$" + salt)
    let mut a_ctx = Md5::new();
    a_ctx.update(pwd);
    a_ctx.update(b"$1$");
    a_ctx.update(salt_bytes);

    // Step 2: digest_b = MD5(password + salt + password)
    let mut b_ctx = Md5::new();
    b_ctx.update(pwd);
    b_ctx.update(salt_bytes);
    b_ctx.update(pwd);
    let digest_b = b_ctx.finalize();

    // Step 3: Append digest_b bytes interleaved by password length
    let mut j = 0;
    while j < pwd.len() {
        let n = std::cmp::min(pwd.len() - j, 16);
        a_ctx.update(&digest_b[..n]);
        j += 16;
    }

    // Step 4: Process each bit of password length
    let mut n = pwd.len();
    while n > 0 {
        if (n & 1) != 0 {
            a_ctx.update(&[0u8]);
        } else {
            a_ctx.update(&[pwd[0]]);
        }
        n >>= 1;
    }

    // Step 5: Finalize initial digest
    let mut digest = [0u8; 16];
    digest.copy_from_slice(&a_ctx.finalize());

    // Step 6: 1000 rounds
    for i in 0..1000 {
        let mut ctx = Md5::new();
        if (i & 1) != 0 {
            ctx.update(pwd);
        } else {
            ctx.update(&digest);
        }
        if (i % 3) != 0 {
            ctx.update(salt_bytes);
        }
        if (i % 7) != 0 {
            ctx.update(pwd);
        }
        if (i & 1) != 0 {
            ctx.update(&digest);
        } else {
            ctx.update(pwd);
        }
        let result = ctx.finalize();
        digest.copy_from_slice(&result);
    }

    // Step 7: Encode
    format!("$1${}${}", salt, encode_md5crypt_hash(&digest))
}

#[test]
fn test_md5crypt_hunter2() {
    // From md5crypt crate test vector
    let hash = md5crypt("hunter2", "1234abcd");
    assert_eq!(hash, "$1$1234abcd$k941IFPqhCBpKvhOnZqRd/");
}

#[test]
fn test_md5crypt_roundtrip() {
    let module = RawMd5Crypt;
    let hash = md5crypt("test123", "abc");
    let parsed = module.parse_hash_string(&hash).unwrap();
    assert_eq!(parsed.digest_words, 4);
    assert_eq!(parsed.salt, b"abc");
}

#[test]
fn test_md5crypt_regression() {
    assert_eq!(md5crypt("password", "saltsalt"), "$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/");
    assert_eq!(md5crypt("password", "abc"), "$1$abc$BXBqpb9BZcZhXLgbee.0s/");
    assert_eq!(md5crypt("test123", "abc"), "$1$abc$0zyr.q.R6J8FreshPZmKj.");
    assert_eq!(md5crypt("test", ""), "$1$$whuMjZj.HMFoaTaZRRtkO0");
}
