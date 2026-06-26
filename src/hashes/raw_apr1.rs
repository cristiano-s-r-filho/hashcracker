use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawApr1;

impl HashModule for RawApr1 {
    fn name(&self) -> &'static str { "apr1" }
    fn mode(&self) -> u32 { 1600 }
    fn digest_words(&self) -> u32 { 4 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        let salt_str = std::str::from_utf8(salt).unwrap_or("");
        let full_hash = apr1_hash(password, salt_str);
        if let Ok(parsed) = self.parse_hash_string(&full_hash) {
            parsed.hash_words[..4] == hash[..4]
        } else {
            false
        }
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../apr1_crack.wgsl"),
            AttackModeType::Mask => include_str!("../apr1_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../apr1_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: Some("$apr1$"), hex_len: None, priority: 50 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let s = s.trim();
        if !s.starts_with("$apr1$") {
            return Err("Expected $apr1$ prefix for Apache APR1".to_string());
        }
        let rest = &s[6..];
        let parts: Vec<&str> = rest.split('$').collect();
        if parts.len() != 2 || parts[1].is_empty() {
            return Err(format!("Invalid APR1 format '{}'. Expected $apr1$salt$hash", s));
        }
        let salt_str = parts[0];
        if salt_str.len() > 8 {
            return Err(format!("APR1 salt too long (max 8 chars): {}", salt_str.len()));
        }
        let hash_encoded = parts[1];
        if hash_encoded.len() != 22 {
            return Err(format!("Expected 22-char APR1 hash, got {}", hash_encoded.len()));
        }

        let salt_bytes = salt_str.as_bytes().to_vec();
        let hash_bytes = decode_apr1_hash(hash_encoded)?;
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

fn decode_apr1_hash(encoded: &str) -> Result<[u8; 16], String> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 22 {
        return Err("APR1 hash must be 22 chars".to_string());
    }

    let v: Result<Vec<u8>, String> = bytes.iter().map(|&c| {
        b64_idx(c).map(|p| p as u8).ok_or_else(|| format!("Invalid base64 char: {}", c as char))
    }).collect();
    let v = v?;

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

    let a = v[20] as u32;
    let b = v[21] as u32;
    out[11] = (a | (b << 6)) as u8;

    Ok(out)
}

pub fn encode_apr1_hash(hash: &[u8; 16]) -> String {
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

    let value = hash[11] as u32;
    out[20] = B64[(value & 0x3F) as usize];
    out[21] = B64[((value >> 6) & 0x3F) as usize];

    String::from_utf8(out.to_vec()).unwrap()
}

pub fn apr1_hash(password: &str, salt: &str) -> String {
    use md5::{Md5, Digest};

    let pwd = password.as_bytes();
    let salt_bytes = salt.as_bytes();

    let mut a_ctx = Md5::new();
    a_ctx.update(pwd);
    a_ctx.update(b"$apr1$");
    a_ctx.update(salt_bytes);

    let mut b_ctx = Md5::new();
    b_ctx.update(pwd);
    b_ctx.update(salt_bytes);
    b_ctx.update(pwd);
    let digest_b = b_ctx.finalize();

    let mut j = 0;
    while j < pwd.len() {
        let n = std::cmp::min(pwd.len() - j, 16);
        a_ctx.update(&digest_b[..n]);
        j += 16;
    }

    let mut n = pwd.len();
    while n > 0 {
        if (n & 1) != 0 {
            a_ctx.update(&[0u8]);
        } else {
            a_ctx.update(&[pwd[0]]);
        }
        n >>= 1;
    }

    let mut digest = [0u8; 16];
    digest.copy_from_slice(&a_ctx.finalize());

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

    format!("$apr1${}${}", salt, encode_apr1_hash(&digest))
}

#[test]
fn test_apr1_openssl_vectors() {
    // These vectors are verified against `openssl passwd -apr1`
    assert_eq!(apr1_hash("password", "saltsalt"), "$apr1$saltsalt$yAAkm4libquA.ZWLHbSBq/");
    assert_eq!(apr1_hash("hunter2", "1234abcd"), "$apr1$1234abcd$9CIaClZ4r0Ls0lioox8Vb1");
    assert_eq!(apr1_hash("hello", "8sFt66rZ"), "$apr1$8sFt66rZ$Y7XkHshZq90L3ql/CaLy50");
}

#[test]
fn test_apr1_roundtrip() {
    let module = RawApr1;
    let hash = apr1_hash("test123", "abc");
    let parsed = module.parse_hash_string(&hash).unwrap();
    assert_eq!(parsed.digest_words, 4);
    assert_eq!(parsed.salt, b"abc");
}
