pub struct RawSha256Crypt;

use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};
use sha2::{Digest, Sha256};

impl HashModule for RawSha256Crypt {
    fn name(&self) -> &'static str { "sha256crypt" }
    fn mode(&self) -> u32 { 7400 }
    fn digest_words(&self) -> u32 { 8 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        let salt_str = std::str::from_utf8(salt).unwrap_or("");
        let full_salt = if salt_str.starts_with("$5$") {
            salt_str.to_string()
        } else {
            format!("$5${}", salt_str)
        };
        let full_hash = sha256crypt(password, &full_salt);
        if let Ok(parsed) = self.parse_hash_string(&full_hash) {
            parsed.hash_words[..8] == hash[..8]
        } else {
            false
        }
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../sha256crypt_crack.wgsl"),
            AttackModeType::Mask => include_str!("../sha256crypt_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../sha256crypt_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: Some("$5$"), hex_len: None, priority: 50 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let s = s.trim();
        if !s.starts_with("$5$") {
            return Err("Expected $5$ prefix for sha256crypt".to_string());
        }
        let rest = &s[3..];
        let rest = if rest.starts_with("rounds=") {
            let rest2 = &rest[7..];
            if let Some(dollar_pos) = rest2.find('$') {
                &rest2[dollar_pos + 1..]
            } else {
                return Err(format!("Invalid sha256crypt format '{}'", s));
            }
        } else {
            rest
        };
        let parts: Vec<&str> = rest.split('$').collect();
        if parts.len() != 2 || parts[1].is_empty() {
            return Err(format!("Invalid sha256crypt format '{}'. Expected $5$salt$hash", s));
        }
        let salt_str = parts[0];
        if salt_str.len() > 16 {
            return Err(format!("sha256crypt salt too long (max 16 chars): {}", salt_str.len()));
        }
        let hash_encoded = parts[1];
        if hash_encoded.len() != 43 {
            return Err(format!("Expected 43-char sha256crypt hash, got {}", hash_encoded.len()));
        }

        let salt_bytes = salt_str.as_bytes().to_vec();
        let hash_bytes = decode_sha256crypt_hash(hash_encoded)?;
        let mut target = [0u32; 8];
        for i in 0..8 {
            target[i] = u32::from_le_bytes(hash_bytes[i * 4..i * 4 + 4].try_into().unwrap());
        }

        Ok(ParsedHash {
            hash_words: target,
            extra_words: [0u32; 8],
            salt: salt_bytes,
            digest_words: 8,
        })
    }
}

const B64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn b64_idx(c: u8) -> Option<usize> {
    B64.iter().position(|&x| x == c)
}

fn decode_sha256crypt_hash(encoded: &str) -> Result<[u8; 32], String> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 43 {
        return Err(format!("sha256crypt hash must be 43 chars, got {}", bytes.len()));
    }

    let v: Result<Vec<u8>, String> = bytes.iter().map(|&c| {
        b64_idx(c).map(|p| p as u8).ok_or_else(|| format!("Invalid base64 char: {}", c as char))
    }).collect();
    let v = v?;

    let mut out = [0u8; 32];

    let groups: [(usize, usize, usize); 10] = [
        (0, 10, 20),
        (21, 1, 11),
        (12, 22, 2),
        (3, 13, 23),
        (24, 4, 14),
        (15, 25, 5),
        (6, 16, 26),
        (27, 7, 17),
        (18, 28, 8),
        (9, 19, 29),
    ];

    for (gi, &(b2, b1, b0)) in groups.iter().enumerate() {
        let a = v[gi * 4] as u32;
        let b = v[gi * 4 + 1] as u32;
        let c = v[gi * 4 + 2] as u32;
        let d = v[gi * 4 + 3] as u32;
        let w = a | (b << 6) | (c << 12) | (d << 18);
        out[b2] = ((w >> 16) & 0xFF) as u8;
        out[b1] = ((w >> 8) & 0xFF) as u8;
        out[b0] = (w & 0xFF) as u8;
    }

    let a = v[40] as u32;
    let b = v[41] as u32;
    let c = v[42] as u32;
    let w = a | (b << 6) | (c << 12);
    out[31] = ((w >> 8) & 0xFF) as u8;
    out[30] = (w & 0xFF) as u8;

    Ok(out)
}

fn encode_sha256crypt_hash(hash: &[u8; 32]) -> String {
    let mut out = [0u8; 43];

    let groups: [(usize, usize, usize); 10] = [
        (0, 10, 20),
        (21, 1, 11),
        (12, 22, 2),
        (3, 13, 23),
        (24, 4, 14),
        (15, 25, 5),
        (6, 16, 26),
        (27, 7, 17),
        (18, 28, 8),
        (9, 19, 29),
    ];

    let mut pos = 0usize;
    for &(b2, b1, b0) in &groups {
        let w = (hash[b2] as u32) << 16 | (hash[b1] as u32) << 8 | (hash[b0] as u32);
        for j in 0..4 {
            out[pos] = B64[((w >> (j * 6)) & 0x3F) as usize];
            pos += 1;
        }
    }

    let w = (hash[31] as u32) << 8 | (hash[30] as u32);
    for j in 0..3 {
        out[pos] = B64[((w >> (j * 6)) & 0x3F) as usize];
        pos += 1;
    }

    String::from_utf8(out.to_vec()).unwrap()
}

fn parse_rounds_and_salt(full_salt: &str) -> (u32, bool, &str) {
    let mut s = full_salt;
    if s.starts_with("$5$") {
        s = &s[3..];
    }

    let mut rounds = 5000u32;
    let mut rounds_custom = false;

    if s.starts_with("rounds=") {
        let rest = &s[7..];
        if let Some(dollar_pos) = rest.find('$') {
            let num_str = &rest[..dollar_pos];
            if let Ok(n) = num_str.parse::<u32>() {
                rounds = n.max(1000).min(999999999);
                rounds_custom = true;
            }
            s = &rest[dollar_pos + 1..];
        }
    }

    let salt_end = s.find('$').unwrap_or(s.len());
    let salt_actual = &s[..salt_end.min(16)];
    (rounds, rounds_custom, salt_actual)
}

pub fn sha256crypt(password: &str, full_salt: &str) -> String {
    let pwd = password.as_bytes();
    let pwd_len = pwd.len();

    let (rounds, rounds_custom, salt_actual) = parse_rounds_and_salt(full_salt);
    let salt_bytes = salt_actual.as_bytes();
    let salt_len = salt_bytes.len();

    let mut ctx = Sha256::new();
    ctx.update(pwd);
    ctx.update(salt_bytes);

    let mut alt_ctx = Sha256::new();
    alt_ctx.update(pwd);
    alt_ctx.update(salt_bytes);
    alt_ctx.update(pwd);
    let digest_b = alt_ctx.finalize_reset();

    let mut remaining = pwd_len;
    while remaining > 32 {
        ctx.update(&digest_b);
        remaining -= 32;
    }
    ctx.update(&digest_b[..remaining]);

    remaining = pwd_len;
    while remaining > 0 {
        if (remaining & 1) != 0 {
            ctx.update(&digest_b);
        } else {
            ctx.update(pwd);
        }
        remaining >>= 1;
    }

    let mut alt_result = [0u8; 32];
    alt_result.copy_from_slice(&ctx.finalize_reset());

    alt_ctx.reset();
    for _ in 0..pwd_len {
        alt_ctx.update(pwd);
    }
    let temp_result = alt_ctx.finalize_reset();

    let mut p = Vec::with_capacity(pwd_len);
    while p.len() < pwd_len {
        let remaining = pwd_len - p.len();
        let n = remaining.min(32);
        p.extend_from_slice(&temp_result[..n]);
    }

    let repeat_count = 16usize + alt_result[0] as usize;
    for _ in 0..repeat_count {
        alt_ctx.update(salt_bytes);
    }
    let temp_result = alt_ctx.finalize_reset();

    let mut s = Vec::with_capacity(salt_len);
    while s.len() < salt_len {
        let remaining = salt_len - s.len();
        let n = remaining.min(32);
        s.extend_from_slice(&temp_result[..n]);
    }

    for cnt in 0..rounds {
        let mut ctx = Sha256::new();

        if (cnt & 1) != 0 {
            ctx.update(&p);
        } else {
            ctx.update(&alt_result);
        }

        if (cnt % 3) != 0 {
            ctx.update(&s);
        }

        if (cnt % 7) != 0 {
            ctx.update(&p);
        }

        if (cnt & 1) != 0 {
            ctx.update(&alt_result);
        } else {
            ctx.update(&p);
        }

        alt_result.copy_from_slice(&ctx.finalize_reset());
    }

    let encoded = encode_sha256crypt_hash(&alt_result);
    let mut result = String::from("$5$");
    if rounds_custom {
        result.push_str(&format!("rounds={}$", rounds));
    }
    result.push_str(salt_actual);
    result.push('$');
    result.push_str(&encoded);
    result
}

#[allow(dead_code)]
pub fn decode_hash_to_words(encoded: &str) -> Result<[u32; 8], String> {
    let bytes = decode_sha256crypt_hash(encoded)?;
    let mut words = [0u32; 8];
    for i in 0..8 {
        words[i] = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
    }
    Ok(words)
}

#[test]
fn test_sha256crypt_hello_world() {
    let hash = sha256crypt("Hello world!", "$5$saltstring");
    assert_eq!(hash, "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5");
}

#[test]
fn test_sha256crypt_debug_intermediate() {
    let pwd = b"Hello world!";
    let pwd_len = pwd.len();
    let salt = b"saltsaltstringsaltst";
    let salt_len = salt.len();

    let mut ctx = Sha256::new();
    ctx.update(pwd);
    ctx.update(salt);
    let digest_a = ctx.finalize_reset();
    eprintln!("digest_a initial: {:02x?}", digest_a.as_slice());

    let mut alt_ctx = Sha256::new();
    alt_ctx.update(pwd);
    alt_ctx.update(salt);
    alt_ctx.update(pwd);
    let digest_b = alt_ctx.finalize_reset();
    eprintln!("digest_b: {:02x?}", digest_b.as_slice());

    let mut ctx2 = Sha256::new();
    ctx2.update(pwd);
    ctx2.update(salt);
    let mut remaining = pwd_len;
    while remaining > 32 {
        ctx2.update(&digest_b);
        remaining -= 32;
    }
    ctx2.update(&digest_b[..remaining]);
    remaining = pwd_len;
    while remaining > 0 {
        if (remaining & 1) != 0 {
            ctx2.update(&digest_b);
        } else {
            ctx2.update(pwd);
        }
        remaining >>= 1;
    }
    let extended = ctx2.finalize_reset();
    eprintln!("extended digest_a (step12): {:02x?}", extended.as_slice());
    eprintln!("alt_result[0] = {}", extended[0]);

    for _ in 0..pwd_len {
        alt_ctx.update(pwd);
    }
    let dp = alt_ctx.finalize_reset();
    eprintln!("DP digest: {:02x?}", dp.as_slice());

    let rc = 16 + extended[0] as usize;
    for _ in 0..rc {
        alt_ctx.update(salt);
    }
    let ds = alt_ctx.finalize_reset();
    eprintln!("DS digest ({} reps): {:02x?}", rc, ds.as_slice());
}

#[test]
fn test_sha256crypt_rounds_10000() {
    let hash = sha256crypt("Hello world!", "$5$rounds=10000$saltstringsaltstring");
    assert_eq!(hash, "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA");
}

#[test]
fn test_sha256crypt_rounds_5000_long_salt() {
    let hash = sha256crypt("This is just a test", "$5$rounds=5000$toolongsaltstring");
    assert_eq!(hash, "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5");
}

#[test]
fn test_sha256crypt_rounds_1400() {
    let hash = sha256crypt(
        "a very much longer text to encrypt.  This one even stretches over morethan one line.",
        "$5$rounds=1400$anotherlongsaltstring",
    );
    assert_eq!(hash, "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1");
}

#[test]
fn test_sha256crypt_rounds_77777() {
    let hash = sha256crypt(
        "we have a short salt string but not a short password",
        "$5$rounds=77777$short",
    );
    assert_eq!(hash, "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/");
}

#[test]
fn test_sha256crypt_rounds_123456() {
    let hash = sha256crypt("a short string", "$5$rounds=123456$asaltof16chars..");
    assert_eq!(hash, "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD");
}

#[test]
fn test_sha256crypt_rounds_too_low() {
    let hash = sha256crypt("the minimum number is still observed", "$5$rounds=10$roundstoolow");
    assert_eq!(hash, "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC");
}

#[test]
fn test_sha256crypt_roundtrip() {
    let module = RawSha256Crypt;
    let hash = sha256crypt("test123", "$5$abc");
    let parsed = module.parse_hash_string(&hash).unwrap();
    assert_eq!(parsed.digest_words, 8);
    assert_eq!(parsed.salt, b"abc");
    assert!(module.cpu_verify("test123", b"abc", &parsed.hash_words));
}

#[test]
fn test_sha256crypt_decode_encode_roundtrip() {
    let test_cases = [
        "5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
        "3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
        "Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5",
    ];
    for encoded in &test_cases {
        let decoded = decode_sha256crypt_hash(encoded).unwrap();
        let reencoded = encode_sha256crypt_hash(&decoded);
        assert_eq!(reencoded, *encoded);
    }
}
