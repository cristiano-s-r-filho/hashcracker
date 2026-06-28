pub struct RawSha512Crypt;

use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};
use sha2::{Digest, Sha512};

impl HashModule for RawSha512Crypt {
    fn name(&self) -> &'static str { "sha512crypt" }
    fn mode(&self) -> u32 { 1800 }
    fn digest_words(&self) -> u32 { 8 }
    fn needs_int64(&self) -> bool { true }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        let salt_str = std::str::from_utf8(salt).unwrap_or("");
        let full_salt = if salt_str.starts_with("$6$") {
            salt_str.to_string()
        } else {
            format!("$6${}", salt_str)
        };
        let full_hash = sha512crypt(password, &full_salt);
        if let Ok(parsed) = self.parse_hash_string(&full_hash) {
            parsed.hash_words[..8] == hash[..8]
        } else {
            false
        }
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            AttackModeType::BruteForce => include_str!("../sha512crypt_crack.wgsl"),
            AttackModeType::Mask => include_str!("../sha512crypt_mask.wgsl"),
            AttackModeType::Wordlist => include_str!("../sha512crypt_wordlist.wgsl"),
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: Some("$6$"), hex_len: None, priority: 50 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let s = s.trim();
        if !s.starts_with("$6$") {
            return Err("Expected $6$ prefix for sha512crypt".to_string());
        }
        let rest = &s[3..];
        let rest = if rest.starts_with("rounds=") {
            let rest2 = &rest[7..];
            if let Some(dollar_pos) = rest2.find('$') {
                &rest2[dollar_pos + 1..]
            } else {
                return Err(format!("Invalid sha512crypt format '{}'", s));
            }
        } else {
            rest
        };
        let parts: Vec<&str> = rest.split('$').collect();
        if parts.len() != 2 || parts[1].is_empty() {
            return Err(format!("Invalid sha512crypt format '{}'. Expected $6$salt$hash", s));
        }
        let salt_str = parts[0];
        if salt_str.len() > 16 {
            return Err(format!("sha512crypt salt too long (max 16 chars): {}", salt_str.len()));
        }
        let hash_encoded = parts[1];
        if hash_encoded.len() != 86 {
            return Err(format!("Expected 86-char sha512crypt hash, got {}", hash_encoded.len()));
        }

        let salt_bytes = salt_str.as_bytes().to_vec();
        let hash_bytes = decode_sha512crypt_hash(hash_encoded)?;
        let mut target = [0u32; 8];
        let mut extra = [0u32; 8];
        for i in 0..8 {
            let word = u64::from_be_bytes(hash_bytes[i * 8..i * 8 + 8].try_into().unwrap());
            target[i] = word as u32;
            extra[i] = (word >> 32) as u32;
        }

        Ok(ParsedHash {
            hash_words: target,
            extra_words: extra,
            salt: salt_bytes,
            digest_words: 8,
        })
    }
}

const B64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn b64_idx(c: u8) -> Option<usize> {
    B64.iter().position(|&x| x == c)
}

fn decode_sha512crypt_hash(encoded: &str) -> Result<[u8; 64], String> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 86 {
        return Err(format!("sha512crypt hash must be 86 chars, got {}", bytes.len()));
    }

    let v: Result<Vec<u8>, String> = bytes.iter().map(|&c| {
        b64_idx(c).map(|p| p as u8).ok_or_else(|| format!("Invalid base64 char: {}", c as char))
    }).collect();
    let v = v?;

    let mut out = [0u8; 64];

    let groups: [(usize, usize, usize); 21] = [
        (0, 21, 42),
        (22, 43, 1),
        (44, 2, 23),
        (3, 24, 45),
        (25, 46, 4),
        (47, 5, 26),
        (6, 27, 48),
        (28, 49, 7),
        (50, 8, 29),
        (9, 30, 51),
        (31, 52, 10),
        (53, 11, 32),
        (12, 33, 54),
        (34, 55, 13),
        (56, 14, 35),
        (15, 36, 57),
        (37, 58, 16),
        (59, 17, 38),
        (18, 39, 60),
        (40, 61, 19),
        (62, 20, 41),
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

    let a = v[84] as u32;
    let b = v[85] as u32;
    let w = a | (b << 6);
    out[63] = w as u8;

    Ok(out)
}

fn encode_sha512crypt_hash(hash: &[u8; 64]) -> String {
    let mut out = [0u8; 86];

    let groups: [(usize, usize, usize); 21] = [
        (0, 21, 42),
        (22, 43, 1),
        (44, 2, 23),
        (3, 24, 45),
        (25, 46, 4),
        (47, 5, 26),
        (6, 27, 48),
        (28, 49, 7),
        (50, 8, 29),
        (9, 30, 51),
        (31, 52, 10),
        (53, 11, 32),
        (12, 33, 54),
        (34, 55, 13),
        (56, 14, 35),
        (15, 36, 57),
        (37, 58, 16),
        (59, 17, 38),
        (18, 39, 60),
        (40, 61, 19),
        (62, 20, 41),
    ];

    let mut pos = 0usize;
    for &(b2, b1, b0) in &groups {
        let w = (hash[b2] as u32) << 16 | (hash[b1] as u32) << 8 | (hash[b0] as u32);
        for j in 0..4 {
            out[pos] = B64[((w >> (j * 6)) & 0x3F) as usize];
            pos += 1;
        }
    }

    let w = hash[63] as u32;
    for j in 0..2 {
        out[pos] = B64[((w >> (j * 6)) & 0x3F) as usize];
        pos += 1;
    }

    String::from_utf8(out.to_vec()).unwrap()
}

fn parse_rounds_and_salt(full_salt: &str) -> (u32, bool, &str) {
    let mut s = full_salt;
    if s.starts_with("$6$") {
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

pub fn sha512crypt(password: &str, full_salt: &str) -> String {
    let pwd = password.as_bytes();
    let pwd_len = pwd.len();

    let (rounds, rounds_custom, salt_actual) = parse_rounds_and_salt(full_salt);
    let salt_bytes = salt_actual.as_bytes();
    let salt_len = salt_bytes.len();

    let mut ctx = Sha512::new();
    ctx.update(pwd);
    ctx.update(salt_bytes);

    let mut alt_ctx = Sha512::new();
    alt_ctx.update(pwd);
    alt_ctx.update(salt_bytes);
    alt_ctx.update(pwd);
    let digest_b = alt_ctx.finalize_reset();

    let mut remaining = pwd_len;
    while remaining > 64 {
        ctx.update(&digest_b);
        remaining -= 64;
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

    let mut alt_result = [0u8; 64];
    alt_result.copy_from_slice(&ctx.finalize_reset());

    alt_ctx.reset();
    for _ in 0..pwd_len {
        alt_ctx.update(pwd);
    }
    let temp_result = alt_ctx.finalize_reset();

    let mut p = Vec::with_capacity(pwd_len);
    while p.len() < pwd_len {
        let remaining = pwd_len - p.len();
        let n = remaining.min(64);
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
        let n = remaining.min(64);
        s.extend_from_slice(&temp_result[..n]);
    }

    for cnt in 0..rounds {
        let mut ctx = Sha512::new();

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

    let encoded = encode_sha512crypt_hash(&alt_result);
    let mut result = String::from("$6$");
    if rounds_custom {
        result.push_str(&format!("rounds={}$", rounds));
    }
    result.push_str(salt_actual);
    result.push('$');
    result.push_str(&encoded);
    result
}

#[allow(dead_code)]
pub fn decode_hash_to_words(encoded: &str) -> Result<([u32; 8], [u32; 8]), String> {
    let bytes = decode_sha512crypt_hash(encoded)?;
    let mut target = [0u32; 8];
    let mut extra = [0u32; 8];
    for i in 0..8 {
        let word = u64::from_be_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
        target[i] = word as u32;
        extra[i] = (word >> 32) as u32;
    }
    Ok((target, extra))
}

#[test]
fn test_sha512crypt_hello_world() {
    let hash = sha512crypt("Hello world!", "$6$saltstring");
    assert_eq!(hash, "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1");
}

#[test]
fn test_sha512crypt_rounds_10000() {
    let hash = sha512crypt("Hello world!", "$6$rounds=10000$saltstringsaltstring");
    assert_eq!(hash, "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.");
}

#[test]
fn test_sha512crypt_rounds_5000_long_salt() {
    let hash = sha512crypt("This is just a test", "$6$rounds=5000$toolongsaltstring");
    assert_eq!(hash, "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0");
}

#[test]
fn test_sha512crypt_rounds_1400() {
    let hash = sha512crypt(
        "a very much longer text to encrypt.  This one even stretches over morethan one line.",
        "$6$rounds=1400$anotherlongsaltstring",
    );
    assert_eq!(hash, "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1");
}

#[test]
fn test_sha512crypt_rounds_77777() {
    let hash = sha512crypt(
        "we have a short salt string but not a short password",
        "$6$rounds=77777$short",
    );
    assert_eq!(hash, "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0");
}

#[test]
fn test_sha512crypt_rounds_123456() {
    let hash = sha512crypt("a short string", "$6$rounds=123456$asaltof16chars..");
    assert_eq!(hash, "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1");
}

#[test]
fn test_sha512crypt_rounds_too_low() {
    let hash = sha512crypt("the minimum number is still observed", "$6$rounds=10$roundstoolow");
    assert_eq!(hash, "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.");
}

#[test]
fn test_sha512crypt_roundtrip() {
    let module = RawSha512Crypt;
    let hash = sha512crypt("test123", "$6$abc");
    let parsed = module.parse_hash_string(&hash).unwrap();
    assert_eq!(parsed.digest_words, 8);
    assert_eq!(parsed.salt, b"abc");
    assert!(module.cpu_verify("test123", b"abc", &parsed.hash_words));
}

#[test]
fn test_sha512crypt_decode_encode_roundtrip() {
    let test_cases = [
        "svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
        "OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
        "lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
    ];
    for encoded in &test_cases {
        let decoded = decode_sha512crypt_hash(encoded).unwrap();
        let reencoded = encode_sha512crypt_hash(&decoded);
        assert_eq!(reencoded, *encoded);
    }
}
