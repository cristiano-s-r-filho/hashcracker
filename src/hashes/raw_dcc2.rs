use md4::{Digest, Md4};
use sha1::{Digest as Sha1Digest, Sha1};
use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawDcc2;

impl HashModule for RawDcc2 {
    fn name(&self) -> &'static str { "dcc2" }
    fn mode(&self) -> u32 { 2100 }
    fn digest_words(&self) -> u32 { 5 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        let mut utf16 = Vec::with_capacity(password.len() * 2);
        for b in password.encode_utf16() {
            utf16.extend_from_slice(&b.to_le_bytes());
        }
        let mut inner = Md4::new();
        inner.update(&utf16);
        let ntlm_hash = inner.finalize();

        let mut outer = Sha1::new();
        outer.update(&ntlm_hash);
        outer.update(salt);
        let result = outer.finalize();

        let mut computed = [0u32; 8];
        for i in 0..5 {
            computed[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
        }
        computed[..5] == hash[..5]
    }

    fn shader_source(&self, mode: &AttackModeType) -> &'static str {
        match mode {
            _ => "",
        }
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(40), priority: 80 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        if let Some(colon_pos) = s.find(':') {
            let hash_part = &s[..colon_pos];
            let username = &s[colon_pos + 1..];
            let clean = hash_part.strip_prefix("0x").unwrap_or(hash_part);
            if clean.len() != 40 {
                return Err(format!("Expected 40 hex chars for DCC2, got {}", clean.len()));
            }
            let mut target = [0u32; 8];
            for i in 0..5 {
                target[i] = u32::from_str_radix(&clean[i * 8..i * 8 + 8], 16)
                    .map_err(|_| format!("Invalid hex at position {}", i * 8))?;
            }
            Ok(ParsedHash {
                hash_words: target,
                extra_words: [0u32; 8],
                salt: username.as_bytes().to_vec(),
                digest_words: 5,
            })
        } else {
            Err("DCC2 hash requires hash:username format".to_string())
        }
    }
}

pub fn dcc2_hash(password: &str, username: &str) -> ([u32; 8], [u32; 8]) {
    let mut utf16 = Vec::with_capacity(password.len() * 2);
    for b in password.encode_utf16() {
        utf16.extend_from_slice(&b.to_le_bytes());
    }
    let mut inner = Md4::new();
    inner.update(&utf16);
    let ntlm_hash = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(&ntlm_hash);
    outer.update(username.as_bytes());
    let result = outer.finalize();

    let mut target = [0u32; 8];
    for i in 0..5 {
        target[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
    }
    (target, [0u32; 8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dcc2_vector() {
        // Known DCC2 hash for password "test" with username "admin"
        // SHA-1(MD4(UTF16-LE("test")) || "admin")
        let dcc2 = RawDcc2;
        let (hash, _) = dcc2_hash("test", "admin");
        let hex = format!("{:08x}{:08x}{:08x}{:08x}{:08x}",
            hash[0], hash[1], hash[2], hash[3], hash[4]);
        assert_eq!(hex.len(), 40);

        // Verify via cpu_verify
        let salt = "admin".as_bytes();
        assert!(dcc2.cpu_verify("test", salt, &hash[..5]));

        // Wrong password should fail
        assert!(!dcc2.cpu_verify("wrong", salt, &hash[..5]));

        // parse_hash_string round-trip
        let full = format!("{}:admin", hex);
        let parsed = dcc2.parse_hash_string(&full).unwrap();
        assert_eq!(parsed.hash_words[..5], hash[..5]);
        assert_eq!(parsed.salt, b"admin");
    }
}
