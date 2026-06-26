use sha2::Sha512;
use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawGrub2;

fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    type HmacSha512 = Hmac<Sha512>;

    let mut dk = [0u8; 64];

    let mut u = HmacSha512::new_from_slice(password).expect("HMAC key");
    u.update(salt);
    u.update(&1u32.to_be_bytes());
    let mut t = u.finalize().into_bytes();
    let mut u_prev = t;

    for _ in 1..iterations {
        let mut u_cur = HmacSha512::new_from_slice(password).expect("HMAC key");
        u_cur.update(&u_prev);
        let u_cur_bytes = u_cur.finalize().into_bytes();
        for j in 0..64 {
            t[j] ^= u_cur_bytes[j];
        }
        u_prev = u_cur_bytes;
    }

    dk.copy_from_slice(&t);
    dk
}

impl HashModule for RawGrub2 {
    fn name(&self) -> &'static str { "grub2" }
    fn mode(&self) -> u32 { 7200 }
    fn digest_words(&self) -> u32 { 16 }
    fn needs_int64(&self) -> bool { true }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        // Parse salt as: iterations (be u32) || salt_bytes
        if salt.len() < 5 { return false; }
        let mut iter_bytes = [0u8; 4];
        iter_bytes.copy_from_slice(&salt[..4]);
        let iterations = u32::from_be_bytes(iter_bytes);
        let actual_salt = &salt[4..];

        let dk = pbkdf2_hmac_sha512(password.as_bytes(), actual_salt, iterations);

        let mut computed = [0u32; 16];
        for i in 0..8 {
            let word = u64::from_be_bytes(dk[i * 8..i * 8 + 8].try_into().unwrap());
            let hi = (word >> 32) as u32;
            let lo = word as u32;
            if i < 4 {
                computed[i * 2] = hi;
                computed[i * 2 + 1] = lo;
            } else {
                let j = i - 4;
                computed[8 + j * 2] = hi;
                computed[8 + j * 2 + 1] = lo;
            }
        }
        computed[..8] == hash[..8] && computed[8..16] == hash[8..16]
    }

    fn shader_source(&self, _mode: &AttackModeType) -> &'static str {
        ""
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: Some("$grub$"), hex_len: None, priority: 100 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        // $grub$pbkdf2-sha512$iterations.salt$hash
        let parts: Vec<&str> = s.split('$').collect();
        if parts.len() < 5 {
            return Err("GRUB2 hash requires format: $grub$pbkdf2-sha512$iter.salt$hash_hex".to_string());
        }
        let params = parts[3];
        let hash_hex = parts[4];

        let dot_pos = params.find('.').ok_or("missing . in iter.salt")?;
        let iterations: u32 = params[..dot_pos].parse().map_err(|_| "invalid iterations")?;
        let salt_str = &params[dot_pos + 1..];

        let salt_bytes = hex::decode(salt_str).map_err(|_| "invalid salt hex")?;

        let clean = hash_hex.strip_prefix("0x").unwrap_or(hash_hex);
        if clean.len() != 128 {
            return Err("GRUB2 hash must be 128 hex chars".to_string());
        }
        let mut target = [0u32; 8];
        let mut extra = [0u32; 8];
        for i in 0..8 {
            target[i] = u32::from_str_radix(&clean[i * 8..i * 8 + 8], 16)
                .map_err(|_| "invalid hex".to_string())?;
        }
        for i in 8..16 {
            extra[i - 8] = u32::from_str_radix(&clean[i * 8..i * 8 + 8], 16)
                .map_err(|_| "invalid hex".to_string())?;
        }

        // Prepend iterations to salt for cpu_verify
        let mut full_salt = Vec::with_capacity(4 + salt_bytes.len());
        full_salt.extend_from_slice(&iterations.to_be_bytes());
        full_salt.extend_from_slice(&salt_bytes);

        Ok(ParsedHash { hash_words: target, extra_words: extra, salt: full_salt, digest_words: 16 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_grub2_roundtrip() {
        let m = RawGrub2;
        let pw = "abc";
        let salt_hex = "abcd1234";
        let salt_bytes = hex::decode(salt_hex).unwrap();
        let iterations = 100u32;
        let dk = pbkdf2_hmac_sha512(pw.as_bytes(), &salt_bytes, iterations);
        let hash_str = format!("$grub$pbkdf2-sha512${}.{}${}", iterations, salt_hex, hex::encode(dk));
        let parsed = m.parse_hash_string(&hash_str).unwrap();
        let mut combined = [0u32; 16];
        combined[..8].copy_from_slice(&parsed.hash_words);
        combined[8..16].copy_from_slice(&parsed.extra_words);
        assert!(m.cpu_verify(pw, &parsed.salt, &combined));
    }
}
