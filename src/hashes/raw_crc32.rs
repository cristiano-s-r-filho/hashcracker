use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawCrc32;

impl HashModule for RawCrc32 {
    fn name(&self) -> &'static str { "crc32" }
    fn mode(&self) -> u32 { 11500 }
    fn digest_words(&self) -> u32 { 1 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, _salt: &[u8], hash: &[u32]) -> bool {
        use crc::Crc;
        const CRC32: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
        let mut digest = CRC32.digest();
        digest.update(password.as_bytes());
        let result = digest.finalize();
        hash[0] == result
    }

    fn shader_source(&self, _mode: &AttackModeType) -> &'static str {
        ""
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: None, hex_len: Some(8), priority: 100 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if clean.len() != 8 {
            return Err(format!("Expected 8 hex chars for CRC32, got {}", clean.len()));
        }
        let mut target = [0u32; 8];
        target[0] = u32::from_str_radix(clean, 16)
            .map_err(|_| "Invalid CRC32 hex".to_string())?;
        Ok(ParsedHash { hash_words: target, extra_words: [0u32; 8], salt: Vec::new(), digest_words: 1 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_crc32_roundtrip() {
        let m = RawCrc32;
        assert!(m.cpu_verify("hello", &[], &[0x3610a686]));
        assert!(!m.cpu_verify("hello", &[], &[0xdeadbeef]));
        let parsed = m.parse_hash_string("3610a686").unwrap();
        assert_eq!(parsed.hash_words[0], 0x3610a686);
    }
}
