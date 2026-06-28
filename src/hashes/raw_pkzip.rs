use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawPkzip;

impl HashModule for RawPkzip {
    fn name(&self) -> &'static str {
        "pkzip"
    }

    fn mode(&self) -> u32 {
        17200
    }

    fn digest_words(&self) -> u32 {
        8
    }

    fn needs_int64(&self) -> bool {
        false
    }

    fn cpu_verify(&self, password: &str, salt: &[u8], _hash: &[u32]) -> bool {
        if salt.len() < 8 {
            return false;
        }

        let crc32 = u32::from_le_bytes(salt[0..4].try_into().unwrap());
        let _comp_size = u32::from_le_bytes(salt[4..8].try_into().unwrap());
        let data = &salt[8..];

        if data.is_empty() {
            return false;
        }

        crate::zip_extract::pkzip_verify(password, crc32, data)
    }

    fn shader_source(&self, _mode: &AttackModeType) -> &'static str {
        ""
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern {
            prefix: Some("$pkzip$"),
            hex_len: None,
            priority: 90,
        }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let s = s.trim();
        let body = s
            .strip_prefix("$pkzip$")
            .and_then(|s| s.strip_suffix("$/pkzip$"))
            .ok_or_else(|| "Missing $pkzip$...$/pkzip$ markers".to_string())?;

        let fields: Vec<&str> = body.split('*').collect();
        if fields.len() < 18 {
            return Err(format!(
                "Expected at least 18 fields in pkzip hash, got {}",
                fields.len()
            ));
        }

        let crc32 = fields[4]
            .parse::<u32>()
            .map_err(|_| "Invalid CRC32".to_string())?;
        let comp_size = fields[5]
            .parse::<u32>()
            .map_err(|_| "Invalid compressed size".to_string())?;
        let data_hex = fields[6];
        let magic_hex = fields[17];

        let data = hex::decode(data_hex).map_err(|_| "Invalid encrypted data hex".to_string())?;
        let magic =
            hex::decode(magic_hex).map_err(|_| "Invalid magic bytes hex".to_string())?;

        let mut salt = Vec::with_capacity(8 + data.len() + magic.len());
        salt.extend_from_slice(&crc32.to_le_bytes());
        salt.extend_from_slice(&comp_size.to_le_bytes());
        salt.extend_from_slice(&data);
        salt.extend_from_slice(&magic);

        Ok(ParsedHash {
            hash_words: [0u32; 8],
            extra_words: [0u32; 8],
            salt,
            digest_words: 8,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pkzip_hash() {
        let hash_str = "$pkzip$2*1*1*0*12345*100*00112233445566778899aabbccddeeff*0*0*0*0*0*0*0*0*0*ffeeddccbbaa*$/pkzip$";

        let module = RawPkzip;
        let parsed = module.parse_hash_string(hash_str).unwrap();

        assert_eq!(parsed.salt.len() >= 8, true);
        let crc = u32::from_le_bytes(parsed.salt[0..4].try_into().unwrap());
        let comp = u32::from_le_bytes(parsed.salt[4..8].try_into().unwrap());
        assert_eq!(crc, 12345);
        assert_eq!(comp, 100);
    }

    #[test]
    fn test_pkzip_detect() {
        let module = RawPkzip;
        let patterns = module.detect_patterns();
        assert!(patterns[0].prefix == Some("$pkzip$"));
    }
}
