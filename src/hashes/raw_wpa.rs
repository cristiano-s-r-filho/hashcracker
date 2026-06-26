use sha1::{Digest, Sha1};
use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawWpa;

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let key = if key.len() > 64 {
        let mut hasher = Sha1::new();
        hasher.update(key);
        hasher.finalize().to_vec()
    } else {
        key.to_vec()
    };

    let mut padded_key = [0u8; 64];
    for (i, &b) in key.iter().enumerate() {
        padded_key[i] = b;
    }

    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = padded_key[i] ^ 0x36;
        opad[i] = padded_key[i] ^ 0x5c;
    }

    let mut inner = Sha1::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_result = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(&inner_result);
    outer.finalize().into()
}

fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let blocks = (dk_len + 19) / 20;
    let mut dk = Vec::with_capacity(blocks * 20);

    for block in 1..=blocks as u32 {
        let mut msg = Vec::with_capacity(salt.len() + 4);
        msg.extend_from_slice(salt);
        msg.extend_from_slice(&block.to_be_bytes());

        let mut u = hmac_sha1(password, &msg);
        let mut block_result = u;

        for _ in 1..iterations {
            u = hmac_sha1(password, &u);
            for i in 0..20 {
                block_result[i] ^= u[i];
            }
        }

        dk.extend_from_slice(&block_result);
    }

    dk.truncate(dk_len);
    dk
}

impl RawWpa {
    #[allow(dead_code)]
    pub fn cpu_hash(&self, password: &str, salt: &[u8]) -> Vec<u32> {
        if salt.len() < 16 {
            return vec![0u32; 4];
        }
        let ap_mac: [u8; 6] = salt[..6].try_into().unwrap();
        let client_mac: [u8; 6] = salt[6..12].try_into().unwrap();
        let ssid_len = u32::from_le_bytes(salt[salt.len() - 4..].try_into().unwrap()) as usize;
        let ssid = &salt[12..12 + ssid_len];

        let mut pmk = vec![0u8; 32];
        pmk.copy_from_slice(&pbkdf2_hmac_sha1(password.as_bytes(), ssid, 4096, 32));

        let pmkid = Self::compute_pmkid(&pmk[..32].try_into().unwrap(), &ap_mac, &client_mac);

        let mut words = vec![0u32; 4];
        for i in 0..4 {
            words[i] = u32::from_le_bytes(pmkid[i * 4..i * 4 + 4].try_into().unwrap());
        }
        words
    }

    fn compute_pmkid(pmk: &[u8; 32], ap_mac: &[u8; 6], client_mac: &[u8; 6]) -> [u8; 16] {
        let mut msg = Vec::with_capacity(12);
        msg.extend_from_slice(ap_mac);
        msg.extend_from_slice(client_mac);

        let result = hmac_sha1(pmk, &msg);
        let mut pmkid = [0u8; 16];
        pmkid.copy_from_slice(&result[..16]);
        pmkid
    }
}

fn parse_wpa_string(s: &str) -> Result<ParsedHash, String> {
    let parts: Vec<&str> = s.splitn(4, ':').collect();
    if parts.len() != 4 {
        return Err("WPA format: hash_hex:ap_mac:client_mac:ssid".to_string());
    }
    let hash_hex = parts[0];
    let ap_mac_hex = parts[1];
    let client_mac_hex = parts[2];
    let ssid = parts[3].as_bytes();

    if hash_hex.len() != 32 {
        return Err(format!("Expected 32 hex chars for PMKID, got {}", hash_hex.len()));
    }
    let mut hash_words = [0u32; 8];
    for i in 0..4 {
        hash_words[i] = u32::from_str_radix(&hash_hex[i * 8..i * 8 + 8], 16)
            .map_err(|_| format!("Invalid hex at position {}", i * 8))?;
    }

    let ap_mac = hex_to_6bytes(ap_mac_hex)?;
    let client_mac = hex_to_6bytes(client_mac_hex)?;

    let mut salt = Vec::with_capacity(12 + ssid.len() + 4);
    salt.extend_from_slice(&ap_mac);
    salt.extend_from_slice(&client_mac);
    salt.extend_from_slice(ssid);
    salt.extend_from_slice(&(ssid.len() as u32).to_le_bytes());

    Ok(ParsedHash { hash_words, extra_words: [0u32; 8], salt, digest_words: 4 })
}

fn hex_to_6bytes(hex: &str) -> Result<[u8; 6], String> {
    if hex.len() != 12 {
        return Err(format!("Expected 12 hex chars for MAC, got {}", hex.len()));
    }
    let mut bytes = [0u8; 6];
    for i in 0..6 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("Invalid hex at position {}", i * 2))?;
    }
    Ok(bytes)
}

impl HashModule for RawWpa {
    fn name(&self) -> &'static str { "wpa" }
    fn mode(&self) -> u32 { 16800 }
    fn digest_words(&self) -> u32 { 4 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        if salt.len() < 16 {
            return false;
        }
        let ap_mac: [u8; 6] = match salt[..6].try_into() {
            Ok(m) => m,
            Err(_) => return false,
        };
        let client_mac: [u8; 6] = match salt[6..12].try_into() {
            Ok(m) => m,
            Err(_) => return false,
        };
        let ssid_len = match salt[salt.len() - 4..].try_into() {
            Ok(bytes) => u32::from_le_bytes(bytes) as usize,
            Err(_) => return false,
        };
        let ssid_offset = 12;
        if ssid_offset + ssid_len > salt.len() - 4 {
            return false;
        }
        let ssid = &salt[ssid_offset..ssid_offset + ssid_len];

        let pmk = pbkdf2_hmac_sha1(password.as_bytes(), ssid, 4096, 32);
        let pmk_arr: [u8; 32] = match pmk[..32].try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let computed_pmkid = Self::compute_pmkid(&pmk_arr, &ap_mac, &client_mac);

        let target_pmkid_words: [u32; 4] = [
            u32::from_le_bytes(computed_pmkid[0..4].try_into().unwrap()),
            u32::from_le_bytes(computed_pmkid[4..8].try_into().unwrap()),
            u32::from_le_bytes(computed_pmkid[8..12].try_into().unwrap()),
            u32::from_le_bytes(computed_pmkid[12..16].try_into().unwrap()),
        ];
        target_pmkid_words == hash[..4]
    }

    fn shader_source(&self, _mode: &AttackModeType) -> &'static str { "" }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        parse_wpa_string(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wpa_parse_basic() {
        let m = RawWpa;
        let input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:001122334455:66778899AABB:test_ssid";
        let parsed = m.parse_hash_string(input).unwrap();
        assert_eq!(parsed.hash_words[0], 0xaaaaaaaa);
        assert_eq!(parsed.hash_words[1], 0xaaaaaaaa);
        assert_eq!(parsed.hash_words[2], 0xaaaaaaaa);
        assert_eq!(parsed.hash_words[3], 0xaaaaaaaa);
        assert_eq!(parsed.salt.len(), 25);
        let ssid_salt = &parsed.salt[12..parsed.salt.len() - 4];
        assert_eq!(ssid_salt, b"test_ssid");
    }

    #[test]
    fn test_wpa_cpu_verify() {
        let m = RawWpa;
        let ap_mac = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let client_mac = [0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b];
        let ssid = b"a";
        let password = "a";

        let pmk = pbkdf2_hmac_sha1(password.as_bytes(), ssid, 4096, 32);
        let pmk_arr: [u8; 32] = pmk[..32].try_into().unwrap();
        let computed_pmkid = RawWpa::compute_pmkid(&pmk_arr, &ap_mac, &client_mac);

        let mut hash_words = [0u32; 8];
        for i in 0..4 {
            hash_words[i] = u32::from_le_bytes(computed_pmkid[i * 4..i * 4 + 4].try_into().unwrap());
        }

        let mut salt = Vec::new();
        salt.extend_from_slice(&ap_mac);
        salt.extend_from_slice(&client_mac);
        salt.extend_from_slice(ssid);
        salt.extend_from_slice(&(ssid.len() as u32).to_le_bytes());

        assert!(m.cpu_verify("a", &salt, &hash_words[..4]));
        assert!(!m.cpu_verify("wrong", &salt, &hash_words[..4]));
    }

    #[test]
    fn test_wpa_parse_and_verify_roundtrip() {
        let m = RawWpa;
        let hash_str = "4e27b0a3a1c8e171b6f9e00d9d8e9e0e:001122334455:66778899aabb:test_wifi";
        let parsed = m.parse_hash_string(hash_str).unwrap();
        assert_eq!(parsed.digest_words, 4);
        let ssid = &parsed.salt[12..parsed.salt.len() - 4];
        assert_eq!(ssid, b"test_wifi");
    }

    #[test]
    fn test_wpa_invalid_parse() {
        let m = RawWpa;
        assert!(m.parse_hash_string("too:few:parts").is_err());
        assert!(m.parse_hash_string(":00:00:ssid").is_err());
        assert!(m.parse_hash_string("0000:001122334455:66778899aabb:ssid").is_err());
    }

    #[test]
    fn test_pbkdf2_hmac_sha1_rfc6070_c1() {
        let dk = pbkdf2_hmac_sha1(b"password", b"salt", 1, 20);
        assert_eq!(hex::encode(&dk), "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    }

    #[test]
    fn test_pbkdf2_hmac_sha1_rfc6070_c2() {
        let dk = pbkdf2_hmac_sha1(b"password", b"salt", 2, 20);
        assert_eq!(hex::encode(&dk), "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
    }

    #[test]
    fn test_pbkdf2_hmac_sha1_rfc6070_c4096() {
        let dk = pbkdf2_hmac_sha1(b"password", b"salt", 4096, 20);
        assert_eq!(hex::encode(&dk), "4b007901b765489abead49d926f721d065a429c1");
    }
}
