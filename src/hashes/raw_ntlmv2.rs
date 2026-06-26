use md4::{Digest as Md4Digest, Md4};
use md5::{Digest as Md5Digest, Md5};
use crate::hashes::{AttackModeType, HashModule, HashPattern, ParsedHash};

pub struct RawNtlmv2;

fn hmac_md5(key: &[u8], msg: &[u8]) -> [u8; 16] {
    const BLOCK: usize = 64;
    let k = if key.len() > BLOCK {
        let mut h = Md5::new();
        h.update(key);
        let r = h.finalize();
        let mut k2 = vec![0u8; BLOCK];
        k2[..16].copy_from_slice(&r);
        k2
    } else {
        let mut k2 = key.to_vec();
        k2.resize(BLOCK, 0);
        k2
    };
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5Cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Md5::new();
    inner.update(&ipad);
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = Md5::new();
    outer.update(&opad);
    outer.update(&ih);
    outer.finalize().into()
}

impl HashModule for RawNtlmv2 {
    fn name(&self) -> &'static str { "ntlmv2" }
    fn mode(&self) -> u32 { 5600 }
    fn digest_words(&self) -> u32 { 4 }
    fn needs_int64(&self) -> bool { false }

    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool {
        if salt.len() < 9 { return false; }
        let server_challenge = &salt[..8];
        let blob = &salt[8..];

        let mut utf16 = Vec::with_capacity(password.len() * 2);
        for b in password.encode_utf16() {
            utf16.extend_from_slice(&b.to_le_bytes());
        }
        let mut md4 = Md4::new();
        md4.update(&utf16);
        let nt_hash = md4.finalize();

        let mut msg = Vec::with_capacity(8 + blob.len());
        msg.extend_from_slice(server_challenge);
        msg.extend_from_slice(blob);
        let hmac = hmac_md5(&nt_hash, &msg);

        let mut proof = [0u8; 16];
        for i in 0..4 {
            proof[i * 4..i * 4 + 4].copy_from_slice(&hash[i].to_le_bytes());
        }
        hmac == proof
    }

    fn shader_source(&self, _mode: &AttackModeType) -> &'static str {
        ""
    }

    fn detect_patterns(&self) -> &[HashPattern] {
        &[HashPattern { prefix: Some("$NETNTLMv2$"), hex_len: None, priority: 100 }]
    }

    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String> {
        let parts: Vec<&str> = s.split('$').collect();
        if parts.len() < 7 {
            return Err("NTLMv2 hash requires format: $NETNTLMv2$user$domain$sc$proof$blob".to_string());
        }
        let sc = hex::decode(parts[4]).map_err(|_| "invalid server challenge hex")?;
        let proof = hex::decode(parts[5]).map_err(|_| "invalid proof hex")?;
        let blob = hex::decode(parts[6]).map_err(|_| "invalid blob hex")?;
        if sc.len() != 8 { return Err("server challenge must be 8 bytes".to_string()); }
        if proof.len() != 16 { return Err("proof must be 16 bytes".to_string()); }
        let mut hash_w = [0u32; 8];
        for i in 0..4 {
            hash_w[i] = u32::from_le_bytes(proof[i*4..i*4+4].try_into().unwrap());
        }
        let mut concat = sc;
        concat.extend_from_slice(&blob);
        Ok(ParsedHash { hash_words: hash_w, extra_words: [0u32; 8], salt: concat, digest_words: 4 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ntlmv2_parse() {
        let m = RawNtlmv2;
        let hash_str = "$NETNTLMv2$user$domain$0102030405060708$aabbccdd00112233445566778899aabb$deadbeef01020304050607080910111213141516";
        let parsed = m.parse_hash_string(hash_str).unwrap();
        assert_eq!(parsed.salt.len(), 8 + 20);
        assert_eq!(parsed.digest_words, 4);
    }
}
