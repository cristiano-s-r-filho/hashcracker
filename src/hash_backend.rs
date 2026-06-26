use std::str::FromStr;
use crate::hashes::HashModule;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum HashType {
    Sha224,
    Sha256,
    Sha384,
    Sha1,
    Sha512,
    HmacSha512,
    Md5,
    Md4,
    Ntlm,
    Ntlmv2,
    Md5Crypt,
    Mssql05,
    Mssql12,
    Mysql41,
    Sha256Crypt,
    Sha256d,
    Sha512Crypt,
    Sha512d,
    Phpass,
    Apr1,
    Bcrypt,
    Crc32,
    Dcc,
    Dcc2,
    Db2,
    Drupal7,
    Grub2,
    Pbkdf2Sha256,
    Postgresql,
    SaltedSha1,
    SaltedSha256,
    SaltedSha512,
    Pdf,
    HmacSha1,
    HmacSha256,
    Lm,
    Wpa,
    Pkzip,
    KeePass,
    SevenZip,
    Rar5,
}

impl HashType {
    pub     fn module(&self) -> &'static dyn HashModule {
        match self {
            HashType::Sha224 => &crate::hashes::raw_sha224::RawSha224,
            HashType::Sha256 => &crate::hashes::raw_sha256::RawSha256,
            HashType::Sha384 => &crate::hashes::raw_sha384::RawSha384,
            HashType::Sha1 => &crate::hashes::raw_sha1::RawSha1,
            HashType::Sha512 => &crate::hashes::raw_sha512::RawSha512,
            HashType::HmacSha512 => &crate::hashes::raw_hmac_sha512::RawHmacSha512,
            HashType::Md5 => &crate::hashes::raw_md5::RawMd5,
            HashType::Apr1 => &crate::hashes::raw_apr1::RawApr1,
            HashType::Bcrypt => &crate::hashes::raw_bcrypt::RawBcrypt,
            HashType::Crc32 => &crate::hashes::raw_crc32::RawCrc32,
            HashType::Dcc => &crate::hashes::raw_dcc::RawDcc,
            HashType::Dcc2 => &crate::hashes::raw_dcc2::RawDcc2,
            HashType::Md4 => &crate::hashes::raw_md4::RawMd4,
            HashType::Ntlm => &crate::hashes::raw_ntlm::RawNtlm,
            HashType::Ntlmv2 => &crate::hashes::raw_ntlmv2::RawNtlmv2,
            HashType::Md5Crypt => &crate::hashes::raw_md5crypt::RawMd5Crypt,
            HashType::Mssql05 => &crate::hashes::raw_mssql05::RawMssql05,
            HashType::Mssql12 => &crate::hashes::raw_mssql12::RawMssql12,
            HashType::Mysql41 => &crate::hashes::raw_mysql41::RawMysql41,
            HashType::Sha256Crypt => &crate::hashes::raw_sha256crypt::RawSha256Crypt,
            HashType::Sha256d => &crate::hashes::raw_sha256d::RawSha256d,
            HashType::Sha512Crypt => &crate::hashes::raw_sha512crypt::RawSha512Crypt,
            HashType::Sha512d => &crate::hashes::raw_sha512d::RawSha512d,
            HashType::Phpass => &crate::hashes::raw_phpass::RawPhpass,
            HashType::Drupal7 => &crate::hashes::raw_drupal7::RawDrupal7,
            HashType::Grub2 => &crate::hashes::raw_grub2::RawGrub2,
            HashType::Db2 => &crate::hashes::raw_db2::RawDb2,
            HashType::Pbkdf2Sha256 => &crate::hashes::raw_pbkdf2_sha256::RawPbkdf2Sha256,
            HashType::Postgresql => &crate::hashes::raw_postgresql::RawPostgresql,
            HashType::SaltedSha1 => &crate::hashes::raw_salted::RawSaltedSha1,
            HashType::SaltedSha256 => &crate::hashes::raw_salted::RawSaltedSha256,
            HashType::SaltedSha512 => &crate::hashes::raw_salted::RawSaltedSha512,
            HashType::Pdf => &crate::hashes::raw_pdf::RawPdf,
            HashType::HmacSha1 => &crate::hashes::raw_hmac_sha1::RawHmacSha1,
            HashType::HmacSha256 => &crate::hashes::raw_hmac_sha256::RawHmacSha256,
            HashType::Lm => &crate::hashes::raw_lm::RawLm,
            HashType::Wpa => &crate::hashes::raw_wpa::RawWpa,
            HashType::Pkzip => &crate::hashes::raw_pkzip::RawPkzip,
            HashType::KeePass => &crate::hashes::raw_keepass::RawKeePass,
            HashType::SevenZip => &crate::hashes::raw_7z::RawSevenZip,
            HashType::Rar5 => &crate::hashes::raw_rar5::RawRar5,
        }
    }
}

#[derive(Debug, Clone)]
pub enum AttackMode {
    BruteForce { password_len: u32 },
    Mask { mask: [u32; 16], keyspace: u64, password_len: u32 },
    Wordlist { words: Vec<String> },
    Hybrid { words: Vec<String>, mask: [u32; 16], keyspace: u64, password_len: u32, suffix: bool },
    Prince { dict: Vec<String> },
}

pub const CS_SIZES: [u32; 5] = [26, 26, 10, 62, 0];

impl AttackMode {
    pub fn num_passwords(&self) -> u32 {
        match self {
            AttackMode::BruteForce { password_len } => 62u32.pow(*password_len),
            AttackMode::Mask { keyspace, .. } => *keyspace as u32,
            AttackMode::Wordlist { words } => words.len() as u32,
            AttackMode::Hybrid { keyspace, .. } => *keyspace as u32,
            AttackMode::Prince { dict } => {
                let n = dict.len() as u64;
                let singles = n;
                let pairs = n.saturating_mul(n);
                let triples = if n <= 215 {
                    n.saturating_mul(n).saturating_mul(n)
                } else {
                    0
                };
                let total = singles.saturating_add(pairs).saturating_add(triples);
                total.min(u32::MAX as u64) as u32
            }
        }
    }

    pub fn from_mask_str(mask_str: &str) -> Result<(u32, u64, [u32; 16]), String> {
        let mut ids = [0u32; 16];
        let mut pos = 0usize;
        let mut chars = mask_str.chars().peekable();

        while let Some(c) = chars.next() {
            if pos >= 16 {
                return Err("Mask too long (max 16 positions)".to_string());
            }
            if c != '?' {
                return Err(format!(
                    "Unexpected character '{}' in mask. Masks use ?l/?u/?d/?a syntax",
                    c
                ));
            }
            let spec = chars.next().ok_or("Unexpected end of mask after '?'")?;
            let id = match spec {
                'l' => 0u32,
                'u' => 1u32,
                'd' => 2u32,
                'a' => 3u32,
                _ => return Err(format!("Unknown mask spec '?{}'. Use l/u/d/a", spec)),
            };
            ids[pos] = id;
            pos += 1;
        }

        if pos == 0 {
            return Err("Mask is empty".to_string());
        }

        let keyspace: u64 = ids[..pos].iter().map(|&id| CS_SIZES[id as usize] as u64).product();
        if keyspace > u32::MAX as u64 {
            return Err(format!(
                "Mask keyspace ({}) exceeds u32 limit ({})",
                keyspace,
                u32::MAX
            ));
        }

        Ok((pos as u32, keyspace, ids))
    }

    pub fn mask_keyspace(mask: &[u32; 16], len: u32) -> u32 {
        (0..len).map(|i| CS_SIZES[mask[i as usize] as usize]).product::<u32>().max(1)
    }

    pub fn index_to_mask_str(mut idx: u32, mask: &[u32; 16], len: u32) -> String {
        let mut s = String::with_capacity(len as usize);
        for i in 0..len as usize {
            let sz = CS_SIZES[mask[i] as usize];
            let d = idx % sz;
            idx /= sz;
            let c = match mask[i] {
                0 => char::from_u32(d + 97).unwrap(),
                1 => char::from_u32(d + 65).unwrap(),
                2 => char::from_u32(d + 48).unwrap(),
                _ => {
                    if d < 26 { char::from_u32(d + 97).unwrap() }
                    else if d < 52 { char::from_u32(d - 26 + 65).unwrap() }
                    else { char::from_u32(d - 52 + 48).unwrap() }
                }
            };
            s.push(c);
        }
        s
    }

}

impl HashType {
    pub fn cpu_hash(&self, password: &str, salt: &str) -> ([u32; 8], [u32; 8]) {
        match self {
            HashType::Sha224 => {
                use sha2::{Digest, Sha224};
                let mut hasher = Sha224::new();
                hasher.update(password.as_bytes());
                hasher.update(salt.as_bytes());
                let result = hasher.finalize();
                let mut target = [0u32; 8];
                for i in 0..7 {
                    target[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::Sha256 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(password.as_bytes());
                hasher.update(salt.as_bytes());
                let result = hasher.finalize();
                let mut target = [0u32; 8];
                for i in 0..8 {
                    target[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::Sha384 => {
                use sha2::{Digest, Sha384};
                let mut hasher = Sha384::new();
                hasher.update(password.as_bytes());
                hasher.update(salt.as_bytes());
                let result = hasher.finalize();
                let mut target = [0u32; 8];
                let mut extra = [0u32; 8];
                for i in 0..6 {
                    let word = u64::from_be_bytes(result[i * 8..i * 8 + 8].try_into().unwrap());
                    target[i] = word as u32;
                    extra[i] = (word >> 32) as u32;
                }
                (target, extra)
            }
            HashType::Sha1 => {
                use sha1::{Digest, Sha1};
                let mut hasher = Sha1::new();
                hasher.update(password.as_bytes());
                hasher.update(salt.as_bytes());
                let result = hasher.finalize();
                let mut target = [0u32; 8];
                for i in 0..5 {
                    target[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::Sha512 => {
                use sha2::{Digest, Sha512};
                let mut hasher = Sha512::new();
                hasher.update(password.as_bytes());
                hasher.update(salt.as_bytes());
                let result = hasher.finalize();
                let mut target = [0u32; 8];
                let mut extra = [0u32; 8];
                for i in 0..8 {
                    let word = u64::from_be_bytes(result[i * 8..i * 8 + 8].try_into().unwrap());
                    target[i] = word as u32;
                    extra[i] = (word >> 32) as u32;
                }
                (target, extra)
            }
            HashType::HmacSha512 => {
                use sha2::{Digest, Sha512};
                const BLOCK_SIZE: usize = 128;
                let key = password.as_bytes();
                let mut ipad = [0x36u8; BLOCK_SIZE];
                let mut opad = [0x5Cu8; BLOCK_SIZE];
                let k = if key.len() > BLOCK_SIZE {
                    let mut h = Sha512::new();
                    h.update(key);
                    h.finalize().to_vec()
                } else {
                    key.to_vec()
                };
                for i in 0..k.len() {
                    ipad[i] ^= k[i];
                    opad[i] ^= k[i];
                }
                let mut inner = Sha512::new();
                inner.update(&ipad);
                inner.update(salt.as_bytes());
                let inner_hash = inner.finalize();
                let mut outer = Sha512::new();
                outer.update(&opad);
                outer.update(&inner_hash);
                let result = outer.finalize();
                let mut target = [0u32; 8];
                let mut extra = [0u32; 8];
                for i in 0..8 {
                    let word = u64::from_be_bytes(result[i * 8..i * 8 + 8].try_into().unwrap());
                    target[i] = word as u32;
                    extra[i] = (word >> 32) as u32;
                }
                (target, extra)
            }
            HashType::Md5 => {
                use md5::{Digest, Md5};
                let mut hasher = Md5::new();
                hasher.update(password.as_bytes());
                hasher.update(salt.as_bytes());
                let result = hasher.finalize();
                let mut target = [0u32; 8];
                for i in 0..4 {
                    target[i] = u32::from_le_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::Apr1 => {
                let full = crate::hashes::raw_apr1::apr1_hash(password, salt);
                if let Ok(parsed) = crate::hashes::raw_apr1::RawApr1.parse_hash_string(&full) {
                    (parsed.hash_words, [0u32; 8])
                } else {
                    ([0u32; 8], [0u32; 8])
                }
            }
            HashType::Bcrypt => {
                let hash = crate::hashes::raw_bcrypt::bcrypt_hash(password, salt, 4);
                let mut target = [0u32; 8];
                for i in 0..6 {
                    target[i] = u32::from_be_bytes(hash[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::Crc32 => {
                use crc::Crc;
                const CRC32: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
                let mut digest = CRC32.digest();
                digest.update(password.as_bytes());
                digest.update(salt.as_bytes());
                let result = digest.finalize();
                let mut target = [0u32; 8];
                target[0] = result;
                (target, [0u32; 8])
            }
            HashType::Grub2 | HashType::Ntlmv2 | HashType::Wpa | HashType::Pkzip
            | HashType::KeePass | HashType::SevenZip | HashType::Rar5 => {
                // Complex format types — cpu_hash not used (CPU-only wordlist fallback)
                ([0u32; 8], [0u32; 8])
            }
            HashType::Md4 => {
                let hash = crate::hashes::raw_md4::raw_md4(password.as_bytes());
                let mut target = [0u32; 8];
                for i in 0..4 {
                    target[i] = u32::from_le_bytes(hash[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::Ntlm => {
                let hash = crate::hashes::raw_ntlm::ntlm_hash(password);
                let mut target = [0u32; 8];
                for i in 0..4 {
                    target[i] = u32::from_le_bytes(hash[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::Lm => {
                let hash = crate::hashes::raw_lm::lm_hash(password);
                let mut target = [0u32; 8];
                for i in 0..4 {
                    target[i] = u32::from_le_bytes(hash[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::Md5Crypt => {
                let full = crate::hashes::raw_md5crypt::md5crypt(password, salt);
                if let Ok(parsed) = crate::hashes::raw_md5crypt::RawMd5Crypt.parse_hash_string(&full) {
                    (parsed.hash_words, [0u32; 8])
                } else {
                    ([0u32; 8], [0u32; 8])
                }
            }
            HashType::Mssql05 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(salt.as_bytes());
                for b in password.as_bytes() {
                    hasher.update(&[b.to_ascii_uppercase()]);
                }
                let result = hasher.finalize();
                let mut target = [0u32; 8];
                for i in 0..8 {
                    target[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::Mssql12 => {
                use sha2::{Digest, Sha512};
                let mut hasher = Sha512::new();
                hasher.update(salt.as_bytes());
                for b in password.as_bytes() {
                    hasher.update(&[b.to_ascii_uppercase()]);
                }
                let result = hasher.finalize();
                let mut target = [0u32; 8];
                let mut extra = [0u32; 8];
                for i in 0..8 {
                    let word = u64::from_be_bytes(result[i * 8..i * 8 + 8].try_into().unwrap());
                    target[i] = word as u32;
                    extra[i] = (word >> 32) as u32;
                }
                (target, extra)
            }
            HashType::Mysql41 => {
                use sha1::{Digest, Sha1};
                let mut h1 = Sha1::new();
                h1.update(password.as_bytes());
                h1.update(salt.as_bytes());
                let r1 = h1.finalize();
                let mut h2 = Sha1::new();
                h2.update(&r1);
                let r2 = h2.finalize();
                let mut target = [0u32; 8];
                for i in 0..5 {
                    target[i] = u32::from_be_bytes(r2[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::Sha256Crypt => {
                let full = crate::hashes::raw_sha256crypt::sha256crypt(password, salt);
                if let Ok(parsed) = crate::hashes::raw_sha256crypt::RawSha256Crypt.parse_hash_string(&full) {
                    (parsed.hash_words, [0u32; 8])
                } else {
                    ([0u32; 8], [0u32; 8])
                }
            }
            HashType::Sha256d => {
                use sha2::{Digest, Sha256};
                let mut h1 = Sha256::new();
                h1.update(password.as_bytes());
                h1.update(salt.as_bytes());
                let r1 = h1.finalize();
                let mut h2 = Sha256::new();
                h2.update(&r1);
                let r2 = h2.finalize();
                let mut target = [0u32; 8];
                for i in 0..8 {
                    target[i] = u32::from_be_bytes(r2[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::Sha512Crypt => {
                let full = crate::hashes::raw_sha512crypt::sha512crypt(password, salt);
                if let Ok(parsed) = crate::hashes::raw_sha512crypt::RawSha512Crypt.parse_hash_string(&full) {
                    (parsed.hash_words, parsed.extra_words)
                } else {
                    ([0u32; 8], [0u32; 8])
                }
            }
            HashType::Sha512d => {
                use sha2::{Digest, Sha512};
                let mut h1 = Sha512::new();
                h1.update(password.as_bytes());
                h1.update(salt.as_bytes());
                let r1 = h1.finalize();
                let mut h2 = Sha512::new();
                h2.update(&r1);
                let r2 = h2.finalize();
                let mut target = [0u32; 8];
                let mut extra = [0u32; 8];
                for i in 0..8 {
                    let word = u64::from_be_bytes(r2[i * 8..i * 8 + 8].try_into().unwrap());
                    target[i] = word as u32;
                    extra[i] = (word >> 32) as u32;
                }
                (target, extra)
            }
            HashType::Phpass => {
                let full = crate::hashes::raw_phpass::phpass_hash(password, &format!("$P$D{}", salt));
                if let Ok(parsed) = crate::hashes::raw_phpass::RawPhpass.parse_hash_string(&full) {
                    (parsed.hash_words, [0u32; 8])
                } else {
                    ([0u32; 8], [0u32; 8])
                }
            }
            HashType::Drupal7 => {
                let full = crate::hashes::raw_drupal7::drupal7_hash(password, &format!("$S${}", salt));
                if let Ok(parsed) = crate::hashes::raw_drupal7::RawDrupal7.parse_hash_string(&full) {
                    (parsed.hash_words, parsed.extra_words)
                } else {
                    ([0u32; 8], [0u32; 8])
                }
            }
            HashType::Db2 => {
                use sha1::{Digest, Sha1};
                let mut hasher = Sha1::new();
                hasher.update(password.as_bytes());
                hasher.update(salt.as_bytes());
                hasher.update(password.as_bytes());
                let result = hasher.finalize();
                let mut target = [0u32; 8];
                for i in 0..5 {
                    target[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::Pbkdf2Sha256 => {
                let salt_bytes = salt.as_bytes();
                let iterations = 1000u32; // default
                let dk = crate::hashes::raw_pbkdf2_sha256::pbkdf2_hmac_sha256(password.as_bytes(), salt_bytes, iterations);
                let mut target = [0u32; 8];
                for i in 0..8 {
                    target[i] = u32::from_be_bytes(dk[i * 4..i * 4 + 4].try_into().unwrap());
                }
                let mut extra = [0u32; 8];
                extra[0] = iterations;
                (target, extra)
            }
            HashType::SaltedSha1 => {
                use sha1::{Digest, Sha1};
                let mut ctx = Sha1::new();
                ctx.update(password.as_bytes());
                ctx.update(salt.as_bytes());
                let result = ctx.finalize();
                let mut target = [0u32; 8];
                for i in 0..5 {
                    target[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::SaltedSha256 => {
                use sha2::{Digest, Sha256};
                let mut ctx = Sha256::new();
                ctx.update(password.as_bytes());
                ctx.update(salt.as_bytes());
                let result = ctx.finalize();
                let mut target = [0u32; 8];
                for i in 0..8 {
                    target[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::SaltedSha512 => {
                use sha2::{Digest, Sha512};
                let mut ctx = Sha512::new();
                ctx.update(password.as_bytes());
                ctx.update(salt.as_bytes());
                let result = ctx.finalize();
                let mut target = [0u32; 8];
                let mut extra = [0u32; 8];
                for i in 0..8 {
                    let word = u64::from_be_bytes(result[i * 8..i * 8 + 8].try_into().unwrap());
                    target[i] = word as u32;
                    extra[i] = (word >> 32) as u32;
                }
                (target, extra)
            }
            HashType::Postgresql => {
                use md5::{Digest, Md5};
                let mut hasher = Md5::new();
                hasher.update(password.as_bytes());
                hasher.update(salt.as_bytes());
                let result = hasher.finalize();
                let mut target = [0u32; 8];
                for i in 0..4 {
                    target[i] = u32::from_le_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::Dcc => {
                let (hash, _) = crate::hashes::raw_dcc::dcc_hash(password, salt);
                (hash, [0u32; 8])
            }
            HashType::Dcc2 => {
                let (hash, _) = crate::hashes::raw_dcc2::dcc2_hash(password, salt);
                (hash, [0u32; 8])
            }
            HashType::Pdf => {
                // PDF uses verify-based comparison, not cpu_hash
                ([0u32; 8], [0u32; 8])
            }
            HashType::HmacSha1 => {
                let result = crate::hashes::raw_hmac_sha1::hmac_sha1(password.as_bytes(), salt.as_bytes());
                let mut target = [0u32; 8];
                for i in 0..5 {
                    target[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
            HashType::HmacSha256 => {
                let result = crate::hashes::raw_hmac_sha256::hmac_sha256(password.as_bytes(), salt.as_bytes());
                let mut target = [0u32; 8];
                for i in 0..8 {
                    target[i] = u32::from_be_bytes(result[i * 4..i * 4 + 4].try_into().unwrap());
                }
                (target, [0u32; 8])
            }
        }
    }

    pub fn shader_source(&self, mode: &AttackMode) -> &'static str {
        let mode_type = crate::hashes::attack_mode_type(mode);
        self.module().shader_source(&mode_type)
    }

    pub fn name(&self) -> &'static str {
        self.module().name()
    }

    pub fn digest_words(&self) -> u32 {
        self.module().digest_words()
    }

    pub fn hash_to_hex(&self, target: [u32; 8], extra: [u32; 8]) -> String {
        let dw = self.digest_words() as usize;
        match self {
            HashType::Md5 | HashType::Md4 | HashType::Ntlm | HashType::Lm | HashType::Crc32 | HashType::Ntlmv2 => {
                let mut bytes = Vec::with_capacity(dw * 4);
                for i in 0..dw {
                    bytes.extend_from_slice(&target[i].to_le_bytes());
                }
                hex::encode(bytes)
            }
            HashType::Bcrypt => {
                let mut bytes = Vec::with_capacity(dw * 4);
                for i in 0..dw {
                    bytes.extend_from_slice(&target[i].to_be_bytes());
                }
                hex::encode(bytes)
            }
            HashType::Sha1 | HashType::Sha224 | HashType::Sha256 | HashType::Mysql41 | HashType::Sha256d | HashType::Mssql05 | HashType::HmacSha1 | HashType::HmacSha256 => {
                let mut bytes = Vec::with_capacity(dw * 4);
                for i in 0..dw {
                    bytes.extend_from_slice(&target[i].to_be_bytes());
                }
                hex::encode(bytes)
            }
            HashType::HmacSha512 => {
                let mut bytes = Vec::with_capacity(64);
                for i in 0..8 {
                    let word = (extra[i] as u64) << 32 | target[i] as u64;
                    bytes.extend_from_slice(&word.to_be_bytes());
                }
                hex::encode(bytes)
            }
            HashType::Sha384 | HashType::Sha512 | HashType::Sha512d | HashType::Mssql12 | HashType::Grub2 => {
                let mut bytes = Vec::with_capacity(64);
                // digest_words is u32 word count for cpu_verify (≥ 8 for SHA-512 family).
                // For hex output, each u64 is reconstructed from 2 u32 halves.
                let n = if dw > 8 { dw / 2 } else { dw };
                for i in 0..n {
                    let word = (extra[i] as u64) << 32 | target[i] as u64;
                    bytes.extend_from_slice(&word.to_be_bytes());
                }
                hex::encode(bytes)
            }
            HashType::Md5Crypt | HashType::Sha256Crypt | HashType::Apr1 | HashType::Dcc => {
                let mut bytes = Vec::with_capacity(dw * 4);
                for i in 0..dw {
                    bytes.extend_from_slice(&target[i].to_le_bytes());
                }
                hex::encode(bytes)
            }
            HashType::Sha512Crypt => {
                let mut bytes = Vec::with_capacity(64);
                for i in 0..8 {
                    let word = (extra[i] as u64) << 32 | target[i] as u64;
                    bytes.extend_from_slice(&word.to_be_bytes());
                }
                hex::encode(bytes)
            }
            HashType::Phpass | HashType::Postgresql => {
                let mut bytes = Vec::with_capacity(dw * 4);
                for i in 0..dw {
                    bytes.extend_from_slice(&target[i].to_le_bytes());
                }
                hex::encode(bytes)
            }
            HashType::Db2 => {
                let mut bytes = Vec::with_capacity(20);
                for i in 0..5 {
                    bytes.extend_from_slice(&target[i].to_be_bytes());
                }
                hex::encode(bytes)
            }
            HashType::Drupal7 => {
                let mut bytes = Vec::with_capacity(40);
                for i in 0..5 {
                    let word = (extra[i] as u64) << 32 | target[i] as u64;
                    bytes.extend_from_slice(&word.to_be_bytes());
                }
                hex::encode(bytes)
            }
            HashType::Pbkdf2Sha256 => {
                let mut bytes = Vec::with_capacity(32);
                for i in 0..8 {
                    bytes.extend_from_slice(&target[i].to_be_bytes());
                }
                hex::encode(bytes)
            }
            HashType::SaltedSha1 | HashType::SaltedSha256 | HashType::Dcc2 => {
                let mut bytes = Vec::with_capacity(dw * 4);
                for i in 0..dw {
                    bytes.extend_from_slice(&target[i].to_be_bytes());
                }
                hex::encode(bytes)
            }
            HashType::SaltedSha512 => {
                let mut bytes = Vec::with_capacity(64);
                // target/extra are [u32; 8], reconstruct 8 u64 words
                for i in 0..8 {
                    let word = (extra[i] as u64) << 32 | target[i] as u64;
                    bytes.extend_from_slice(&word.to_be_bytes());
                }
                hex::encode(bytes)
            }
            HashType::Pdf => {
                // PDF hashes are $pdf$ formatted strings, not hex. Return U as hex.
                let mut bytes = Vec::with_capacity(32);
                for i in 0..8 {
                    bytes.extend_from_slice(&target[i].to_le_bytes());
                }
                hex::encode(bytes)
            }
            HashType::Wpa | HashType::Pkzip => {
                let mut bytes = Vec::with_capacity(16);
                for i in 0..4 {
                    bytes.extend_from_slice(&target[i].to_le_bytes());
                }
                hex::encode(bytes)
            }
            HashType::KeePass | HashType::SevenZip | HashType::Rar5 => {
                hex::encode(&target[..4].iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>())
            }
        }
    }
}

impl FromStr for HashType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sha224" | "sha-224" => Ok(HashType::Sha224),
            "sha256" | "sha-256" => Ok(HashType::Sha256),
            "sha384" | "sha-384" => Ok(HashType::Sha384),
            "sha1" | "sha-1" => Ok(HashType::Sha1),
            "sha512" | "sha-512" => Ok(HashType::Sha512),
            "hmac-sha512" | "hmacsha512" | "hmac_sha512" => Ok(HashType::HmacSha512),
            "crc32" | "crc-32" => Ok(HashType::Crc32),
            "md5" => Ok(HashType::Md5),
            "ntlm" => Ok(HashType::Ntlm),
            "md4" => Ok(HashType::Md4),
            "ntlmv2" | "ntlm-v2" => Ok(HashType::Ntlmv2),
            "md5crypt" => Ok(HashType::Md5Crypt),
            "sha256crypt" | "sha-256crypt" => Ok(HashType::Sha256Crypt),
            "sha256d" | "sha-256d" | "double-sha256" | "bitcoin" => Ok(HashType::Sha256d),
            "sha512crypt" | "sha-512crypt" => Ok(HashType::Sha512Crypt),
            "sha512d" | "sha-512d" | "double-sha512" => Ok(HashType::Sha512d),
            "apr1" | "apache" => Ok(HashType::Apr1),
            "bcrypt" | "blowfish" => Ok(HashType::Bcrypt),
            "phpass" | "wordpress" => Ok(HashType::Phpass),
            "drupal7" | "drupal-7" => Ok(HashType::Drupal7),
            "db2" => Ok(HashType::Db2),
            "grub2" | "grub" => Ok(HashType::Grub2),
            "pbkdf2-sha256" | "pbkdf2sha256" | "pbkdf2" => Ok(HashType::Pbkdf2Sha256),
            "postgresql" | "postgres" | "pg" => Ok(HashType::Postgresql),
            "mysql41" | "mysql-4.1" | "mysql4.1" | "mysql" => Ok(HashType::Mysql41),
            "mssql05" | "mssql-2005" | "mssql2005" | "mssql" => Ok(HashType::Mssql05),
            "mssql12" | "mssql-2012" | "mssql2012" => Ok(HashType::Mssql12),
            "salted-sha1" | "saltedsha1" | "sha1salt" | "sha1-salt" => Ok(HashType::SaltedSha1),
            "salted-sha256" | "saltedsha256" | "sha256salt" | "sha256-salt" => Ok(HashType::SaltedSha256),
            "salted-sha512" | "saltedsha512" | "sha512salt" | "sha512-salt" => Ok(HashType::SaltedSha512),
            "dcc" => Ok(HashType::Dcc),
            "dcc2" | "dcc-2" => Ok(HashType::Dcc2),
            "pdf" => Ok(HashType::Pdf),
            "hmac-sha1" | "hmacsha1" | "hmac_sha1" => Ok(HashType::HmacSha1),
            "hmac-sha256" | "hmacsha256" | "hmac_sha256" => Ok(HashType::HmacSha256),
            "lm" => Ok(HashType::Lm),
            "wpa" => Ok(HashType::Wpa),
            "pkzip" => Ok(HashType::Pkzip),
            "keepass" | "kp" => Ok(HashType::KeePass),
            "7z" | "sevenzip" | "7-zip" => Ok(HashType::SevenZip),
            "rar5" | "rar" => Ok(HashType::Rar5),
            "auto" => Err("AUTO".to_string()),
            _ => {
                // Try the registry for dynamic types
                if crate::hashes::registry::find_by_name(s).is_some() {
                    Err(format!("AUTO:{}", s))
                } else {
                    Err(format!("Unknown hash type: {}", s))
                }
            }
        }
    }
}

pub fn detect_hash_type(hex: &str) -> Option<HashType> {
    let clean = hex.trim().strip_prefix("0x").unwrap_or(hex.trim());
    match clean.len() {
         8 => Some(HashType::Crc32),
         56 => Some(HashType::Sha224),
        64 => Some(HashType::Sha256),
        96 => Some(HashType::Sha384),
        40 => Some(HashType::Sha1),
        128 => Some(HashType::Sha512),
          32 => {
                // 32 hex chars: could be MD5, MD4, NTLM, or LM. Try MD5 first (most common).
                Some(HashType::Md5)
            }
        _ => None,
    }
}

/// Combine hash_words and extra_words from ParsedHash into a single [u32; 16] array.
/// All hash types have at most 16 u32 words (8 hash + 8 extra).
pub fn full_hash_slice(parsed: &crate::hashes::ParsedHash, digest_words: usize) -> [u32; 16] {
    let mut combined = [0u32; 16];
    let n = digest_words.min(8);
    combined[..n].copy_from_slice(&parsed.hash_words[..n]);
    if digest_words > 8 {
        let extra_n = (digest_words - 8).min(8);
        combined[8..8 + extra_n].copy_from_slice(&parsed.extra_words[..extra_n]);
    }
    combined
}

pub fn parse_hex_hash_opt(hex: &str, preferred: Option<HashType>) -> Result<([u32; 8], [u32; 8], HashType), String> {
    let clean = hex.trim().strip_prefix("0x").unwrap_or(hex.trim());

    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("Hash '{}' contains non-hex characters. For prefixed hashes (like $1$, $6$, etc.), use --hash-type explicitly.", clean));
    }

    let ht = match preferred {
        Some(pt) => pt,
        None => detect_hash_type(clean).ok_or_else(|| {
            format!("Unrecognized hash length {} (expected 32/40/64/128 hex chars)", clean.len())
        })?,
    };

    let expected = match ht {
        HashType::Crc32 => 8,
        HashType::Md5 | HashType::Md4 | HashType::Ntlm | HashType::Md5Crypt | HashType::Dcc | HashType::Lm => 32,
        HashType::Bcrypt => 48,
        HashType::Phpass => 32,
        HashType::Sha224 => 56,
        HashType::Sha1 | HashType::Mysql41 | HashType::HmacSha1 | HashType::Dcc2 => 40,
        HashType::Sha256 | HashType::Sha256Crypt | HashType::Sha256d | HashType::HmacSha256 => 64,
        HashType::Sha384 => 96,
        HashType::Sha512 | HashType::Sha512Crypt | HashType::Sha512d | HashType::HmacSha512 => 128,
        HashType::Apr1 | HashType::Drupal7 | HashType::Pdf | HashType::Db2 | HashType::Grub2 | HashType::Ntlmv2 => 0,
        HashType::Pbkdf2Sha256 => 0,
        HashType::Postgresql => 0,
        HashType::SaltedSha1 | HashType::SaltedSha256 | HashType::SaltedSha512 => 0,
        HashType::Mssql05 | HashType::Mssql12 | HashType::Wpa | HashType::Pkzip | HashType::KeePass | HashType::SevenZip | HashType::Rar5 => 0,
    };
    if clean.len() != expected {
        return Err(format!("Expected {expected} hex chars for {:?}, got {}", ht, clean.len()));
    }

    let parsed = ht.module().parse_hash_string(clean).map_err(|e| {
        format!("Failed to parse {}: {}", ht.name(), e)
    })?;

    Ok((parsed.hash_words, parsed.extra_words, ht))
}
