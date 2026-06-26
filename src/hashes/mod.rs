pub mod raw_apr1;
pub mod raw_bcrypt;
pub mod raw_crc32;
pub mod raw_db2;
pub mod raw_dcc;
pub mod raw_dcc2;
pub mod raw_drupal7;
pub mod raw_grub2;
pub mod raw_hmac_sha1;
pub mod raw_hmac_sha256;
pub mod raw_hmac_sha512;
pub mod raw_lm;
pub mod raw_md4;
pub mod raw_md5;
pub mod raw_md5crypt;
pub mod raw_mssql05;
pub mod raw_mssql12;
pub mod raw_mysql41;
pub mod raw_ntlm;
pub mod raw_ntlmv2;
pub mod raw_pbkdf2_sha256;
pub mod raw_pdf;
pub mod raw_phpass;
pub mod raw_pkzip;
pub mod raw_postgresql;
pub mod raw_salted;
pub mod raw_sha1;
pub mod raw_sha224;
pub mod raw_sha256;
pub mod raw_sha256crypt;
pub mod raw_sha256d;
pub mod raw_sha384;
pub mod raw_sha512;
pub mod raw_sha512crypt;
pub mod raw_sha512d;
pub mod raw_7z;
pub mod raw_keepass;
pub mod raw_rar5;
pub mod raw_wpa;
pub mod registry;

pub struct HashPattern {
    pub prefix: Option<&'static str>,
    pub hex_len: Option<usize>,
    pub priority: u8,
}

pub struct ParsedHash {
    pub hash_words: [u32; 8],
    pub extra_words: [u32; 8],
    pub salt: Vec<u8>,
    #[allow(dead_code)]
    pub digest_words: u32,
}

pub trait HashModule: Send + Sync {
    fn name(&self) -> &'static str;
    #[allow(dead_code)]
    fn mode(&self) -> u32;
    fn digest_words(&self) -> u32;
    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool;
    fn shader_source(&self, mode: &AttackModeType) -> &'static str;
    fn needs_int64(&self) -> bool;
    fn detect_patterns(&self) -> &[HashPattern];
    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackModeType {
    BruteForce,
    Mask,
    Wordlist,
}

pub fn attack_mode_type(mode: &crate::AttackMode) -> AttackModeType {
    match mode {
        crate::AttackMode::BruteForce { .. } => AttackModeType::BruteForce,
        crate::AttackMode::Mask { .. } => AttackModeType::Mask,
        crate::AttackMode::Wordlist { .. } => AttackModeType::Wordlist,
        crate::AttackMode::Hybrid { .. } => AttackModeType::Wordlist,
        crate::AttackMode::Prince { .. } => AttackModeType::Wordlist,
    }
}
