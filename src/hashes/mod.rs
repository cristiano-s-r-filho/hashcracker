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

/// Detection pattern for auto-identifying a hash type from its string representation.
///
/// A hash is matched if its string starts with `prefix` OR its hex length equals `hex_len`.
/// When multiple modules match, the one with highest `priority` wins.
pub struct HashPattern {
    /// Optional literal prefix (e.g. `"$1$"`, `"$2y$"`, `"$pkzip$"`)
    pub prefix: Option<&'static str>,
    /// Optional expected hex-char length (e.g. 32 for MD5, 64 for SHA-256)
    pub hex_len: Option<usize>,
    /// Match priority; higher values win when multiple patterns match
    pub priority: u8,
}

/// A hash parsed into its internal representation for GPU comparison.
pub struct ParsedHash {
    /// First 8 digest words (primary comparison)
    pub hash_words: [u32; 8],
    /// Next 8 digest words (for hashes with >8 words, e.g. SHA-512)
    pub extra_words: [u32; 8],
    /// Salt bytes extracted from the hash string
    pub salt: Vec<u8>,
    /// Number of u32 digest words produced by this hash type
    #[allow(dead_code)]
    pub digest_words: u32,
}

/// Trait that every hash type must implement.
///
/// Provides the CPU verification function, WGSL shader source,
/// auto-detection patterns, and hash-string parsing.
pub trait HashModule: Send + Sync {
    /// Human-readable name (e.g. `"md5"`, `"sha256"`, `"bcrypt"`)
    fn name(&self) -> &'static str;
    /// Hashcat mode number for reference
    #[allow(dead_code)]
    fn mode(&self) -> u32;
    /// Number of u32 digest words this hash produces
    fn digest_words(&self) -> u32;
    /// Verify a password against a parsed hash + salt. Returns `true` if it matches.
    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool;
    /// WGSL shader source for the given attack mode; empty string = CPU-only.
    fn shader_source(&self, mode: &AttackModeType) -> &'static str;
    /// Whether the WGSL kernel requires `SHADER_INT64` feature (for SHA-512 family)
    fn needs_int64(&self) -> bool;
    /// List of detection patterns used during auto-detection
    fn detect_patterns(&self) -> &[HashPattern];
    /// Parse a hash string into its internal representation
    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, String>;
}

/// The GPU pipeline variant for a given attack mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackModeType {
    /// Brute-force kernel (single workgroup, no wordlist input)
    BruteForce,
    /// Mask kernel (position-aware charset per slot)
    Mask,
    /// Wordlist/hybrid kernel (reads password candidates from a buffer)
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
