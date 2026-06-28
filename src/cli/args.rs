use clap::Parser;
use std::path::PathBuf;

/// A parsed hash entry ready for cracking.
#[derive(Debug, Clone)]
pub struct HashEntry {
    /// Original hash string (hex or prefixed format)
    pub hex: String,
    /// First 8 u32 digest words (primary GPU comparison)
    pub hash: [u32; 8],
    /// Next 8 u32 digest words (for 128-byte digest hashes like SHA-512)
    pub hash_extra: [u32; 8],
    /// Salt buffer padded to 64 bytes (16 × u32)
    pub salt: [u32; 16],
    /// Salt length in bytes
    pub salt_len: u32,
    /// Username extracted from `user:hash` format (DCC, PostgreSQL)
    pub username: Option<String>,
}

/// Command-line arguments for hashcracker.
#[derive(Parser, Clone)]
#[command(
    name = "hashcracker",
    version,
    about = "GPU-accelerated password cracker — 42 hash types, Vulkan/Metal/DX12, single binary",
    long_about = "hashcracker — GPU-accelerated password cracking with a focus on portability and ergonomics.

Supports 42 hash types across CPU and GPU (Vulkan via wgpu).
Auto-detects hash type from format prefixes and hex lengths.

Examples:
  hashcracker --hash-type md5 --hash e99a18c428cb38d5f260853678922e03
  hashcracker --hashlist hashes.txt --wordlist rockyou.txt --rules best64.rule
  hashcracker --hash '$1$c$TEPt3Oo2oa8cNB9HQmta7/'
  hashcracker --bench
  hashcracker --show
  hashcracker --extract pdf document.pdf

Documentation: https:
",
    arg_required_else_help = true,
)]
pub struct Args {
    #[arg(short, long, default_value = "brute",
        help = "Attack mode: brute, wordlist, mask, hybrid, prince, single, markov, incremental")]
    pub mode: String,

    #[arg(help = "Known plaintext password (for benchmarking / known-plaintext mode)")]
    pub password: Option<String>,

    #[arg(long, default_value = "auto",
        help = "Hash type (auto-detect, or pick from 42 types: md5, sha1, sha256, sha512, ntlm, bcrypt, keepass, ...)")]
    pub hash_type: String,

    #[arg(short, long,
        help = "Wordlist file path")]
    pub wordlist: Option<PathBuf>,

    #[arg(long,
        help = "Mask pattern, e.g. ?l?l?d?d?d (?l=lower, ?u=upper, ?d=digit, ?a=all)")]
    pub mask: Option<String>,

    #[arg(long,
        help = "Prepend word to mask result (suffix mode is default)")]
    pub prefix: bool,

    #[arg(long, default_value = "",
        help = "Static salt (hex or string) for hash computation")]
    pub salt: String,

    #[arg(long,
        help = "Rules file for wordlist mode (hashcat-compatible .rule syntax)")]
    pub rules: Option<PathBuf>,

    #[arg(long,
        help = "Stacked rules files applied sequentially")]
    pub rules_stack: Vec<PathBuf>,

    #[arg(long,
        help = "Filter constraints: min=X, max=X, chars=abc")]
    pub filter: Vec<String>,

    #[arg(long,
        help = "Single target hash (hex string or prefixed format like $1$..., $6$...)")]
    pub hash: Option<String>,

    #[arg(long,
        help = "Hashlist file (one hash per line, supports user:hash format)")]
    pub hashlist: Option<PathBuf>,

    #[arg(long,
        help = "Prince mode dictionary file (word-concatenation chains)")]
    pub prince_dict: Option<PathBuf>,

    #[arg(long, default_value = "false",
        help = "Use potfile cracked passwords as wordlist input")]
    pub loopback: bool,

    #[arg(long, default_value = "false",
        help = "Generate candidate passwords to stdout (no cracking)")]
    pub stdout: bool,

    #[arg(long,
        help = "Session name for save/resume")]
    pub session: Option<String>,

    #[arg(long,
        help = "Custom potfile path (default: ~/.hashcracker/potfile)")]
    pub potfile: Option<PathBuf>,

    #[arg(long, default_value = "false",
        help = "Show cracked passwords from potfile")]
    pub show: bool,

    #[arg(long, default_value = "false",
        help = "Show remaining (uncracked) hashes")]
    pub left: bool,

    #[arg(long, default_value = "false",
        help = "Only output cracked passwords, suppress progress and banner")]
    pub quiet: bool,

    #[arg(long, default_value = "false",
        help = "Show detailed per-event GPU stats")]
    pub verbose: bool,

    #[arg(long, default_value = "false",
        help = "Output cracked password as hex-encoded string")]
    pub hex: bool,

    #[arg(long, default_value = "false",
        help = "Machine-readable JSON-line output per event")]
    pub json: bool,

    #[arg(long, default_value = "false",
        help = "Benchmark all supported hash types")]
    pub bench: bool,

    #[arg(long,
        help = "Extract hash from file (pdf, zip)")]
    pub extract: Option<String>,

    #[arg(long, default_value = "false",
        help = "Run quick demo with embedded test data")]
    pub demo: bool,
}
