use std::path::PathBuf;
use std::str::FromStr;
use crate::hash_backend::{HashType, parse_hex_hash_opt};
use crate::hashes::registry;
use crate::potfile::Potfile;

/// Suggest possible hash types for a hex string that failed auto-detection
pub fn suggest_hash_types(s: &str) -> String {
    let clean = s.trim().split(':').next().unwrap_or(s.trim());
    let suggestions: Vec<&str> = match clean.len() {
         8 => vec!["CRC32", "try --hash-type crc32"],
         32 => vec!["MD5 (common)", "NTLM", "MD4", "LM", "DCC", "try --hash-type md5, ntlm, or lm"],
         40 => vec!["SHA-1", "MySQL 4.1", "DB2 (hash:salt)", "try --hash-type sha1, mysql41, or db2"],
         56 => vec!["SHA-224", "try --hash-type sha224"],
         64 => vec!["SHA-256", "SHA-256d / Bitcoin", "try --hash-type sha256 or sha256d"],
         96 => vec!["SHA-384", "try --hash-type sha384"],
        128 => vec!["SHA-512", "SHA-512d", "HMAC-SHA512", "try --hash-type sha512, sha512d, or hmac-sha512"],
        _ if clean.starts_with('$') => vec!["Unrecognized $prefix — check hash format"],
        _ => vec!["Could be MD5 (common), NTLM, or MD4; try --hash-type md5"],
    };
    suggestions.join("; ")
}

pub fn maybe_suggest(s: &str) {
    let suggestion = suggest_hash_types(s);
    eprintln!("  Hint: {}", suggestion);
}

/// Convert a salt byte slice to [u32; 16] (reverse order, one byte per u32).
pub fn salt_vec_to_arr(salt: &[u8]) -> ([u32; 16], u32) {
    let len = salt.len().min(16) as u32;
    let mut arr = [0u32; 16];
    for (i, &b) in salt.iter().rev().enumerate().take(len as usize) {
        arr[i] = b as u32;
    }
    (arr, len)
}

/// Convert a [u32; 16] salt array back to a byte vector.
pub fn salt_from_arr(arr: &[u32; 16], len: u32) -> Vec<u8> {
    (0..len as usize)
        .map(|i| arr[len as usize - 1 - i] as u8)
        .collect()
}

/// Parse a hashlist file, detecting hash types per line.
pub fn parse_hashlist_file_opt(path: &PathBuf, preferred: Option<HashType>) -> Vec<(String, Option<String>, [u32; 8], [u32; 8], HashType)> {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Failed to read hashlist '{}': {}", path.display(), e);
        std::process::exit(1);
    });

    let mut entries: Vec<(String, Option<String>, [u32; 8], [u32; 8], HashType)> = Vec::new();
    let mut detected_type: Option<HashType> = None;

    for (lineno, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Extract optional username prefix: "username:hash"
        let (username, effective_line) = if let Some(colon_pos) = trimmed.find(':') {
            let candidate = &trimmed[..colon_pos];
            // If the part before ':' is not all-hex and doesn't start with '$', it's a username
            if !candidate.chars().all(|c| c.is_ascii_hexdigit()) && !candidate.starts_with('$') {
                (Some(candidate.to_string()), &trimmed[colon_pos + 1..])
            } else {
                (None, trimmed)
            }
        } else {
            (None, trimmed)
        };

        let (th, the, ht) = if effective_line.starts_with('$') {
            // Prefixed hash — always autodetect from prefix
            if let Some(module) = registry::autodetect(effective_line) {
                let ht = HashType::from_str(module.name()).unwrap_or_else(|_| {
                    eprintln!("Error on line {}: autodetected '{}' but cannot map", lineno + 1, module.name());
                    std::process::exit(1);
                });
                let parsed = ht.module().parse_hash_string(effective_line).unwrap_or_else(|e| {
                    eprintln!("Error on line {}: {}", lineno + 1, e);
                    std::process::exit(1);
                });
                (parsed.hash_words, parsed.extra_words, ht)
            } else {
                eprintln!("Error on line {}: unable to autodetect hash type from '{}'", lineno + 1, effective_line);
                maybe_suggest(effective_line);
                std::process::exit(1);
            }
        } else if effective_line.contains(':') {
            // hash:salt format — use autodetect on the full string
            if let Some(module) = registry::autodetect(effective_line) {
                let ht = HashType::from_str(module.name()).unwrap_or_else(|_| {
                    eprintln!("Error on line {}: autodetected '{}' but cannot map", lineno + 1, module.name());
                    std::process::exit(1);
                });
                let parsed = ht.module().parse_hash_string(effective_line).unwrap_or_else(|e| {
                    eprintln!("Error on line {}: {}", lineno + 1, e);
                    std::process::exit(1);
                });
                (parsed.hash_words, parsed.extra_words, ht)
            } else {
                eprintln!("Error on line {}: unable to autodetect hash type from '{}'", lineno + 1, effective_line);
                maybe_suggest(effective_line);
                std::process::exit(1);
            }
        } else {
            parse_hex_hash_opt(effective_line, preferred).unwrap_or_else(|e| {
                eprintln!("Error on line {} of hashlist '{}': {}", lineno + 1, path.display(), e);
                maybe_suggest(effective_line);
                std::process::exit(1);
            })
        };
        if let Some(ref dt) = detected_type {
            if &ht != dt {
                eprintln!("Error on line {}: mixed hash types detected ({} vs {:?})", lineno + 1, ht.name(), dt);
                std::process::exit(1);
            }
        } else {
            detected_type = Some(ht);
        }
        entries.push((effective_line.to_string(), username, th, the, ht));
    }

    if entries.is_empty() {
        eprintln!("Hashlist '{}' is empty", path.display());
        std::process::exit(1);
    }

    entries
}

/// Read wordlist passwords: from file or from potfile (loopback).
pub fn read_wordlist_words(loopback: bool, wordlist_path: Option<PathBuf>, potfile: &Potfile) -> Vec<String> {
    let words: Vec<String> = if loopback {
        potfile.entries().iter()
            .map(|(_, pw)| pw.to_string())
            .filter(|w| !w.is_empty())
            .collect()
    } else {
        let path = wordlist_path.unwrap_or_else(|| {
            std::process::exit(1);
        });
        let content = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("Failed to read wordlist '{}': {}", path.display(), e);
            std::process::exit(1);
        });
        content.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && l.len() <= 4)
            .collect()
    };
    if words.is_empty() {
        eprintln!("No words available (wordlist is empty or all filtered out)");
        std::process::exit(1);
    }
    words
}

/// Save session state to disk.
pub fn save_session_state(
    sess: &crate::session::Session,
    hash_type: &str,
    args: &crate::cli::Args,
    entry_hex: &str,
    salt_arr: &[u32; 16],
    salt_len: u32,
    password_len: u32,
    keyspace: u32,
    progress: u32,
    total_found: &[(usize, String, String)],
) {
    let salt = salt_from_arr(salt_arr, salt_len);
    let salt_str = String::from_utf8_lossy(&salt).to_string();
    let state = crate::session::SessionState {
        hash_type: hash_type.to_string(),
        attack_mode: args.mode.clone(),
        target_hash: entry_hex.to_string(),
        salt: salt_str,
        password_len,
        keyspace: keyspace as u64,
        progress: progress as u64,
        mask: args.mask.clone(),
        wordlist: args.wordlist.as_ref().map(|p| p.to_string_lossy().to_string()),
        rules_file: args.rules.as_ref().map(|p| p.to_string_lossy().to_string()),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_default(),
        cracked_hashes: total_found.iter().map(|(_, h, p)| (h.clone(), p.clone())).collect(),
    };
    if let Err(e) = sess.save(&state) {
        eprintln!("Warning: failed to save session: {}", e);
    }
}
