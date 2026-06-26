pub mod benchmark;
pub mod cpu_pipeline;
pub mod extraction;
pub mod attack;
pub mod helpers;
pub mod stdout;

use std::path::PathBuf;
use std::str::FromStr;
use crate::hash_backend::{HashType, AttackMode, parse_hex_hash_opt};
use crate::potfile::Potfile;
use crate::session;

/// Central application state. Holds all configuration and mutable state
/// for a single cracking session.
pub struct App {
    pub args: crate::cli::Args,
    pub hash_type: HashType,
    pub attack_mode: AttackMode,
    pub potfile: Potfile,
    pub entries: Vec<crate::cli::HashEntry>,
    pub salt: [u32; 16],
    pub salt_len: u32,
    pub num_passwords: u32,
    pub active_session: Option<session::Session>,
    pub session_state_opt: Option<session::SessionState>,
}

impl App {
    /// Parse CLI args and build App.
    pub fn new(args: crate::cli::Args) -> Self {
        let potfile_path = args.potfile.clone().unwrap_or_else(|| {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".hashcracker").join("potfile")
        });
        Self {
            args,
            hash_type: HashType::Sha256,
            attack_mode: AttackMode::BruteForce { password_len: 1 },
            potfile: Potfile::with_path(potfile_path),
            entries: Vec::new(),
            salt: [0u32; 16],
            salt_len: 0,
            num_passwords: 0,
            active_session: None,
            session_state_opt: None,
        }
    }

    /// Run show mode: display cracked passwords from potfile.
    pub fn run_show(&self) {
        let hashes: Vec<String> = self.collect_show_hashes();
        println!("Cracked passwords:");
        for (h, p) in self.potfile.entries() {
            if hashes.is_empty() || hashes.iter().any(|x| x == h) {
                println!("  {}:{}", h, p);
            }
        }
    }

    /// Run left mode: display uncracked hashes.
    pub fn run_left(&self) {
        let hashes: Vec<String> = self.collect_show_hashes();
        println!("Remaining hashes:");
        for h in &hashes {
            if !self.potfile.is_cracked(h) {
                println!("  {}", h);
            }
        }
    }

    /// Collect hashes for show/left modes.
    fn collect_show_hashes(&self) -> Vec<String> {
        if let Some(hashlist_path) = &self.args.hashlist {
            std::fs::read_to_string(hashlist_path)
                .unwrap_or_default()
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect()
        } else if let Some(hash_hex) = &self.args.hash {
            vec![hash_hex.clone()]
        } else if let Some(ref pw) = self.args.password {
            let ht = HashType::from_str(&self.args.hash_type).unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            });
            let (th, the) = ht.cpu_hash(pw, &self.args.salt);
            vec![ht.hash_to_hex(th, the)]
        } else {
            vec![]
        }
    }

    /// Initialize session (load or create).
    pub fn init_session(&mut self) {
        self.active_session = self.args.session.as_ref().map(|name| session::Session::new(name));
        if let Some(ref mut sess) = self.active_session {
            if sess.exists() {
                eprintln!("Resuming session '{}'...", self.args.session.as_ref().unwrap());
                match sess.load() {
                    Ok(state) => {
                        eprintln!("  Loaded session: {} progress {}/{} ({} found)",
                            state.hash_type, state.progress, state.keyspace, state.cracked_hashes.len());
                        self.session_state_opt = Some(state);
                    }
                    Err(e) => {
                        eprintln!("Warning: failed to load session: {}", e);
                    }
                }
            }
        }
    }

    /// Parse hash list or single hash into entries.
    pub fn collect_entries(&mut self) {
        let (entries, hash_type, _password, _parsed_salt) = if let Some(hashlist_path) = &self.args.hashlist {
            let preferred = if self.args.hash_type == "auto" { None }
                else { HashType::from_str(&self.args.hash_type).ok() };
            let parsed = crate::app::helpers::parse_hashlist_file_opt(hashlist_path, preferred);
            let ht = parsed[0].4;
            let _pw = self.args.password.clone().unwrap_or_else(|| "abc".to_string());
            let first_hex = &parsed[0].0;
            let first_salt = if let Ok(p) = ht.module().parse_hash_string(first_hex) { p.salt } else { Vec::new() };
            let (salt_arr, salt_len) = crate::app::helpers::salt_vec_to_arr(&first_salt);
            let entries: Vec<crate::cli::HashEntry> = parsed.into_iter().map(|(hex, username, h, he, _)| {
                crate::cli::HashEntry { hex, hash: h, hash_extra: he, salt: salt_arr, salt_len, username }
            }).collect();
            (entries, ht, _pw, first_salt)
        } else if let Some(hash_str) = &self.args.hash {
            let (th, the, ht, parsed_salt) = self.parse_single_hash(hash_str);
            let mut the = the;
            if ht == HashType::Bcrypt && hash_str.len() > 6 && hash_str.as_bytes()[0] == b'$' {
                if let Ok(cost) = hash_str[4..6].parse::<u32>() { the[0] = cost; }
            }
            let (salt_arr, salt_len) = crate::app::helpers::salt_vec_to_arr(&parsed_salt);
            let _pw = self.args.password.clone().unwrap_or_else(|| "abc".to_string());
            (vec![crate::cli::HashEntry { hex: hash_str.clone(), hash: th, hash_extra: the, salt: salt_arr, salt_len, username: None }], ht, _pw, parsed_salt)
        } else {
            let ht = HashType::from_str(&self.args.hash_type).unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                eprintln!("Available: sha256, sha1, sha512, md5, md4, ntlm, md5crypt, sha256crypt, sha512crypt, phpass, wordpress, bcrypt, drupal7, pbkdf2-sha256, salted-sha1, salted-sha256, salted-sha512, dcc, dcc2, auto");
                std::process::exit(1);
            });
            let pw = self.args.password.clone().unwrap_or_else(|| "abc".to_string());
            if pw.is_empty() || pw.len() > 16 { eprintln!("Password must be 1-16 characters"); std::process::exit(1); }
            let (th, the) = ht.cpu_hash(&pw, &self.args.salt);
            let hex_str = ht.hash_to_hex(th, the);
            let (salt_arr, salt_len) = crate::app::helpers::salt_vec_to_arr(self.args.salt.as_bytes());
            (vec![crate::cli::HashEntry { hex: hex_str, hash: th, hash_extra: the, salt: salt_arr, salt_len, username: None }], ht, pw, self.args.salt.as_bytes().to_vec())
        };

        self.hash_type = hash_type;
        self.entries = entries;
    }

    /// Parse a single --hash argument
    fn parse_single_hash(&self, hash_str: &str) -> ([u32; 8], [u32; 8], HashType, Vec<u8>) {
        if hash_str.trim().starts_with('$') || hash_str.trim().contains(':') {
            if let Some(module) = crate::hashes::registry::autodetect(hash_str) {
                let ht = HashType::from_str(module.name()).unwrap_or_else(|_| {
                    eprintln!("Autodetected '{}' but cannot map to HashType", module.name());
                    std::process::exit(1);
                });
                let parsed = ht.module().parse_hash_string(hash_str).unwrap_or_else(|e| {
                    eprintln!("Error parsing --hash: {}", e);
                    std::process::exit(1);
                });
                (parsed.hash_words, parsed.extra_words, ht, parsed.salt)
            } else {
                eprintln!("Unable to autodetect hash type from '{}'", hash_str);
                crate::app::helpers::maybe_suggest(hash_str);
                std::process::exit(1);
            }
        } else {
            let preferred = if self.args.hash_type == "auto" { None }
                else { HashType::from_str(&self.args.hash_type).ok() };
            let (th, the, ht) = parse_hex_hash_opt(hash_str, preferred).unwrap_or_else(|e| {
                eprintln!("Error parsing --hash: {}", e);
                crate::app::helpers::maybe_suggest(hash_str);
                std::process::exit(1);
            });
            (th, the, ht, Vec::new())
        }
    }

    /// Parse attack mode and compute keyspace.
    pub fn parse_attack_mode(&mut self) {
        let is_auto = self.args.hash_type == "auto" || self.args.hash.is_some() || self.args.hashlist.is_some();
        let password = self.args.password.clone().unwrap_or_else(|| "abc".to_string());

        let (attack_mode, num_passwords) = match self.args.mode.as_str() {
            "brute" | "bruteforce" => {
                if !is_auto && password.len() > 4 {
                    eprintln!("For brute-force mode, password must be 1-4 characters"); std::process::exit(1);
                }
                if !is_auto && !password.chars().all(|c| c.is_ascii_alphanumeric()) {
                    eprintln!("Password must contain only alphanumeric characters"); std::process::exit(1);
                }
                let pw_len = password.len() as u32;
                (AttackMode::BruteForce { password_len: pw_len }, 62u32.pow(pw_len))
            }
            "mask" => {
                let mask_str = self.args.mask.clone().unwrap_or_else(|| {
                    eprintln!("Mask mode requires --mask <pattern> (e.g. ?l?l?d?d)"); std::process::exit(1);
                });
                let (pw_len, ks, mask) = AttackMode::from_mask_str(&mask_str).unwrap_or_else(|e| {
                    eprintln!("Invalid mask: {}", e); std::process::exit(1);
                });
                (AttackMode::Mask { mask, keyspace: ks, password_len: pw_len }, ks as u32)
            }
            "wordlist" => {
                let words = crate::app::helpers::read_wordlist_words(
                    self.args.loopback, self.args.wordlist.clone(), &self.potfile);
                let words = self.apply_rules(words);
                let words = self.apply_rules_stack(words);
                let words = self.apply_filters(words);
                (AttackMode::Wordlist { words: words.clone() }, words.len() as u32)
            }
            "hybrid" => {
                let words = crate::app::helpers::read_wordlist_words(
                    self.args.loopback, self.args.wordlist.clone(), &self.potfile);
                let mask_str = self.args.mask.clone().unwrap_or_else(|| {
                    eprintln!("Hybrid mode requires --mask <pattern>"); std::process::exit(1);
                });
                let (mask_len, _, mask) = AttackMode::from_mask_str(&mask_str).unwrap_or_else(|e| {
                    eprintln!("Invalid mask: {}", e); std::process::exit(1);
                });
                let words = if !self.args.filter.is_empty() {
                    let filters = crate::filter::parse_filters(&self.args.filter);
                    let filtered: Vec<_> = words.into_iter().filter(|w| crate::filter::apply_filters(w, &filters)).collect();
                    eprintln!("Filtered to {} words", filtered.len()); filtered
                } else { words };
                let total_ks = (words.len() as u64).saturating_mul(AttackMode::mask_keyspace(&mask, mask_len) as u64);
                if total_ks > u32::MAX as u64 { eprintln!("Hybrid keyspace exceeds u32 limit"); std::process::exit(1); }
                (AttackMode::Hybrid { words, mask, keyspace: total_ks, password_len: mask_len, suffix: !self.args.prefix }, total_ks as u32)
            }
            "incremental" => (AttackMode::BruteForce { password_len: 1 }, 62u32.pow(1)),
            "prince" => {
                let path = self.args.prince_dict.clone().unwrap_or_else(|| {
                    eprintln!("Prince mode requires --prince-dict <path>"); std::process::exit(1);
                });
                let content = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                    eprintln!("Failed to read prince dict '{}': {}", path.display(), e); std::process::exit(1);
                });
                let mut dict: Vec<String> = content.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
                if !self.args.filter.is_empty() {
                    let filters = crate::filter::parse_filters(&self.args.filter);
                    dict = dict.into_iter().filter(|w| crate::filter::apply_filters(w, &filters)).collect();
                    eprintln!("Filtered to {} prince words", dict.len());
                }
                let n = AttackMode::Prince { dict: dict.clone() }.num_passwords();
                (AttackMode::Prince { dict }, n)
            }
            "single" => (AttackMode::Wordlist { words: vec![] }, 0),
            "markov" => (AttackMode::Wordlist { words: vec![] }, 0),
            _ => { eprintln!("Unknown mode"); std::process::exit(1); }
        };
        self.attack_mode = attack_mode;
        self.num_passwords = num_passwords;
    }

    fn apply_rules(&self, words: Vec<String>) -> Vec<String> {
        if let Some(ref rules_path) = self.args.rules {
            let ruleset = crate::rules::parse_rule_file(rules_path);
            eprintln!("Applying {} rules...", ruleset.len());
            let mut expanded = Vec::new();
            for w in &words { expanded.extend(crate::rules::apply_rules(w, &ruleset)); }
            expanded.sort(); expanded.dedup(); expanded
        } else { words }
    }

    fn apply_rules_stack(&self, words: Vec<String>) -> Vec<String> {
        if self.args.rules_stack.is_empty() { return words; }
        let mut current = words;
        for stack_path in &self.args.rules_stack {
            let ruleset = crate::rules::parse_rule_file(stack_path);
            eprintln!("Rules-stack: {} rules...", ruleset.len());
            let mut next = Vec::new();
            for w in &current { next.extend(crate::rules::apply_rules(w, &ruleset)); }
            next.sort(); next.dedup();
            current = next;
        }
        current
    }

    fn apply_filters(&self, words: Vec<String>) -> Vec<String> {
        if self.args.filter.is_empty() { return words; }
        let filters = crate::filter::parse_filters(&self.args.filter);
        eprintln!("Applying {} filters...", filters.len());
        let filtered: Vec<_> = words.into_iter().filter(|w| crate::filter::apply_filters(w, &filters)).collect();
        eprintln!("Filtered to {}", filtered.len()); filtered
    }

    /// Set up salt buffer from entries or from --salt CLI flag.
    pub fn setup_salt(&mut self) {
        let salt_bytes = self.args.salt.as_bytes();
        let salt_len = salt_bytes.len().min(16) as u32;
        let mut salt = [0u32; 16];
        for (i, &b) in salt_bytes.iter().rev().enumerate().take(salt_len as usize) {
            salt[i] = b as u32;
        }
        if self.entries.is_empty() { return; }
        if self.entries[0].salt_len > 0 {
            let mut s = self.entries[0].salt;
            let hash_str = &self.entries[0].hex;
            if self.hash_type == HashType::Phpass && hash_str.len() > 4 {
                let count_log2 = crate::hashes::raw_phpass::RawPhpass.count_log2_from_char(hash_str.as_bytes()[3]);
                s[8] = count_log2;
            }
            if self.hash_type == HashType::Drupal7 && hash_str.len() > 4 {
                let count_log2 = crate::hashes::raw_drupal7::RawDrupal7.count_log2_from_char(hash_str.as_bytes()[3]);
                s[8] = count_log2;
            }
            if self.hash_type == HashType::Bcrypt && hash_str.len() > 6 && hash_str.as_bytes()[0] == b'$' {
                if let Ok(cost) = hash_str[4..6].parse::<u32>() {
                    self.entries[0].hash_extra[0] = cost;
                }
            }
            self.salt = s;
            self.salt_len = self.entries[0].salt_len;
        } else {
            self.salt = salt;
            self.salt_len = salt_len;
        }
    }

}
