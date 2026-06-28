use crate::hash_backend::{HashType, AttackMode, full_hash_slice};
use crate::potfile::Potfile;

pub fn run_prince_cpu(
    attack_mode: &AttackMode,
    hash_type: HashType,
    entries: &[(String, Vec<u8>)],
    potfile: &mut Potfile,
    active_session: &Option<crate::session::Session>,
) {
    let AttackMode::Prince { dict } = attack_mode else { return };
    eprintln!("Prince mode: {} words in dictionary", dict.len());

    let module = hash_type.module();
    let mut total_found: Vec<(usize, String, String)> = Vec::new();
    let n = dict.len();
    let dict = dict.clone();

    let mut sorted: Vec<&String> = dict.iter().collect();
    sorted.sort_by(|a, b| a.len().cmp(&b.len()).then(a.cmp(b)));
    let sorted: Vec<String> = sorted.into_iter().cloned().collect();

    for (idx, entry) in entries.iter().enumerate() {
        let parsed = match module.parse_hash_string(&entry.0) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Warning: failed to parse hash '{}': {}", entry.0, e);
                continue;
            }
        };

        let dw = module.digest_words() as usize;
        let full = full_hash_slice(&parsed, dw);
        let hash_slice = &full[..dw];
        let salt: &[u8] = if !parsed.salt.is_empty() {
            &parsed.salt
        } else {
            &entry.1
        };
        let mut found = false;

        let mut report = |pwd: &str| {
            println!("  ✅ {:<64} : {}", entry.0, pwd);
            potfile.record_crack(&entry.0, pwd);
            total_found.push((idx, entry.0.clone(), pwd.to_string()));
        };

        for w in &sorted {
            if module.cpu_verify(w, &salt, hash_slice) {
                report(w);
                found = true;
                break;
            }
        }
        if found { continue; }

        let pairs = n as u64 * n as u64;
        if pairs <= 10_000_000 {
            eprintln!("  Trying {} word pairs...", pairs);
            for a in &sorted {
                for b in &sorted {
                    let mut chain = a.clone();
                    chain.push_str(b);
                    if module.cpu_verify(&chain, &salt, hash_slice) {
                        report(&chain);
                        found = true;
                        break;
                    }
                }
                if found { break; }
            }
        }
        if found { continue; }

        let triples = n as u64 * n as u64 * n as u64;
        if triples <= 10_000_000 {
            eprintln!("  Trying {} word triples...", triples);
            for a in &sorted {
                for b in &sorted {
                    for c in &sorted {
                        let mut chain = a.clone();
                        chain.push_str(b);
                        chain.push_str(c);
                        if module.cpu_verify(&chain, &salt, hash_slice) {
                            report(&chain);
                            found = true;
                            break;
                        }
                    }
                    if found { break; }
                }
                if found { break; }
            }
        }

        if !found {
            eprintln!("  ❌ Not found for hash {}", entry.0);
        }
    }

    if !total_found.is_empty() {
        if let Err(e) = potfile.save() {
            eprintln!("Warning: failed to save potfile: {}", e);
        }
    }

    if let Some(ref sess) = active_session {
        let _ = sess.delete();
    }
}

fn single_crack_candidates(username: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    let lower = username.to_lowercase();
    let upper = username.to_uppercase();
    let rev: String = username.chars().rev().collect();
    let cap = if let Some(c) = username.chars().next() {
        let mut s = c.to_uppercase().collect::<String>();
        s.extend(username.chars().skip(1).map(|c| c.to_lowercase().next().unwrap_or(c)));
        s
    } else {
        username.to_string()
    };

    candidates.push(username.to_string());
    if lower != *username { candidates.push(lower.clone()); }
    if upper != *username { candidates.push(upper.clone()); }
    if cap != *username && cap != lower && cap != upper { candidates.push(cap.clone()); }
    candidates.push(rev);
    candidates.push(format!("{}{}", username, username));

    for suffix in &["!", "123", "123!", "1", "!", "@", "#", "2024", "2025", "2026"] {
        candidates.push(format!("{}{}", username, suffix));
        if lower != *username { candidates.push(format!("{}{}", lower, suffix)); }
        if cap != *username { candidates.push(format!("{}{}", cap, suffix)); }
    }
    for prefix in &["!", "@", "#"] {
        candidates.push(format!("{}{}", prefix, username));
    }

    candidates
}

pub fn run_single_crack(
    hash_type: HashType,
    entries: &[(String, Option<String>, Vec<u8>)],
    usernames: &[String],
    potfile: &mut Potfile,
    active_session: &Option<crate::session::Session>,
) {
    let module = hash_type.module();
    eprintln!("Single crack mode: {} username(s), {} target hash(es)", usernames.len(), entries.len());
    let mut total_found: Vec<(usize, String, String)> = Vec::new();

    for (idx, entry) in entries.iter().enumerate() {
        let parsed = match module.parse_hash_string(&entry.0) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Warning: failed to parse hash '{}': {}", entry.0, e);
                continue;
            }
        };
        let dw = module.digest_words() as usize;
        let full = full_hash_slice(&parsed, dw);
        let hash_slice = &full[..dw];
        let salt: &[u8] = if !parsed.salt.is_empty() { &parsed.salt } else { &entry.2 };

        for user in usernames {
            let candidates = single_crack_candidates(user);
            for candidate in &candidates {
                if module.cpu_verify(candidate, salt, hash_slice) {
                    println!("  ✅ {:<64} : {}", entry.0, candidate);
                    potfile.record_crack(&entry.0, candidate);
                    total_found.push((idx, entry.0.clone(), candidate.to_string()));
                    return;
                }
            }
        }
        eprintln!("  ❌ Not found for hash {}", entry.0);
    }

    if !total_found.is_empty() {
        if let Err(e) = potfile.save() {
            eprintln!("Warning: failed to save potfile: {}", e);
        }
    }
    if let Some(ref sess) = active_session {
        let _ = sess.delete();
    }
}

pub fn run_markov_cpu(
    hash_type: HashType,
    entries: &[(String, Vec<u8>)],
    candidates: &[String],
    potfile: &mut Potfile,
    active_session: &Option<crate::session::Session>,
) {
    let module = hash_type.module();
    eprintln!("Markov CPU: verifying {} candidates against {} hash(es)", candidates.len(), entries.len());
    let mut total_found: Vec<(usize, String, String)> = Vec::new();

    for (idx, entry) in entries.iter().enumerate() {
        let parsed = match module.parse_hash_string(&entry.0) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Warning: failed to parse hash '{}': {}", entry.0, e);
                continue;
            }
        };
        let dw = module.digest_words() as usize;
        let full = full_hash_slice(&parsed, dw);
        let hash_slice = &full[..dw];
        let salt: &[u8] = if !parsed.salt.is_empty() { &parsed.salt } else { &entry.1 };

        for candidate in candidates {
            if module.cpu_verify(candidate, salt, hash_slice) {
                println!("  ✅ {:<64} : {}", entry.0, candidate);
                potfile.record_crack(&entry.0, candidate);
                total_found.push((idx, entry.0.clone(), candidate.to_string()));
                break;
            }
        }

        if total_found.iter().any(|(i, _, _)| *i == idx) {
            continue;
        }
        eprintln!("  ❌ Not found for hash {}", entry.0);
    }

    if !total_found.is_empty() {
        if let Err(e) = potfile.save() {
            eprintln!("Warning: failed to save potfile: {}", e);
        }
    }
    if let Some(ref sess) = active_session {
        let _ = sess.delete();
    }
}
