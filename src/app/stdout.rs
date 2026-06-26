use std::io::{BufWriter, Write, stdout};
use crate::hash_backend::AttackMode;
use crate::filter;

pub fn run_stdout(attack_mode: &AttackMode, _num_passwords: u32, filters: &[filter::Filter]) {
    let out = stdout();
    let mut writer = BufWriter::new(out.lock());
    let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let has_filters = !filters.is_empty();

    match attack_mode {
        AttackMode::BruteForce { password_len } => {
            let sz = 62u32;
            let total = sz.pow(*password_len);
            for idx in 0..total {
                let mut idx = idx;
                let mut s = vec![0u8; *password_len as usize];
                for i in 0..*password_len as usize {
                    let d = (idx % sz) as usize;
                    idx /= sz;
                    s[i] = charset[d];
                }
                let candidate = std::str::from_utf8(&s).unwrap_or("");
                if has_filters && !filter::apply_filters(candidate, filters) {
                    continue;
                }
                writer.write_all(&s).ok();
                writer.write_all(b"\n").ok();
            }
        }
        AttackMode::Mask { mask, keyspace, password_len } => {
            for idx in 0..(*keyspace as u32) {
                let s = AttackMode::index_to_mask_str(idx, mask, *password_len);
                if has_filters && !filter::apply_filters(&s, filters) {
                    continue;
                }
                writer.write_all(s.as_bytes()).ok();
                writer.write_all(b"\n").ok();
            }
        }
        AttackMode::Wordlist { words } => {
            for w in words {
                if has_filters && !filter::apply_filters(w, filters) {
                    continue;
                }
                writer.write_all(w.as_bytes()).ok();
                writer.write_all(b"\n").ok();
            }
        }
        AttackMode::Hybrid { words, mask, keyspace: _, password_len, suffix } => {
            let mask_ks = AttackMode::mask_keyspace(mask, *password_len);
            if *suffix {
                for w in words {
                    for mi in 0..mask_ks {
                        let m = AttackMode::index_to_mask_str(mi, mask, *password_len);
                        let candidate = format!("{}{}", w, m);
                        if has_filters && !filter::apply_filters(&candidate, filters) {
                            continue;
                        }
                        writer.write_all(candidate.as_bytes()).ok();
                        writer.write_all(b"\n").ok();
                    }
                }
            } else {
                for w in words {
                    for mi in 0..mask_ks {
                        let m = AttackMode::index_to_mask_str(mi, mask, *password_len);
                        let candidate = format!("{}{}", m, w);
                        if has_filters && !filter::apply_filters(&candidate, filters) {
                            continue;
                        }
                        writer.write_all(candidate.as_bytes()).ok();
                        writer.write_all(b"\n").ok();
                    }
                }
            }
        }
        AttackMode::Prince { dict } => {
            let mut sorted: Vec<&String> = dict.iter().collect();
            sorted.sort_by(|a, b| a.len().cmp(&b.len()).then(a.cmp(b)));
            for w in sorted {
                if has_filters && !filter::apply_filters(w, filters) {
                    continue;
                }
                writer.write_all(w.as_bytes()).ok();
                writer.write_all(b"\n").ok();
            }
        }
    }
    writer.flush().ok();
}
