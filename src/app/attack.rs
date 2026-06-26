use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use indicatif::{ProgressBar, ProgressStyle, HumanCount};

use crate::hash_backend::{AttackMode, HashType, full_hash_slice};
use crate::hashes::AttackModeType;
use crate::cli;

/// Run the main GPU cracking loop: dispatch chunks, poll GPU, verify candidates.
#[allow(clippy::too_many_arguments)]
pub fn run_gpu_attack(
    hash_type: HashType,
    attack_mode: AttackMode,
    entries: &[cli::HashEntry],
    salt: [u32; 16],
    salt_len: u32,
    num_passwords: u32,
    potfile: &mut crate::potfile::Potfile,
    active_session: &mut Option<crate::session::Session>,
    session_name: Option<String>,
    args: &crate::cli::Args,
    hash_type_name: &str,
    first_entry: &crate::cli::HashEntry,
    quiet: bool,
    json: bool,
    verbose: bool,
    mode: &str,
    hex_mode: bool,
) {
    // --- CPU wordlist fallback for CPU-only types
    let is_cpu_only = hash_type.module().shader_source(&AttackModeType::Wordlist).is_empty();
    if is_cpu_only && matches!(&attack_mode, AttackMode::Wordlist { .. }) {
        if let AttackMode::Wordlist { words } = &attack_mode {
            let module = hash_type.module();
            for entry in entries {
                let parsed = match module.parse_hash_string(&entry.hex) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let dw = module.digest_words() as usize;
                let full = full_hash_slice(&parsed, dw);
                let hash_slice = &full[..dw];
                let salt: &[u8] = &parsed.salt;
                for w in words {
                    if module.cpu_verify(w, salt, hash_slice) {
                        println!("  ✅ {:<64} : {}", entry.hex, w);
                        potfile.record_crack(&entry.hex, w);
                    }
                }
            }
            if let Err(e) = potfile.save() {
                eprintln!("Warning: failed to save potfile: {}", e);
            }
            return;
        }
    }

    // --- Main cracking loop
    let num_hashes = entries.len();
    let is_incremental = mode == "incremental";

    let uncracked: Vec<&cli::HashEntry> = entries.iter()
        .filter(|e| !potfile.is_cracked(&e.hex))
        .collect();

    if uncracked.is_empty() && num_hashes > 0 {
        eprintln!("All {} hash(es) already in potfile", num_hashes);
        if !quiet && !json {
            eprintln!("Use --potfile <path> to use a different potfile.");
        }
        return;
    }

    let effective_count = uncracked.len();
    let use_pb = !quiet && !json;
    let pb = if use_pb {
        let p = ProgressBar::new(0);
        p.set_style(
            ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                .unwrap()
                .progress_chars("━╸")
        );
        p
    } else {
        ProgressBar::hidden()
    };

    if json {
        cli::emit_json(&cli::OutputEvent::Start {
            mode: mode.to_string(),
            hash_type: hash_type.name().to_string(),
            num_hashes: effective_count,
            keyspace: num_passwords as u64,
        });
    }

    let first = uncracked[0];
    let mode_type = crate::hashes::attack_mode_type(&attack_mode);
    if hash_type.module().shader_source(&mode_type).is_empty() && !matches!(&attack_mode, AttackMode::Wordlist { .. }) {
        eprintln!("Error: {} is CPU-only and only supports wordlist mode. Use --mode wordlist --wordlist <file>", hash_type.name());
        std::process::exit(1);
    }
    let mut gpu = pollster::block_on(crate::gpu::GpuCracker::new(
        &hash_type, attack_mode, first.hash, first.hash_extra, salt, salt_len,
    ));

    if verbose {
        let np = gpu.num_passwords();
        eprintln!("[verbose] GPU dispatch: workgroup=128, num_passwords={np}, chunk_size=1000000");
    }

    let module = hash_type.module();
    let mut remaining: Vec<&cli::HashEntry> = uncracked.iter().copied().collect();

    let write_remaining = |gpu: &mut crate::gpu::GpuCracker, rem: &[&cli::HashEntry]| {
        let entries: Vec<crate::gpu::TargetEntry> = rem.iter().map(|e| {
            crate::gpu::TargetEntry { hash: e.hash, hash_extra: e.hash_extra }
        }).collect();
        gpu.write_targets(&entries);
    };
    write_remaining(&mut gpu, &remaining);

    // Session state tracking
    let mut session_state_opt = None;
    if let Some(ref mut sess) = active_session {
        if sess.exists() {
            if let Ok(state) = sess.load() {
                session_state_opt = Some(state);
            }
        }
    }

    let mut total_found: Vec<(usize, String, String)> = Vec::new();
    let start_time = Instant::now();

    let abort_flag = Arc::new(AtomicBool::new(false));
    let abort_flag_clone = abort_flag.clone();
    ctrlc::set_handler(move || {
        abort_flag_clone.store(true, Ordering::SeqCst);
        eprintln!("\n⌛ Aborting after current chunk...");
    }).ok();

    let mut current_len: u32 = 1;
    let mut current_space = num_passwords;
    const CHUNK_SIZE: u32 = 1_000_000;
    let mut chunk_start = 0u32;

    if let Some(ref state) = session_state_opt {
        chunk_start = state.progress as u32;
        current_len = state.password_len;
        current_space = state.keyspace as u32;
        for (h, p) in &state.cracked_hashes {
            potfile.record_crack(h, p);
        }
        for (h, _) in &state.cracked_hashes {
            if let Some(pos) = remaining.iter().position(|e| e.hex == *h) {
                remaining.remove(pos);
            }
        }
        if !state.cracked_hashes.is_empty() {
            write_remaining(&mut gpu, &remaining);
        }
        if use_pb && chunk_start > 0 {
            pb.set_position(chunk_start as u64);
        }
    }

    if use_pb {
        pb.reset();
        pb.set_length(current_space as u64);
        if is_incremental {
            pb.set_message(format!("[{} targets] len{}/4", remaining.len(), current_len));
        } else {
            pb.set_message(format!("[{} targets]", remaining.len()));
        }
    }

    #[allow(unused_assignments)]
    let mut last_progress = 0u32;
    let mut last_rate_update = Instant::now();
    let mut current_rate = 0.0;
    let mut last_json_progress = Instant::now();
    let mut poll_interval_us = 1000u64;

    'chunks: while chunk_start < current_space && !remaining.is_empty() {
        let chunk_end = (chunk_start + CHUNK_SIZE).min(current_space);
        let mut chunk_size = chunk_end - chunk_start;

        gpu.redispatch_range(chunk_start, chunk_end);
        if verbose {
            eprintln!("[verbose] Dispatched chunk {}-{} (size {}) of {}",
                chunk_start, chunk_end, chunk_end - chunk_start, current_space);
        }

        let progress_base = chunk_start;
        last_progress = 0;

        'poll: loop {
            gpu.poll();
            if let Some(data) = gpu.try_readback() {
                if data.progress > chunk_size && data.found_flag == 0 {
                    std::thread::sleep(std::time::Duration::from_micros(100));
                    continue;
                }
                let now = Instant::now();
                let dt = now.duration_since(last_rate_update).as_secs_f64().max(0.001);
                let delta = data.progress.saturating_sub(last_progress) as f64;
                if delta > 0.0 {
                    let delta_rate = delta / dt;
                    if current_rate == 0.0 {
                        current_rate = delta_rate;
                    } else {
                        current_rate = current_rate * 0.7 + delta_rate * 0.3;
                    }
                    last_progress = data.progress;
                    last_rate_update = now;

                    poll_interval_us = if current_rate > 1_000_000.0 { 1_000 }
                        else if current_rate > 1_000.0 { 10_000 }
                        else { 100_000 };
                }
                if use_pb {
                    pb.set_position((progress_base + data.progress) as u64);
                    pb.set_message(format!(
                        "[{} targets] {}/s {:.0} H/s",
                        remaining.len(),
                        HumanCount(current_rate as u64),
                        current_rate,
                    ));
                }
                if json && now.duration_since(last_json_progress).as_secs_f64() > 0.5 {
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let total = current_space as f64;
                    let progress = (progress_base + data.progress) as f64;
                    let pct = if total > 0.0 { (progress / total).min(1.0) } else { 0.0 };
                    let remaining_secs = if current_rate > 0.0 { ((total - progress) / current_rate).max(0.0) } else { 0.0 };
                    cli::emit_json(&cli::OutputEvent::Progress { pct, rate: current_rate, elapsed, remaining: remaining_secs });
                    last_json_progress = now;
                }

                if data.found_flag != 0 {
                    let pwd = gpu.decode_found_password(&data).unwrap_or_default();
                    let cracked: Vec<usize> = remaining.iter().enumerate().filter_map(|(i, e)| {
                        let parsed = module.parse_hash_string(&e.hex).ok()?;
                        let dw = module.digest_words() as usize;
                        let full = full_hash_slice(&parsed, dw);
                        let hash_slice = &full[..dw];
                        let salt: &[u8] = if !parsed.salt.is_empty() { &parsed.salt } else { &[] };
                        if module.cpu_verify(&pwd, salt, hash_slice) {
                            Some(i)
                        } else {
                            None
                        }
                    }).rev().collect();

                    for &ci in &cracked {
                        let e = remaining[ci];
                        if json {
                            cli::emit_json(&cli::OutputEvent::Found { hash: e.hex.clone(), password: pwd.clone(), username: e.username.clone() });
                        } else {
                            crate::ui::print_found_entry(&e.hex, &pwd, hex_mode);
                        }
                        potfile.record_crack(&e.hex, &pwd);
                        total_found.push((ci, e.hex.clone(), pwd.clone()));
                    }

                    for &ci in &cracked { remaining.remove(ci); }

                    if remaining.is_empty() {
                        save_session_progress(active_session, &session_name, args, hash_type_name, first_entry, &total_found, current_len, current_space, chunk_start);
                        break 'chunks;
                    }

                    let match_idx = match mode {
                        "wordlist" | "hybrid" => data.found_password[0],
                        _ => data.progress,
                    };
                    chunk_start = progress_base + match_idx + 1;
                    if chunk_start >= chunk_end { break 'poll; }
                    chunk_size = chunk_end - chunk_start;
                    write_remaining(&mut gpu, &remaining);
                    gpu.redispatch_range(chunk_start, chunk_end);
                    last_progress = 0;
                    continue 'poll;
                }

                if data.progress >= chunk_size { break 'poll; }
            }
            std::thread::sleep(std::time::Duration::from_micros(poll_interval_us));
        }

        if abort_flag.load(Ordering::SeqCst) {
            save_session_progress(active_session, &session_name, args, hash_type_name, first_entry, &total_found, current_len, current_space, chunk_start);
            eprintln!("Aborted at chunk (progress {:.1}%)",
                (chunk_start as f64 / current_space as f64) * 100.0);
            break;
        }

        if is_incremental && current_len < 4 {
            current_len += 1;
            current_space = 62u32.pow(current_len);
            chunk_start = 0;
            gpu.reconfig_len(current_len, current_space);
            write_remaining(&mut gpu, &remaining);
            save_session_progress(active_session, &session_name, args, hash_type_name, first_entry, &total_found, current_len, current_space, chunk_start);
            if use_pb {
                pb.set_length(current_space as u64);
                pb.set_message(format!("[{} targets] extending to len {}", remaining.len(), current_len));
            }
            continue;
        }

        save_session_progress(active_session, &session_name, args, hash_type_name, first_entry, &total_found, current_len, current_space, chunk_start);
        chunk_start = chunk_end;
    }

    if use_pb { pb.finish_and_clear(); }

    if !total_found.is_empty() {
        if let Err(e) = potfile.save() {
            eprintln!("Warning: failed to save potfile: {}", e);
        }
    }

    let elapsed = start_time.elapsed().as_secs_f64();

    if json {
        cli::emit_json(&cli::OutputEvent::Done { found: total_found.len(), elapsed });
    }

    if !json && !quiet {
        let results: Vec<(String, String, bool)> = if total_found.is_empty() {
            entries.iter().map(|e| (e.hex.clone(), String::new(), false)).collect()
        } else {
            let mut res = Vec::new();
            for e in entries {
                let found = total_found.iter().find(|(_, h, _)| h == &e.hex);
                if let Some((_, _, pwd)) = found {
                    let display_pwd = if hex_mode { hex::encode(pwd.as_bytes()) } else { pwd.clone() };
                    res.push((e.hex.clone(), display_pwd, true));
                } else {
                    res.push((e.hex.clone(), String::new(), false));
                }
            }
            res
        };
        crate::ui::print_summary(&results, start_time.elapsed(), effective_count);
    }

    if let Some(ref mut sess) = active_session {
        if remaining.is_empty() {
            let _ = sess.delete();
        }
    }
}

/// Save session state to disk.
#[allow(clippy::too_many_arguments)]
fn save_session_progress(
    active_session: &mut Option<crate::session::Session>,
    _session_name: &Option<String>,
    args: &crate::cli::Args,
    hash_type_name: &str,
    entry: &crate::cli::HashEntry,
    total_found: &[(usize, String, String)],
    password_len: u32,
    keyspace: u32,
    progress: u32,
) {
    let sess = match active_session {
        Some(s) => s,
        None => return,
    };
    crate::app::helpers::save_session_state(
        sess,
        hash_type_name,
        args,
        &entry.hex,
        &entry.salt,
        entry.salt_len,
        password_len,
        keyspace,
        progress,
        total_found,
    );
}
