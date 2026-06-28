mod app;
mod cli;
mod ui;
mod gpu;
mod hash_backend;
mod hashes;
mod pdf_extract;
mod potfile;
mod zip_extract;
mod rules;
mod session;
mod filter;
mod markov;

use clap::Parser;

use hash_backend::{AttackMode, HashType};
use cli::HashEntry;

#[allow(unused_assignments)]
fn main() {
    let args = cli::Args::parse();

    if args.bench {
        app::benchmark::run_benchmark(args.verbose);
        return;
    }

    if let Some(ref extract_type) = args.extract {
        app::extraction::handle_extraction(&args, extract_type);
        return;
    }

    let mut app = app::App::new(args);

    if app.args.show || app.args.left {
        if app.args.left { app.run_left(); }
        if app.args.show { app.run_show(); }
        return;
    }

    app.init_session();

    let is_auto = app.args.hash_type == "auto" || app.args.hash.is_some() || app.args.hashlist.is_some();

    app.collect_entries();

    if app.args.verbose {
        eprintln!("[verbose] Hash type: {} (mode: {})", app.hash_type.name(), app.args.mode);
        if is_auto || app.args.hash.is_some() || app.args.hashlist.is_some() {
            eprintln!("[verbose] Parsed {} entry(ies), salt_len={}", app.entries.len(), app.entries[0].salt_len);
        }
    }

    app.parse_attack_mode();

    if app.args.stdout {
        let filters = filter::parse_filters(&app.args.filter);
        app::stdout::run_stdout(&app.attack_mode, app.num_passwords, &filters);
        return;
    }

    if let AttackMode::Prince { .. } = &app.attack_mode {
        let prince_entries: Vec<(String, Vec<u8>)> = app.entries.iter()
            .map(|e| {
                let s = if e.salt_len > 0 {
                    app::helpers::salt_from_arr(&e.salt, e.salt_len)
                } else { Vec::new() };
                (e.hex.clone(), s)
            }).collect();
        app::cpu_pipeline::run_prince_cpu(&app.attack_mode, app.hash_type, &prince_entries, &mut app.potfile, &app.active_session);
        return;
    }

    if app.args.mode == "single" {
        let single_entries: Vec<(String, Option<String>, Vec<u8>)> = app.entries.iter()
            .map(|e| {
                let s = if e.salt_len > 0 {
                    app::helpers::salt_from_arr(&e.salt, e.salt_len)
                } else { Vec::new() };
                (e.hex.clone(), e.username.clone(), s)
            }).collect();
        let usernames: Vec<String> = if let Some(path) = &app.args.wordlist {
            std::fs::read_to_string(path).unwrap_or_else(|e| {
                eprintln!("Failed to read userlist '{}': {}", path.display(), e);
                std::process::exit(1);
            }).lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
        } else {
            single_entries.iter().filter_map(|e| e.1.clone()).collect()
        };
        if usernames.is_empty() {
            eprintln!("No usernames available for single crack mode. Provide --wordlist <users> or use username:hash format in --hashlist");
            std::process::exit(1);
        }
        app::cpu_pipeline::run_single_crack(app.hash_type, &single_entries, &usernames, &mut app.potfile, &app.active_session);
        return;
    }

    if app.args.mode == "markov" {
        let path = app.args.wordlist.clone().unwrap_or_else(|| {
            eprintln!("Markov mode requires --wordlist <training_file>");
            std::process::exit(1);
        });
        let content = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("Failed to read training file '{}': {}", path.display(), e);
            std::process::exit(1);
        });
        let training: Vec<String> = content.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        if training.is_empty() { eprintln!("Training file is empty"); std::process::exit(1); }
        let model = markov::MarkovModel::train(&training);
        let max_len = 8;
        let max_candidates = 1_000_000;
        eprintln!("Markov: trained on {} passwords, generating up to {} candidates (max len {})", training.len(), max_candidates, max_len);
        let candidates = model.generate(max_len, max_candidates);
        eprintln!("Generated {} candidates", candidates.len());

        let markov_entries: Vec<(String, Vec<u8>)> = app.entries.iter()
            .map(|e| {
                let s = if e.salt_len > 0 { app::helpers::salt_from_arr(&e.salt, e.salt_len) } else { Vec::new() };
                (e.hex.clone(), s)
            }).collect();
        app::cpu_pipeline::run_markov_cpu(app.hash_type, &markov_entries, &candidates, &mut app.potfile, &app.active_session);
        return;
    }

    app.setup_salt();

    if app.entries.is_empty() {
        eprintln!("No hashes to crack");
        return;
    }

    if app.args.demo {
        app.hash_type = HashType::Md5;
        let demo_words: Vec<String> = ui::embedded_test::DEMO_WORDLIST.iter().map(|s| s.to_string()).collect();
        app.attack_mode = AttackMode::Wordlist { words: demo_words.clone() };
        app.num_passwords = demo_words.len() as u32;
        let demo_hexes = ui::embedded_test::build_demo_hashset(ui::embedded_test::DEMO_HASHES_MD5);
        app.entries = demo_hexes.iter().map(|h| {
            let parsed = app.hash_type.module().parse_hash_string(h).expect("demo hash is valid");
            HashEntry {
                hex: h.clone(),
                hash: parsed.hash_words,
                hash_extra: parsed.extra_words,
                salt: [0u32; 16],
                salt_len: 0,
                username: None,
            }
        }).collect();
        app.salt = [0u32; 16];
        app.salt_len = 0;
    }

    let is_tui = !app.args.quiet && !app.args.json;
    if is_tui {
        ui::run_tui(
            app.hash_type,
            app.attack_mode.clone(),
            app.entries.clone(),
            app.salt,
            app.salt_len,
            app.num_passwords,
            std::mem::take(&mut app.potfile),
            std::mem::take(&mut app.active_session),
            app.args.clone(),
            app.hash_type.name(),
            app.entries[0].clone(),
            app.args.hex,
        );
    } else {
        app::attack::run_gpu_attack(
            app.hash_type,
            app.attack_mode.clone(),
            &app.entries,
            app.salt,
            app.salt_len,
            app.num_passwords,
            &mut app.potfile,
            &mut app.active_session,
            app.args.session.clone(),
            &app.args,
            app.hash_type.name(),
            &app.entries[0],
            app.args.quiet,
            app.args.json,
            app.args.verbose,
            &app.args.mode,
            app.args.hex,
        );
    }
}
