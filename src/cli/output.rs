use owo_colors::{OwoColorize, Rgb};

// ── JSON output events ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum OutputEvent {
    Found { hash: String, password: String, username: Option<String> },
    Progress { pct: f64, rate: f64, elapsed: f64, remaining: f64 },
    Start { mode: String, hash_type: String, num_hashes: usize, keyspace: u64 },
    Done { found: usize, elapsed: f64 },
}

pub fn emit_json(event: &OutputEvent) {
    match event {
        OutputEvent::Found { hash, password, username } => {
            let user = username.as_deref().unwrap_or("");
            println!("{{\"event\":\"found\",\"hash\":{},\"password\":{},\"username\":{}}}",
                serde_json::to_string(hash).unwrap_or_default(),
                serde_json::to_string(password).unwrap_or_default(),
                serde_json::to_string(user).unwrap_or_default());
        }
        OutputEvent::Start { mode, hash_type, num_hashes, keyspace } => {
            println!("{{\"event\":\"start\",\"mode\":{},\"hash_type\":{},\"num_hashes\":{},\"keyspace\":{}}}",
                serde_json::to_string(mode).unwrap_or_default(),
                serde_json::to_string(hash_type).unwrap_or_default(),
                num_hashes, keyspace);
        }
        OutputEvent::Done { found, elapsed } => {
            println!("{{\"event\":\"done\",\"found\":{},\"elapsed_secs\":{:.3}}}", found, elapsed);
        }
        OutputEvent::Progress { pct, rate, elapsed, remaining } => {
            println!("{{\"event\":\"progress\",\"pct\":{:.3},\"rate_hs\":{:.0},\"elapsed_secs\":{:.3},\"remaining_secs\":{:.3}}}",
                pct, rate, elapsed, remaining);
        }
    }
}

// ── Found entry display ─────────────────────────────────────────────

pub fn print_found_entry(hash: &str, password: &str, hex_mode: bool) {
    let display_pwd = if hex_mode { hex::encode(password.as_bytes()) } else { password.to_string() };
    let green = Rgb(0, 255, 100);
    let white = Rgb(255, 255, 255);
    println!("  {} {:<64} : {}",
        "✅".color(green),
        hash.color(white),
        display_pwd.color(green).bold());
}

// ── Summary table ──────────────────────────────────────────────────

pub fn print_summary(results: &[(String, String, bool)], total_time: std::time::Duration, total_hashes: usize) {
    let green = Rgb(0, 255, 100);
    let red = Rgb(255, 50, 50);
    let cyan = Rgb(0, 200, 255);
    let yellow = Rgb(255, 200, 0);

    let found_count = results.iter().filter(|r| r.2).count();

    println!();
    println!("{}", "  ┌──────────────────────────────────────┐".color(cyan));
    println!("{}", "  │           Results Summary             │".color(cyan));
    println!("{}", "  ├──────────────────────────────────────┤".color(cyan));

    if results.len() <= 8 {
        for (hash, password, found) in results {
            let status = if *found { "✓".color(green) } else { "✗".color(red) };
            let display = if password.len() > 30 {
                format!("{}...", &password[..27])
            } else {
                password.clone()
            };
            println!("  │ {} {} │", status, format!("{} → {}", hash, display).color(yellow));
        }
        if !results.is_empty() {
            println!("{}", "  ├──────────────────────────────────────┤".color(cyan));
        }
    }

    let secs = total_time.as_secs_f64();
    let time_str = if secs > 60.0 {
        format!("{:.0}m {:.0}s", secs / 60.0, secs % 60.0)
    } else {
        format!("{:.1}s", secs)
    };
    println!("  │ {} {}  │", "Time:".color(cyan), format!("{:>23}", time_str).color(green));
    println!("  │ {} {}  │", "Found:".color(cyan), format!("{:>21}", found_count).color(green));
    if total_hashes > 0 {
        println!("  │ {} {}  │", "Total:".color(cyan), format!("{:>21}", total_hashes).color(green));
    }
    println!("{}", "  └──────────────────────────────────────┘".color(cyan));
    println!();
}

// ── Benchmark display ───────────────────────────────────────────────

pub fn print_bench_header(bench_duration: std::time::Duration) {
    let cyan = Rgb(0, 200, 255);
    let green = Rgb(0, 255, 100);
    let yellow = Rgb(255, 200, 0);

    println!("{}", "  ╔════════════════════════════════════════════╗".color(cyan));
    println!("  ║   {}               ║",
        "HashCracker — GPU Benchmark".bold().color(green));
    println!("{}", "  ╠════════════════════════════════════════════╣".color(cyan));
    println!("  ║  {}      {}       ║",
        "Password length: 3".color(yellow),
        "Keyspace: 238,328".color(yellow));
    println!("  ║  {} {} s          ║",
        "Sample time:".color(yellow),
        format!("{}", bench_duration.as_secs()).color(yellow));
    println!("{}", "  ╚════════════════════════════════════════════╝".color(cyan));
}

pub fn print_bench_row(name: &str, hps: f64) {
    let green = Rgb(0, 255, 100);
    let rate_str = if hps >= 1_000_000.0 {
        format!("{:.2} MH/s", hps / 1_000_000.0)
    } else if hps >= 1_000.0 {
        format!("{:.2} KH/s", hps / 1_000.0)
    } else {
        format!("{:.0} H/s", hps)
    };
    println!("  ║  {:<8} {:>20} ║", name.color(green), rate_str.color(green));
}

pub fn print_bench_footer(results: &[(&str, f64)]) {
    let cyan = Rgb(0, 200, 255);
    let green = Rgb(0, 255, 100);
    let yellow = Rgb(255, 200, 0);

    println!("{}", "  ╠════════════════════════════════════════════╣".color(cyan));
    for (name, hps) in results {
        let rate_str = if *hps >= 1_000_000.0 {
            format!("{:.2} MH/s", hps / 1_000_000.0)
        } else if *hps >= 1_000.0 {
            format!("{:.2} KH/s", hps / 1_000.0)
        } else {
            format!("{:.0} H/s", hps)
        };
        println!("  ║  {:<8} {:>20} ║", name.color(yellow), rate_str.color(green));
    }
    println!("{}", "  ╚════════════════════════════════════════════╝".color(cyan));
}


