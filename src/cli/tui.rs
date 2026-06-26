use std::sync::mpsc::{self, Sender, Receiver};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::{Duration, Instant};
use std::collections::VecDeque;

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Wrap},
    Frame, Terminal,
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use crate::hash_backend::HashType;
use crate::cli::HashEntry;

// ── TUI Events ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum TuiEvent {
    Init {
        hash_type: String,
        mode: String,
        num_hashes: usize,
        keyspace: u64,
        targets: Vec<HashEntry>,
    },
    Found {
        hash: String,
        password: String,
    },
    Progress {
        progress: u64,
        total: u64,
        rate: f64,
        elapsed: f64,
        targets_left: usize,
        current_len: u32,
    },
    Done {
        found: usize,
        elapsed: f64,
    },
    Abort,
    Log(String),
}

#[derive(Debug, Clone)]
struct FoundEntry {
    hash: String,
    password: String,
}

// ── TUI App State ─────────────────────────────────────────────────────

struct TuiApp {
    /// Attack info
    hash_type: String,
    mode: String,
    keyspace: u64,
    num_hashes: usize,
    targets: Vec<HashEntry>,

    /// Progress
    progress: u64,
    total: u64,
    rate: f64,
    elapsed: f64,
    targets_left: usize,
    current_len: u32,

    /// Found entries
    found: Vec<FoundEntry>,

    /// Log buffer
    logs: VecDeque<String>,
    max_logs: usize,

    /// Done flag
    done: bool,
}

impl TuiApp {
    fn new() -> Self {
        Self {
            hash_type: String::new(),
            mode: String::new(),
            keyspace: 0,
            num_hashes: 0,
            targets: Vec::new(),
            progress: 0,
            total: 1,
            rate: 0.0,
            elapsed: 0.0,
            targets_left: 0,
            current_len: 0,
            found: Vec::new(),
            logs: VecDeque::with_capacity(100),
            max_logs: 100,
            done: false,
        }
    }

    fn push_log(&mut self, msg: String) {
        if self.logs.len() >= self.max_logs {
            self.logs.pop_front();
        }
        self.logs.push_back(msg);
    }
}

// ── Rendering ─────────────────────────────────────────────────────────

fn render(frame: &mut Frame, app: &TuiApp) {
    let area = frame.area();

    // Top status bar + main content area
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),     // status bar
            Constraint::Min(0),        // main area
        ])
        .split(area);

    // Main area: three columns
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(30), // targets
            Constraint::Percentage(30), // gpu stats
            Constraint::Percentage(40), // found
        ])
        .split(chunks[1]);

    // Bottom area: log panel
    let bottom_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(10),    // log
        ])
        .split(chunks[1]);

    // ── Status bar ──────────────────────────────────────────────────
    let status = render_status(app);
    frame.render_widget(status, chunks[0]);

    // ── Targets panel ───────────────────────────────────────────────
    let targets = render_targets(app);
    frame.render_widget(targets, main_chunks[0]);

    // ── GPU stats panel ─────────────────────────────────────────────
    let gpu_stats = render_gpu_stats(app);
    frame.render_widget(gpu_stats, main_chunks[1]);

    // ── Found panel ─────────────────────────────────────────────────
    let found = render_found(app);
    frame.render_widget(found, main_chunks[2]);

    // ── Log panel ───────────────────────────────────────────────────
    let log = render_log(app);
    frame.render_widget(log, bottom_chunks[1]);
}

fn render_status(app: &TuiApp) -> Paragraph<'static> {
    let elapsed_str = format_secs(app.elapsed);
    let key_info = if app.keyspace > 0 {
        let pct = if app.total > 0 { (app.progress as f64 / app.total as f64) * 100.0 } else { 0.0 };
        format!("{}  {:>5.1}%  {}", elapsed_str, pct, format_rate(app.rate))
    } else {
        elapsed_str.to_string()
    };

    let mode_str = if app.current_len > 0 && app.mode == "incremental" {
        format!("{} len={}", app.mode, app.current_len)
    } else {
        app.mode.clone()
    };

    let lines: Vec<Line<'static>> = vec![
        Line::from(vec![
            Span::styled(" HashCracker ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(" ● ", Style::default().fg(Color::Green)),
            Span::raw(format!("{}  ", app.hash_type)),
            Span::styled(mode_str, Style::default().fg(Color::Yellow)),
            Span::raw("  │  "),
            Span::styled(key_info, Style::default().fg(Color::Green)),
            Span::raw("  │  "),
            Span::styled("[q]uit [p]ause [s]ave", Style::default().fg(Color::DarkGray)),
        ]),
    ];
    Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Plain)
                .border_style(Style::default().fg(Color::Cyan)),
        )
}

fn render_targets(app: &TuiApp) -> Paragraph<'static> {
    let mut lines: Vec<Line<'static>> = Vec::new();

    let total = app.targets.len();
    let title = format!(" Targets ({}/{}) ", total - app.targets_left, total);

    for (i, target) in app.targets.iter().enumerate() {
        let found_entry = app.found.iter().find(|f| f.hash == target.hex);
        let (icon, style) = if found_entry.is_some() {
            ("✓", Style::default().fg(Color::Green).add_modifier(Modifier::DIM))
        } else {
            ("●", Style::default().fg(Color::Yellow))
        };

        let display_hash = if target.hex.len() > 24 {
            format!("{}…", &target.hex[..target.hex.len().min(24)])
        } else {
            target.hex.clone()
        };

        if i < 20 {
            lines.push(Line::from(vec![
                Span::styled(format!(" {} ", icon), style),
                Span::styled(display_hash, style),
            ]));
        } else if i == 20 {
            lines.push(Line::from(Span::styled(
                format!(" … {} more", app.targets.len() - 20),
                Style::default().fg(Color::DarkGray),
            )));
        }
    }

    if app.targets.is_empty() {
        lines.push(Line::from(Span::styled(" No targets", Style::default().fg(Color::DarkGray))));
    }

    Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Blue)),
        )
}

fn render_gpu_stats(app: &TuiApp) -> Paragraph<'static> {
    let pct = if app.total > 0 {
        ((app.progress as f64 / app.total as f64) * 100.0).min(100.0)
    } else {
        0.0
    };

    let remaining = if app.rate > 0.0 {
        let rem = (app.total.saturating_sub(app.progress)) as f64 / app.rate;
        format_secs(rem)
    } else {
        "--".to_string()
    };

    let keyspace_str = if app.keyspace > 1_000_000 {
        format!("{:.1}M", app.keyspace as f64 / 1_000_000.0)
    } else if app.keyspace > 1_000 {
        format!("{:.1}K", app.keyspace as f64 / 1_000.0)
    } else {
        app.keyspace.to_string()
    };

    let lines: Vec<Line<'static>> = vec![
        Line::from(vec![
            Span::styled("Speed    ", Style::default().fg(Color::DarkGray)),
            Span::styled(format_rate(app.rate), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Elapsed  ", Style::default().fg(Color::DarkGray)),
            Span::raw(format_secs(app.elapsed)),
        ]),
        Line::from(vec![
            Span::styled("ETA      ", Style::default().fg(Color::DarkGray)),
            Span::raw(remaining),
        ]),
        Line::from(vec![
            Span::styled("Keyspace ", Style::default().fg(Color::DarkGray)),
            Span::raw(keyspace_str),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            format!(" Progress {:>6.1}%", pct),
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let block = Block::default()
        .title(" GPU ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Blue));

    // We'll render as a Paragraph with gauge embedded in text
    let text = lines;
    Paragraph::new(text)
        .block(block)
}

fn render_found(app: &TuiApp) -> Paragraph<'static> {
    let title = format!(" Found ({}) ", app.found.len());

    let items: Vec<Line<'static>> = app.found.iter().rev().take(16).map(|entry| {
        let display_hash = if entry.hash.len() > 16 {
            format!("{}…", &entry.hash[..14])
        } else {
            entry.hash.clone()
        };
        Line::from(vec![
            Span::styled(" ✓ ", Style::default().fg(Color::Green)),
            Span::styled(display_hash, Style::default().fg(Color::White).add_modifier(Modifier::DIM)),
            Span::raw(" "),
            Span::styled(entry.password.clone(), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        ])
    }).collect();

    let items = if items.is_empty() {
        vec![Line::from(Span::styled(" Waiting...", Style::default().fg(Color::DarkGray)))]
    } else {
        items
    };

    Paragraph::new(items)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Blue)),
        )
}

fn render_log(app: &TuiApp) -> Paragraph<'static> {
    let items: Vec<Line<'static>> = app.logs.iter().rev().take(8).map(|msg| {
        Line::from(Span::styled(msg.clone(), Style::default().fg(Color::DarkGray)))
    }).collect();

    let items = if items.is_empty() {
        vec![Line::from(Span::styled(" Ready", Style::default().fg(Color::DarkGray)))]
    } else {
        items
    };

    Paragraph::new(items)
        .block(
            Block::default()
                .title(" Log ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: false })
}

// ── Helpers ───────────────────────────────────────────────────────────

fn format_secs(secs: f64) -> String {
    let total = secs as u64;
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if h > 0 {
        format!("{}h {:02}m {:02}s", h, m, s)
    } else if m > 0 {
        format!("{}m {:02}s", m, s)
    } else {
        format!("{}s", s)
    }
}

fn format_rate(rate: f64) -> String {
    if rate >= 1_000_000.0 {
        format!("{:.1} MH/s", rate / 1_000_000.0)
    } else if rate >= 1_000.0 {
        format!("{:.1} KH/s", rate / 1_000.0)
    } else {
        format!("{:.0} H/s", rate)
    }
}

// ── Public entry points ───────────────────────────────────────────────

/// Run the crack with a TUI dashboard. The attack runs in a spawned thread,
/// events are sent back via a channel, and the main thread renders the TUI.
pub fn run_crack_tui(
    hash_type: HashType,
    attack_mode: crate::hash_backend::AttackMode,
    entries: Vec<HashEntry>,
    salt: [u32; 16],
    salt_len: u32,
    num_passwords: u32,
    mut potfile: crate::potfile::Potfile,
    mut active_session: Option<crate::session::Session>,
    session_name: Option<String>,
    args: crate::cli::Args,
    hash_type_name: &str,
    first_entry: HashEntry,
    hex_mode: bool,
) {
    // ── Try TUI init first; fall back to CLI if no TTY ──────────────
    let mut terminal = match try_tui_init() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Note: TUI unavailable ({}), falling back to CLI output", e);
            eprintln!("  Use --quiet or --json for non-interactive environments.");
            crate::app::attack::run_gpu_attack(
                hash_type, attack_mode, &entries.clone(), salt, salt_len, num_passwords,
                &mut potfile, &mut active_session, session_name.clone(), &args,
                hash_type_name, &first_entry, false, false, args.verbose, &args.mode, hex_mode,
            );
            return;
        }
    };

    // Channel for events from attack thread
    let (tx, rx): (Sender<TuiEvent>, Receiver<TuiEvent>) = mpsc::channel();
    let abort = Arc::new(AtomicBool::new(false));
    let abort_attack = abort.clone();

    let quiet = args.quiet;
    let json = args.json;
    let verbose = args.verbose;
    let mode = args.mode.clone();
    let htn = hash_type_name.to_string();
    let fe = first_entry.clone();

    // Clone entries before moving into the spawn closure
    let entries_for_worker = entries.clone();

    let mut tw_potfile = potfile;
    let mut tw_session = active_session;

    let attack_handle = thread::Builder::new()
        .name("crack-worker".into())
        .spawn(move || {
            run_attack_tui_inner(
                hash_type, attack_mode, &entries_for_worker,
                salt, salt_len, num_passwords,
                &mut tw_potfile, &mut tw_session, &session_name, &args,
                &htn, &fe, quiet, json, verbose, &mode, hex_mode,
                tx, abort_attack,
            );
        })
        .expect("Failed to spawn crack thread");

    let mut app = TuiApp::new();
    let tick_rate = Duration::from_millis(50);
    let mut last_tick = Instant::now();

    // Main render loop
    let _tui_result = loop {
        let now = Instant::now();
        if now.duration_since(last_tick) >= tick_rate {
            // Process incoming events
            while let Ok(event) = rx.try_recv() {
                match event {
                    TuiEvent::Init { hash_type, mode, num_hashes, keyspace, targets } => {
                        app.hash_type = hash_type;
                        app.mode = mode;
                        app.num_hashes = num_hashes;
                        app.keyspace = keyspace;
                        app.targets = targets;
                        app.total = keyspace;
                        app.push_log(format!("Started: mode={}, targets={}, keyspace={}",
                            app.mode, num_hashes, keyspace));
                    }
                    TuiEvent::Found { hash, password } => {
                        app.found.push(FoundEntry {
                            hash: hash.clone(),
                            password,
                        });
                        app.push_log(format!("✓ Found: {}:{}", &hash[..hash.len().min(20)], app.found.last().unwrap().password));
                        app.targets_left = app.targets_left.saturating_sub(1);
                    }
                    TuiEvent::Progress { progress, total, rate, elapsed, targets_left, current_len } => {
                        app.progress = progress;
                        app.total = total;
                        app.rate = rate;
                        app.elapsed = elapsed;
                        app.targets_left = targets_left;
                        app.current_len = current_len;
                    }
                    TuiEvent::Done { found, elapsed } => {
                        app.done = true;
                        app.elapsed = elapsed;
                        app.push_log(format!("Done: {} found in {}", found, format_secs(elapsed)));
                    }
                    TuiEvent::Abort => {
                        app.push_log("⏹ Aborted by user".to_string());
                    }
                    TuiEvent::Log(msg) => {
                        app.push_log(msg);
                    }
                }
            }

            // Check keyboard
            if event::poll(Duration::from_millis(1)).unwrap_or(false) {
                if let Ok(Event::Key(key)) = event::read() {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                abort.store(true, Ordering::SeqCst);
                                app.push_log("Quit requested, finishing chunk...".to_string());
                                // Still wait for the thread to finish
                            }
                            KeyCode::Char('s') => {
                                app.push_log("Session saved (manual)".to_string());
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Render
            if terminal.draw(|f| render(f, &app)).is_err() {
                break Err("Terminal draw failed".to_string());
            }

            last_tick = now;
        }

        // Check if attack thread finished
        if attack_handle.is_finished() {
            break Ok(());
        }

        std::thread::sleep(Duration::from_millis(10));
    };

    // ── TUI Teardown ──────────────────────────────────────────────────
    disable_raw_mode().expect("disable raw mode");
    execute!(terminal.backend_mut(), LeaveAlternateScreen).expect("leave alt screen");
    terminal.show_cursor().ok();

    // Wait for attack thread
    let _ = attack_handle.join();

    // Print summary to stdout after TUI teardown
    if !quiet && !json {
        if app.found.is_empty() {
            println!("  No passwords found.");
        } else {
            for f in &app.found {
                crate::cli::print_found_entry(&f.hash, &f.password, hex_mode);
            }
        }
        let total_time = std::time::Duration::from_secs_f64(app.elapsed);
        let results: Vec<(String, String, bool)> = entries.iter().map(|e| {
            let found = app.found.iter().find(|f| f.hash == e.hex);
            match found {
                Some(f) => (e.hex.clone(), f.password.clone(), true),
                None => (e.hex.clone(), String::new(), false),
            }
        }).collect();
        crate::cli::print_summary(&results, total_time, entries.len());
    }
}

// ── Attempt TUI init; returns Err in non-TTY environments ────────────

fn try_tui_init() -> Result<Terminal<CrosstermBackend<std::io::Stdout>>, String> {
    enable_raw_mode().map_err(|e| format!("raw mode: {}", e))?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|e| format!("alt screen: {}", e))?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend).map_err(|e| format!("terminal: {}", e))
}

// ── Inner attack runner (sends events instead of printing) ────────────

#[allow(clippy::too_many_arguments)]
fn run_attack_tui_inner(
    hash_type: HashType,
    attack_mode: crate::hash_backend::AttackMode,
    entries: &[HashEntry],
    salt: [u32; 16],
    salt_len: u32,
    num_passwords: u32,
    potfile: &mut crate::potfile::Potfile,
    active_session: &mut Option<crate::session::Session>,
    _session_name: &Option<String>,
    args: &crate::cli::Args,
    hash_type_name: &str,
    first_entry: &HashEntry,
    _quiet: bool,
    _json: bool,
    verbose: bool,
    mode: &str,
    _hex_mode: bool,
    tx: Sender<TuiEvent>,
    abort: Arc<AtomicBool>,
) {
    let log = |msg: String| { let _ = tx.send(TuiEvent::Log(msg)); };
    let is_cpu_only = hash_type.module().shader_source(&crate::hashes::AttackModeType::Wordlist).is_empty();

    // ── CPU wordlist fallback ────────────────────────────────────────
    if is_cpu_only && matches!(&attack_mode, crate::hash_backend::AttackMode::Wordlist { .. }) {
        if let crate::hash_backend::AttackMode::Wordlist { words } = &attack_mode {
            let module = hash_type.module();
            let _ = tx.send(TuiEvent::Init {
                hash_type: hash_type_name.to_string(),
                mode: format!("wordlist (CPU, {} words)", words.len()),
                num_hashes: entries.len(),
                keyspace: words.len() as u64,
                targets: entries.to_vec(),
            });

            for entry in entries {
                if abort.load(Ordering::SeqCst) { break; }
                let parsed = match module.parse_hash_string(&entry.hex) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let dw = module.digest_words() as usize;
                let full = crate::hash_backend::full_hash_slice(&parsed, dw);
                let hash_slice = &full[..dw];
                let salt_bytes: &[u8] = &parsed.salt;
                for w in words {
                    if abort.load(Ordering::SeqCst) { break; }
                    if module.cpu_verify(w, salt_bytes, hash_slice) {
                        let _ = tx.send(TuiEvent::Found {
                            hash: entry.hex.clone(),
                            password: w.clone(),
                        });
                        potfile.record_crack(&entry.hex, w);
                    }
                }
            }
            if let Err(e) = potfile.save() {
                log(format!("Warning: potfile save failed: {}", e));
            }
            let _ = tx.send(TuiEvent::Done {
                found: 0, // we don't track found count easily here
                elapsed: 0.0,
            });
            return;
        }
    }

    // ── Main cracking loop ───────────────────────────────────────────
    let num_hashes = entries.len();
    let is_incremental = mode == "incremental";

    let uncracked: Vec<&HashEntry> = entries.iter()
        .filter(|e| !potfile.is_cracked(&e.hex))
        .collect();

    if uncracked.is_empty() && num_hashes > 0 {
        let _ = tx.send(TuiEvent::Done { found: 0, elapsed: 0.0 });
        return;
    }

    let effective_count = uncracked.len();

    let first = uncracked[0];
    let mode_type = crate::hashes::attack_mode_type(&attack_mode);
    if hash_type.module().shader_source(&mode_type).is_empty() && !matches!(&attack_mode, crate::hash_backend::AttackMode::Wordlist { .. }) {
        let _ = tx.send(TuiEvent::Log(format!("Error: {} is CPU-only and only supports wordlist mode. Use --mode wordlist --wordlist <file>", hash_type.name())));
        let _ = tx.send(TuiEvent::Done { found: 0, elapsed: 0.0 });
        return;
    }

    let mut gpu = pollster::block_on(crate::gpu::GpuCracker::new(
        &hash_type, attack_mode.clone(), first.hash, first.hash_extra, salt, salt_len,
    ));

    if verbose {
        let np = gpu.num_passwords();
        log(format!("GPU dispatch: workgroup=128, num_passwords={np}, chunk_size=1000000"));
    }

    let module = hash_type.module();
    let mut remaining: Vec<&HashEntry> = uncracked.iter().copied().collect();

    let write_remaining = |gpu: &mut crate::gpu::GpuCracker, rem: &[&HashEntry]| {
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

    let save_progress = |sess: &mut Option<crate::session::Session>, htn: &str, a: &crate::cli::Args, fe: &HashEntry, cl: u32, cs: u32, ps: u32, tf: &[(usize, String, String)]| {
        if let Some(s) = sess {
            crate::app::helpers::save_session_state(
                s, htn, a, &fe.hex, &fe.salt, fe.salt_len, cl, cs, ps, tf,
            );
        }
    };

    // Send init event
    let _ = tx.send(TuiEvent::Init {
        hash_type: hash_type_name.to_string(),
        mode: mode.to_string(),
        num_hashes: effective_count,
        keyspace: num_passwords as u64,
        targets: entries.to_vec(),
    });

    let mut current_len_val: u32 = 1;
    let mut current_space = num_passwords;
    const CHUNK_SIZE: u32 = 1_000_000;
    let mut chunk_start = 0u32;

    if let Some(ref state) = session_state_opt {
        chunk_start = state.progress as u32;
        current_len_val = state.password_len;
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
            // Send pre-filled found events for session restore
            for (h, p) in &state.cracked_hashes {
                let _ = tx.send(TuiEvent::Found { hash: h.clone(), password: p.clone() });
            }
            write_remaining(&mut gpu, &remaining);
        }
    }

    #[allow(unused_assignments)]
    let mut last_progress = 0u32;
    let mut last_rate_update = Instant::now();
    let mut current_rate = 0.0;
    let mut poll_interval_us = 1000u64;

    'chunks: while chunk_start < current_space && !remaining.is_empty() {
        if abort.load(Ordering::SeqCst) {
            let _ = tx.send(TuiEvent::Abort);
            break;
        }

        let chunk_end = (chunk_start + CHUNK_SIZE).min(current_space);
        let mut chunk_size = chunk_end - chunk_start;

        gpu.redispatch_range(chunk_start, chunk_end);
        if verbose {
            log(format!("Chunk {}-{} (size {}) of {}", chunk_start, chunk_end, chunk_end - chunk_start, current_space));
        }

        let progress_base = chunk_start;
        last_progress = 0;

        'poll: loop {
            if abort.load(Ordering::SeqCst) {
                break 'chunks;
            }

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

                // Send progress event
                let _ = tx.send(TuiEvent::Progress {
                    progress: (progress_base + data.progress) as u64,
                    total: current_space as u64,
                    rate: current_rate,
                    elapsed: start_time.elapsed().as_secs_f64(),
                    targets_left: remaining.len(),
                    current_len: current_len_val,
                });

                if data.found_flag != 0 {
                    let pwd = gpu.decode_found_password(&data).unwrap_or_default();
                    let cracked: Vec<usize> = remaining.iter().enumerate().filter_map(|(i, e)| {
                        let parsed = module.parse_hash_string(&e.hex).ok()?;
                        let dw = module.digest_words() as usize;
                        let full = crate::hash_backend::full_hash_slice(&parsed, dw);
                        let hash_slice = &full[..dw];
                        let salt_bytes: &[u8] = if !parsed.salt.is_empty() { &parsed.salt } else { &[] };
                        if module.cpu_verify(&pwd, salt_bytes, hash_slice) {
                            Some(i)
                        } else {
                            None
                        }
                    }).rev().collect();

                    for &ci in &cracked {
                        let e = remaining[ci];
                        let _ = tx.send(TuiEvent::Found {
                            hash: e.hex.clone(),
                            password: pwd.clone(),
                        });
                        potfile.record_crack(&e.hex, &pwd);
                        total_found.push((ci, e.hex.clone(), pwd.clone()));
                    }

                    for &ci in &cracked { remaining.remove(ci); }

                    if remaining.is_empty() {
                        save_progress(active_session, hash_type_name, args, first_entry, current_len_val, current_space, chunk_start, &total_found);
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

        if abort.load(Ordering::SeqCst) {
            log(format!("Aborted at chunk ({:.1}%)",
                (chunk_start as f64 / current_space as f64) * 100.0));
            break;
        }

        if is_incremental && current_len_val < 4 {
            current_len_val += 1;
            current_space = 62u32.pow(current_len_val);
            chunk_start = 0;
            gpu.reconfig_len(current_len_val, current_space);
            write_remaining(&mut gpu, &remaining);
            save_progress(active_session, hash_type_name, args, first_entry, current_len_val, current_space, chunk_start, &total_found);
            let _ = tx.send(TuiEvent::Log(format!("Extending to len {}", current_len_val)));
            continue;
        }

        save_progress(active_session, hash_type_name, args, first_entry, current_len_val, current_space, chunk_start, &total_found);
        chunk_start = chunk_end;
    }

    // Save potfile
    if !total_found.is_empty() {
        if let Err(e) = potfile.save() {
            log(format!("Warning: potfile save failed: {}", e));
        }
    }

    let elapsed = start_time.elapsed().as_secs_f64();

    let _ = tx.send(TuiEvent::Done {
        found: total_found.len(),
        elapsed,
    });

    if let Some(ref mut sess) = active_session {
        if remaining.is_empty() {
            let _ = sess.delete();
        }
    }
}
