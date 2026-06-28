use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Alignment, Constraint, Flex, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Clear, Gauge, Paragraph},
    Frame,
};

use crate::hash_backend::{AttackMode, HashType, full_hash_slice};
use crate::cli::HashEntry;

pub mod theme;
pub mod banner;
pub mod embedded_test;

pub use theme::Theme;

pub use crate::cli::output::{
    print_found_entry,
    print_summary,
    print_bench_header,
    print_bench_row,
    print_bench_footer,
};

#[derive(Clone)]
pub struct FoundEntry {
    pub hash: String,
    pub password: String,
}

enum Phase {
    Startup,
    Cracking,
}

struct TuiApp {
    theme: Theme,
    phase: Phase,

    hash_type: String,
    mode: String,
    keyspace: u64,
    num_hashes: usize,

    num_targets: usize,
    targets_left: usize,
    progress: u64,
    total: u64,
    rate: f64,
    elapsed: f64,
    current_len: u32,
    found: Vec<FoundEntry>,

    cracked_count: usize,
    logs: VecDeque<String>,

    completed: bool,
    last_eta: String,
    rate_history: VecDeque<u64>,
}

impl TuiApp {
    fn new(config: &CrackConfig) -> Self {
        Self {
            theme: Theme::dark(),
            phase: Phase::Startup,
            hash_type: config.hash_type.clone(),
            mode: config.mode.clone(),
            keyspace: config.keyspace,
            num_hashes: config.num_hashes,
            num_targets: config.num_hashes,
            targets_left: config.num_hashes,
            progress: 0,
            total: 1,
            rate: 0.0,
            elapsed: 0.0,
            current_len: 0,
            found: Vec::new(),
            cracked_count: 0,
            logs: VecDeque::with_capacity(50),
            completed: false,
            last_eta: String::new(),
            rate_history: VecDeque::with_capacity(40),
        }
    }

    fn reset_attack(&mut self) {
        self.progress = 0;
        self.total = 1;
        self.rate = 0.0;
        self.elapsed = 0.0;
        self.current_len = 0;
        self.found.clear();
        self.cracked_count = 0;
        self.targets_left = self.num_targets;
        self.logs.clear();
        self.completed = false;
        self.last_eta.clear();
        self.rate_history.clear();
    }

    #[allow(dead_code)]
    fn push_log(&mut self, msg: String) {
        if self.logs.len() >= 50 { self.logs.pop_front(); }
        self.logs.push_back(msg);
    }
}

struct CrackConfig {
    hash_type: String,
    mode: String,
    keyspace: u64,
    num_hashes: usize,
}

enum CrackEvent {
    Started,
    Progress { progress: u64, total: u64, rate: f64, elapsed: f64, targets_left: usize, current_len: u32 },
    Found { hash: String, password: String },
    Done { found: usize, elapsed: f64 },
    Log(String),
}

fn fmt_duration(secs: f64) -> String {
    let t = secs as u64;
    let h = t / 3600; let m = (t % 3600) / 60; let s = t % 60;
    if h > 0 { format!("{}h {:02}m {:02}s", h, m, s) }
    else if m > 0 { format!("{}m {:02}s", m, s) }
    else { format!("{}s", s) }
}

fn fmt_rate(rate: f64) -> String {
    if rate >= 1_000_000.0 { format!("{:.1}MH/s", rate / 1_000_000.0) }
    else if rate >= 1_000.0 { format!("{:.1}KH/s", rate / 1_000.0) }
    else { format!("{:.0}H/s", rate) }
}

fn fmt_keyspace(ks: u64) -> String {
    if ks >= 1_000_000 { format!("{:.1}M", ks as f64 / 1_000_000.0) }
    else if ks >= 1_000 { format!("{:.1}K", ks as f64 / 1_000.0) }
    else { ks.to_string() }
}

fn pct_bar(pct: f64, width: u16) -> String {
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    let empty = width.saturating_sub(filled as u16) as usize;
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

fn render_startup(frame: &mut Frame, app: &TuiApp) {
    let t = &app.theme;
    let area = frame.area();
    frame.render_widget(Clear, area);
    frame.render_widget(
        Block::default().style(t.bg_style()),
        area,
    );

    let content_height = banner::banner_lines() as u16 + 1 + 1 + 8 + 2;
    let rows = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(content_height),
        Constraint::Fill(1),
    ]).flex(Flex::Center).split(area);

    let middle = rows[1];
    let group = Layout::vertical([
        Constraint::Length(banner::banner_lines() as u16),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(8),
        Constraint::Length(2),
    ]).split(middle);

    banner::render_banner(frame, group[0], Style::default().fg(t.primary).bold());

    let sub = Paragraph::new("GPU-Accelerated Password Recovery  |  42 hash types")
        .style(t.style_muted()).alignment(Alignment::Center);
    frame.render_widget(sub, group[1]);

    let conf_panel = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(56),
        Constraint::Fill(1),
    ]).split(group[3]);
    let conf_text = format!(
        "\n\nHash Type:  {}     Mode:  {}\nTargets:    {}     Keyspace:  {}\n\n",
        app.hash_type, app.mode, app.num_hashes, fmt_keyspace(app.keyspace),
    );
    let conf = Paragraph::new(conf_text)
        .block(Block::bordered().title(" Configuration ").border_style(t.style_border()))
        .style(t.style_text())
        .alignment(Alignment::Center);
    frame.render_widget(conf, conf_panel[1]);

    let prompt = Paragraph::new(Line::from(vec![
        Span::styled("Press ", t.style_muted()),
        Span::styled("ENTER", t.style_bold_accent()),
        Span::styled(" to start  •  Press ", t.style_muted()),
        Span::styled("Q", t.style_bold_error()),
        Span::styled(" to quit", t.style_muted()),
    ])).alignment(Alignment::Center);
    frame.render_widget(prompt, group[4]);
}

fn sparkline_from_history(history: &VecDeque<u64>, width: usize) -> String {
    if history.is_empty() || width == 0 { return String::new(); }
    let max = history.iter().max().copied().unwrap_or(1).max(1);
    let bars = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];
    let n = history.len().min(width);
    let step = history.len() as f64 / n as f64;
    let mut out = String::with_capacity(n);
    for i in 0..n {
        let idx = (i as f64 * step).floor() as usize;
        let val = history[idx];
        let bar_idx = (val * 7 / max).min(7) as usize;
        out.push_str(bars[bar_idx]);
    }
    out
}

fn render_cracking(frame: &mut Frame, app: &TuiApp) {
    let t = &app.theme;
    let area = frame.area();
    frame.render_widget(Clear, area);
    frame.render_widget(
        Block::default().style(t.bg_style()),
        area,
    );

    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(2),
    ]).split(area);

    let status = Line::from(if app.completed {
        vec![
            Span::styled("#CRACKER", t.style_bold_primary()),
            Span::raw("  ■  "),
            Span::styled("✓ DONE", t.style_bold_secondary()),
            Span::raw("  ■  "),
            Span::styled(fmt_duration(app.elapsed), t.style_accent()),
            Span::raw("  ■  "),
            Span::styled(format!("{} found", app.found.len()), t.style_bold_accent()),
            Span::raw("    "),
            Span::styled("[ENTER]", t.style_bold_accent()),
            Span::styled(" re-run  ", t.style_muted()),
            Span::styled("[Q]", t.style_bold_error()),
            Span::styled(" quit", t.style_muted()),
        ]
    } else {
        vec![
            Span::styled("#CRACKER", t.style_bold_primary()),
            Span::raw("  ■  "),
            Span::styled(&app.hash_type, t.style_text()),
            Span::raw("  ■  "),
            Span::styled(&app.mode, t.style_accent()),
            Span::raw("  ■  "),
            Span::styled(fmt_rate(app.rate), t.style_secondary()),
            Span::raw("    "),
            Span::styled("[Q]", t.style_bold_error()),
            Span::styled(" abort  ", t.style_muted()),
            Span::styled("[S]", t.style_bold_accent()),
            Span::styled(" save", t.style_muted()),
        ]
    });
    frame.render_widget(Paragraph::new(status), rows[0]);

    let top_bot = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Fill(1),
    ]).split(rows[1]);

    let top_row = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Fill(1),
    ]).split(top_bot[0]);

    let bot_row = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Fill(1),
    ]).split(top_bot[1]);

    let pct = if app.total > 0 { (app.progress as f64 / app.total as f64 * 100.0).min(100.0) } else { 0.0 };
    let eta = if app.rate > 0.0 { fmt_duration((app.total.saturating_sub(app.progress)) as f64 / app.rate) } else { "--".into() };

    let targets_lines = vec![
        Line::from(vec![Span::styled("Total", t.style_muted()), Span::raw("  "), Span::styled(app.num_targets.to_string(), t.style_text())]),
        Line::from(vec![Span::styled("Left", t.style_muted()), Span::raw("   "), Span::styled(app.targets_left.to_string(), if app.targets_left > 0 { t.style_accent() } else { t.style_secondary() })]),
        Line::from(vec![Span::styled("Found", t.style_muted()), Span::raw("  "), Span::styled(app.found.len().to_string(), t.style_bold_secondary())]),
    ];
    let targets = Paragraph::new(targets_lines)
        .block(Block::bordered().title(" Targets ").title_alignment(Alignment::Center).border_style(t.style_border()))
        .style(t.style_text());
    frame.render_widget(targets, top_row[0]);

    let spark = sparkline_from_history(&app.rate_history, top_row[1].width.saturating_sub(4) as usize);
    let progress_lines: Vec<Line> = if app.completed {
        vec![
            Line::from(vec![Span::styled("Status", t.style_muted()), Span::raw("    "), Span::styled("✓ COMPLETE", t.style_bold_secondary())]),
            Line::from(vec![Span::styled("Elapsed", t.style_muted()), Span::raw("   "), Span::styled(fmt_duration(app.elapsed), t.style_accent())]),
            Line::from(vec![Span::styled("Rate", t.style_muted()), Span::raw("     "), Span::styled(fmt_rate(app.rate), t.style_secondary())]),
            Line::from(vec![Span::styled("Keyspace", t.style_muted()), Span::raw(" "), Span::styled(fmt_keyspace(app.total), t.style_text())]),
        ]
    } else {
        let mut lines = vec![
            Line::from(vec![Span::styled("Speed", t.style_muted()), Span::raw("    "), Span::styled(fmt_rate(app.rate), t.style_bold_secondary())]),
            Line::from(vec![Span::styled("Elapsed", t.style_muted()), Span::raw("   "), Span::styled(fmt_duration(app.elapsed), t.style_accent())]),
            Line::from(vec![Span::styled("ETA", t.style_muted()), Span::raw("     "), Span::styled(&eta, t.style_accent())]),
            Line::from(vec![Span::styled("Keyspace", t.style_muted()), Span::raw(" "), Span::styled(fmt_keyspace(app.total), t.style_text())]),
        ];
        if !spark.is_empty() {
            lines.push(Line::from(Span::styled(format!(" {} ", spark), t.style_secondary())));
        }
        lines
    };
    let progress_block = Block::bordered().title(" Progress ").title_alignment(Alignment::Center).border_style(t.style_border());
    let progress_inner = progress_block.inner(top_row[1]);
    frame.render_widget(&progress_block, top_row[1]);
    let gauge_line_y = progress_inner.y;
    let gauge_height = if app.completed { 0u16 } else { 1u16 };
    if !app.completed {
        let bar_width = progress_inner.width.saturating_sub(2);
        let gauge_str = pct_bar(pct, bar_width);
        frame.render_widget(Paragraph::new(gauge_str).style(t.style_accent()), Rect::new(progress_inner.x, gauge_line_y, progress_inner.width, 1));
    }
    frame.render_widget(Paragraph::new(progress_lines).style(t.style_text()), Rect::new(progress_inner.x, gauge_line_y + gauge_height + 1, progress_inner.width, progress_inner.height.saturating_sub(gauge_height + 1)));

    let found_lines: Vec<Line> = if app.found.is_empty() {
        vec![Line::from(Span::styled("  awaiting results…", t.style_muted()))]
    } else {
        app.found.iter().rev().take(20).map(|e| {
            let h = if e.hash.len() > 12 { format!("{}…", &e.hash[..12]) } else { e.hash.clone() };
            Line::from(vec![
                Span::styled("✓ ", t.style_secondary()),
                Span::styled(h, t.style_muted()),
                Span::raw(" → "),
                Span::styled(&e.password, t.style_bold_secondary()),
            ])
        }).collect()
    };
    let found = Paragraph::new(found_lines)
        .block(Block::bordered().title(format!(" Found ({}) ", app.found.len())).title_alignment(Alignment::Center).border_style(t.style_border()))
        .style(t.style_text());
    frame.render_widget(found, bot_row[0]);

    let summary_lines = if app.completed {
        vec![
            Line::from(vec![Span::styled("Status", t.style_muted()), Span::raw("     "), Span::styled("✓ COMPLETE", t.style_bold_secondary())]),
            Line::from(vec![Span::styled("Cracked", t.style_muted()), Span::raw("   "), Span::styled(format!("{} / {}", app.found.len(), app.num_targets), t.style_bold_secondary())]),
            Line::from(vec![Span::styled("Elapsed", t.style_muted()), Span::raw("   "), Span::styled(fmt_duration(app.elapsed), t.style_accent())]),
            Line::from(vec![Span::styled("Avg rate", t.style_muted()), Span::raw(" "), Span::styled(fmt_rate(app.rate), t.style_secondary())]),
            Line::from(vec![Span::styled("Keyspace", t.style_muted()), Span::raw(" "), Span::styled(fmt_keyspace(app.total), t.style_text())]),
        ]
    } else {
        vec![
            Line::from(vec![Span::styled("Status", t.style_muted()), Span::raw("     "), Span::styled("CRACKING", t.style_bold_accent())]),
            Line::from(vec![Span::styled("Elapsed", t.style_muted()), Span::raw("   "), Span::styled(fmt_duration(app.elapsed), t.style_accent())]),
            Line::from(vec![Span::styled("ETA", t.style_muted()), Span::raw("     "), Span::styled(&eta, t.style_accent())]),
            Line::from(vec![Span::styled("Left", t.style_muted()), Span::raw("    "), Span::styled(format!("{} / {}", app.targets_left, app.num_targets), t.style_text())]),
            Line::from(vec![Span::styled("Rate", t.style_muted()), Span::raw("     "), Span::styled(fmt_rate(app.rate), t.style_secondary())]),
        ]
    };
    let summary = Paragraph::new(summary_lines)
        .block(Block::bordered().title(" Summary ").title_alignment(Alignment::Center).border_style(t.style_border()))
        .style(t.style_text());
    frame.render_widget(summary, bot_row[1]);

    if app.completed {
        let gauge = Gauge::default()
            .block(Block::bordered().border_style(t.style_border()))
            .gauge_style(t.style_secondary())
            .percent(100)
            .label(" DONE ");
        frame.render_widget(gauge, rows[2]);
    } else {
        let gauge = Gauge::default()
            .block(Block::bordered().border_style(t.style_border()))
            .gauge_style(t.style_accent())
            .percent(pct as u16)
            .label(format!(" {} / {}  ({:.1}%)  @ {} ", app.progress, app.total, pct, fmt_rate(app.rate)));
        frame.render_widget(gauge, rows[2]);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_tui(
    hash_type: HashType,
    attack_mode: AttackMode,
    entries: Vec<HashEntry>,
    salt: [u32; 16],
    salt_len: u32,
    num_passwords: u32,
    potfile: crate::potfile::Potfile,
    active_session: Option<crate::session::Session>,
    args: crate::cli::Args,
    hash_type_name: &str,
    first_entry: HashEntry,
    hex_mode: bool,
) {
    let mut terminal = ratatui::init();

    let config = CrackConfig {
        hash_type: hash_type_name.to_string(),
        mode: args.mode.clone(),
        keyspace: num_passwords as u64,
        num_hashes: entries.len(),
    };
    let mut app = TuiApp::new(&config);

    let potfile_path: PathBuf = args.potfile.clone().unwrap_or_else(|| {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".hashcracker").join("potfile")
    });
    let session_name: Option<String> = args.session.clone();

    let mut potfile_opt = Some(potfile);
    let mut active_session_opt: Option<Option<crate::session::Session>> = Some(active_session);
    let mut attack_rx: Option<Receiver<CrackEvent>> = None;
    let mut abort_flag: Option<Arc<AtomicBool>> = None;

    let tick_rate = Duration::from_millis(50);
    let mut last_tick = Instant::now();

    loop {
        if let Ok(true) = event::poll(tick_rate) {
            match event::read() {
                Ok(Event::Key(key)) => {
                    if key.kind == KeyEventKind::Press {
                        match (&app.phase, app.completed, key.code) {
                            (Phase::Startup, _, KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc) => break,
                            (Phase::Startup, _, KeyCode::Enter) => {
                                let (tx, rx): (Sender<CrackEvent>, Receiver<CrackEvent>) = mpsc::channel();
                                let ab = Arc::new(AtomicBool::new(false));

                                let entries_w = entries.clone();
                                let hash_type_w = hash_type;
                                let attack_mode_w = attack_mode.clone();
                                let htn_w = hash_type_name.to_string();
                                let fe_w = first_entry.clone();
                                let q = args.quiet;
                                let j = args.json;
                                let v = args.verbose;
                                let mode_w = args.mode.clone();
                                let hm = hex_mode;
                                let a = args.clone();
                                let ab_w = ab.clone();

                                let mut pf = potfile_opt.take()
                                    .unwrap_or_else(|| crate::potfile::Potfile::with_path(potfile_path.clone()));
                                let mut sess: Option<crate::session::Session> = active_session_opt.take()
                                    .unwrap_or_else(|| session_name.as_ref().map(|n| crate::session::Session::new(n)));

                                thread::Builder::new().name("crack".into()).spawn(move || {
                                    run_attack_in_thread(
                                        hash_type_w, attack_mode_w, &entries_w,
                                        salt, salt_len, num_passwords,
                                        &mut pf, &mut sess, &a,
                                        &htn_w, &fe_w, q, j, v, &mode_w, hm,
                                        tx, ab_w,
                                    );
                                }).expect("spawn crack");

                                attack_rx = Some(rx);
                                abort_flag = Some(ab);
                                app.phase = Phase::Cracking;
                            }

                            (Phase::Cracking, true, KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc) => break,
                            (Phase::Cracking, true, KeyCode::Enter) => {
                                attack_rx = None;
                                abort_flag = None;
                                app.reset_attack();
                                app.phase = Phase::Startup;
                            }

                            (Phase::Cracking, false, KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc) => {
                                if let Some(ref ab) = abort_flag { ab.store(true, Ordering::SeqCst); }
                            }
                            (Phase::Cracking, false, KeyCode::Char('s')) => {
                                app.push_log("Session saved (manual)".to_string());
                            }

                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        if let Some(ref rx) = attack_rx {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    CrackEvent::Started => {}
                    CrackEvent::Progress { progress, total, rate, elapsed, targets_left, current_len } => {
                        app.progress = progress; app.total = total; app.rate = rate;
                        app.elapsed = elapsed; app.targets_left = targets_left; app.current_len = current_len;
                        let hps = rate as u64;
                        if app.rate_history.len() >= 40 { app.rate_history.pop_front(); }
                        app.rate_history.push_back(hps);
                    }
                    CrackEvent::Found { hash, password } => {
                        app.found.push(FoundEntry { hash, password });
                        app.targets_left = app.targets_left.saturating_sub(1);
                    }
                    CrackEvent::Done { found, elapsed } => {
                        app.cracked_count = found; app.elapsed = elapsed;
                        app.completed = true;
                    }
                    CrackEvent::Log(msg) => { app.push_log(msg); }
                }
            }
        }

        let now = Instant::now();
        if now.duration_since(last_tick) >= tick_rate {
            let _ = terminal.draw(|f| match app.phase {
                Phase::Startup => render_startup(f, &app),
                Phase::Cracking => render_cracking(f, &app),
            });
            last_tick = now;
        }
    }

    ratatui::restore();
}

#[allow(clippy::too_many_arguments)]
fn run_attack_in_thread(
    hash_type: HashType,
    attack_mode: AttackMode,
    entries: &[HashEntry],
    salt: [u32; 16],
    salt_len: u32,
    num_passwords: u32,
    potfile: &mut crate::potfile::Potfile,
    active_session: &mut Option<crate::session::Session>,
    args: &crate::cli::Args,
    hash_type_name: &str,
    first_entry: &HashEntry,
    _quiet: bool,
    _json: bool,
    verbose: bool,
    mode: &str,
    _hex_mode: bool,
    tx: Sender<CrackEvent>,
    abort: Arc<AtomicBool>,
) {
    let _ = tx.send(CrackEvent::Started);

    let is_cpu_only = hash_type.module().shader_source(&crate::hashes::AttackModeType::Wordlist).is_empty();
    if is_cpu_only && matches!(&attack_mode, AttackMode::Wordlist { .. }) {
        if let AttackMode::Wordlist { words } = &attack_mode {
            let module = hash_type.module();
            for entry in entries {
                if abort.load(Ordering::SeqCst) { break; }
                let parsed = match module.parse_hash_string(&entry.hex) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let dw = module.digest_words() as usize;
                let full = full_hash_slice(&parsed, dw);
                let hash_slice = &full[..dw];
                let salt_bytes: &[u8] = &parsed.salt;
                for w in words {
                    if abort.load(Ordering::SeqCst) { break; }
                    if module.cpu_verify(w, salt_bytes, hash_slice) {
                        let _ = tx.send(CrackEvent::Found { hash: entry.hex.clone(), password: w.clone() });
                        potfile.record_crack(&entry.hex, w);
                    }
                }
            }
            if let Err(e) = potfile.save() { let _ = tx.send(CrackEvent::Log(format!("potfile: {}", e))); }
            let _ = tx.send(CrackEvent::Done { found: 0, elapsed: 0.0 });
            return;
        }
    }

    let num_hashes = entries.len();
    let is_incremental = mode == "incremental";
    let uncracked: Vec<&HashEntry> = entries.iter().filter(|e| !potfile.is_cracked(&e.hex)).collect();

    if uncracked.is_empty() && num_hashes > 0 {
        let _ = tx.send(CrackEvent::Done { found: 0, elapsed: 0.0 });
        return;
    }

    let first = uncracked[0];
    let mode_type = crate::hashes::attack_mode_type(&attack_mode);
    if hash_type.module().shader_source(&mode_type).is_empty() && !matches!(&attack_mode, AttackMode::Wordlist { .. }) {
        let _ = tx.send(CrackEvent::Log(format!("{} is CPU-only, only wordlist mode", hash_type.name())));
        let _ = tx.send(CrackEvent::Done { found: 0, elapsed: 0.0 });
        return;
    }

    let mut gpu = pollster::block_on(crate::gpu::GpuCracker::new(&hash_type, attack_mode.clone(), first.hash, first.hash_extra, salt, salt_len));
    if verbose {
        let np = gpu.num_passwords();
        let _ = tx.send(CrackEvent::Log(format!("GPU: {} passwords, chunk=1M", np)));
    }

    let module = hash_type.module();
    let mut remaining: Vec<&HashEntry> = uncracked.iter().copied().collect();

    let write_remaining = |gpu: &mut crate::gpu::GpuCracker, rem: &[&HashEntry]| {
        let targets: Vec<crate::gpu::TargetEntry> = rem.iter().map(|e| crate::gpu::TargetEntry { hash: e.hash, hash_extra: e.hash_extra }).collect();
        gpu.write_targets(&targets);
    };
    write_remaining(&mut gpu, &remaining);

    let mut session_state_opt = None;
    if let Some(ref mut sess) = active_session {
        if sess.exists() { let _ = sess.load().ok().map(|s| session_state_opt = Some(s)); }
    }

    let mut total_found: Vec<(usize, String, String)> = Vec::new();
    let start_time = Instant::now();
    let mut current_len_val = 1u32;
    let mut current_space = num_passwords;
    const CHUNK_SIZE: u32 = 1_000_000;
    let mut chunk_start = 0u32;

    if let Some(ref state) = session_state_opt {
        chunk_start = state.progress as u32;
        current_len_val = state.password_len;
        current_space = state.keyspace as u32;
        for (h, p) in &state.cracked_hashes { potfile.record_crack(h, p); }
        for (h, _) in &state.cracked_hashes { if let Some(pos) = remaining.iter().position(|e| e.hex == *h) { remaining.remove(pos); } }
        if !state.cracked_hashes.is_empty() {
            for (h, p) in &state.cracked_hashes { let _ = tx.send(CrackEvent::Found { hash: h.clone(), password: p.clone() }); }
            write_remaining(&mut gpu, &remaining);
        }
    }

    #[allow(unused_assignments)]
    let mut last_progress = 0u32;
    let mut last_rate_update = Instant::now();
    let mut current_rate = 0.0;
    let mut poll_interval_us = 1000u64;

    'chunks: while chunk_start < current_space && !remaining.is_empty() {
        if abort.load(Ordering::SeqCst) { break; }
        let chunk_end = (chunk_start + CHUNK_SIZE).min(current_space);
        let mut chunk_size = chunk_end - chunk_start;
        gpu.redispatch_range(chunk_start, chunk_end);
        let progress_base = chunk_start;
        last_progress = 0;

        'poll: loop {
            if abort.load(Ordering::SeqCst) { break 'chunks; }
            gpu.poll();
            if let Some(data) = gpu.try_readback() {
                if data.progress > chunk_size && data.found_flag == 0 {
                    std::thread::sleep(Duration::from_micros(100));
                    continue;
                }
                let now = Instant::now();
                let dt = now.duration_since(last_rate_update).as_secs_f64().max(0.001);
                let delta = data.progress.saturating_sub(last_progress) as f64;
                if delta > 0.0 {
                    let delta_rate = delta / dt;
                    current_rate = if current_rate == 0.0 { delta_rate } else { current_rate * 0.7 + delta_rate * 0.3 };
                    last_progress = data.progress;
                    last_rate_update = now;
                    poll_interval_us = if current_rate > 1_000_000.0 { 1_000 } else if current_rate > 1_000.0 { 10_000 } else { 100_000 };
                }

                let _ = tx.send(CrackEvent::Progress {
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
                        let full = full_hash_slice(&parsed, dw);
                        let hash_slice = &full[..dw];
                        let sb: &[u8] = if !parsed.salt.is_empty() { &parsed.salt } else { &[] };
                        if module.cpu_verify(&pwd, sb, hash_slice) { Some(i) } else { None }
                    }).rev().collect();

                    for &ci in &cracked {
                        let e = remaining[ci];
                        let _ = tx.send(CrackEvent::Found { hash: e.hex.clone(), password: pwd.clone() });
                        potfile.record_crack(&e.hex, &pwd);
                        total_found.push((ci, e.hex.clone(), pwd.clone()));
                    }
                    for &ci in &cracked { remaining.remove(ci); }

                    if remaining.is_empty() {
                        save_progress(active_session, hash_type_name, args, first_entry, current_len_val, current_space, chunk_start, &total_found);
                        break 'chunks;
                    }

                    let match_idx = match mode { "wordlist" | "hybrid" => data.found_password[0], _ => data.progress };
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
            std::thread::sleep(Duration::from_micros(poll_interval_us));
        }

        if abort.load(Ordering::SeqCst) { break; }
        if is_incremental && current_len_val < 4 {
            current_len_val += 1;
            current_space = 62u32.pow(current_len_val);
            chunk_start = 0;
            gpu.reconfig_len(current_len_val, current_space);
            write_remaining(&mut gpu, &remaining);
            save_progress(active_session, hash_type_name, args, first_entry, current_len_val, current_space, chunk_start, &total_found);
            continue;
        }
        save_progress(active_session, hash_type_name, args, first_entry, current_len_val, current_space, chunk_start, &total_found);
        chunk_start = chunk_end;
    }

    if !total_found.is_empty() { let _ = potfile.save(); }
    let elapsed = start_time.elapsed().as_secs_f64();
    let _ = tx.send(CrackEvent::Done { found: total_found.len(), elapsed });
    if let Some(ref mut sess) = active_session { if remaining.is_empty() { let _ = sess.delete(); } }
}

fn save_progress(
    active_session: &mut Option<crate::session::Session>,
    hash_type_name: &str,
    args: &crate::cli::Args,
    first_entry: &HashEntry,
    current_len_val: u32,
    current_space: u32,
    chunk_start: u32,
    total_found: &[(usize, String, String)],
) {
    if let Some(s) = active_session.as_mut() {
        crate::app::helpers::save_session_state(
            s, hash_type_name, args, &first_entry.hex,
            &first_entry.salt, first_entry.salt_len,
            current_len_val, current_space, chunk_start,
            total_found,
        );
    }
}
