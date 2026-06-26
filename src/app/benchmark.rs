use owo_colors::OwoColorize;
use crate::hash_backend::{HashType, AttackMode};
use crate::hashes::AttackModeType;
use crate::gpu;
use crate::ui;

pub fn run_benchmark(verbose: bool) {
    let hash_types = [HashType::Lm, HashType::Md4, HashType::Md5, HashType::Ntlm, HashType::Sha1, HashType::Sha224, HashType::Sha256, HashType::Sha384, HashType::Sha512, HashType::HmacSha512, HashType::Md5Crypt, HashType::Sha256Crypt, HashType::Sha512Crypt, HashType::Phpass, HashType::Apr1, HashType::Bcrypt, HashType::Crc32, HashType::Drupal7, HashType::Db2, HashType::Grub2, HashType::Pbkdf2Sha256, HashType::SaltedSha1, HashType::SaltedSha256, HashType::SaltedSha512, HashType::Postgresql, HashType::Pdf, HashType::Mysql41, HashType::Sha256d, HashType::Sha512d, HashType::Mssql05, HashType::Mssql12, HashType::HmacSha1, HashType::HmacSha256, HashType::Dcc, HashType::Dcc2, HashType::Ntlmv2, HashType::KeePass, HashType::SevenZip, HashType::Rar5];
    let password = "abc";
    let bench_duration = std::time::Duration::from_secs(3);

    ui::print_bench_header(bench_duration);

    let mut results: Vec<(&str, f64)> = Vec::new();

    for ht in &hash_types {
        let name = ht.name();
        print!("  {} {} ... ", "[*]".color(owo_colors::Rgb(0, 200, 255)), name.color(owo_colors::Rgb(0, 255, 100)));
        use std::io::{Write, stdout};
        stdout().flush().ok();

        let shader = ht.module().shader_source(&AttackModeType::BruteForce);
        if shader.is_empty() {
            let (test_hash, _) = ht.cpu_hash("password123", "");
            if test_hash == [0u32; 8] {
                eprintln!("{}", "(CPU-only, skipped)".color(owo_colors::Rgb(255, 200, 0)));
                continue;
            }
            let start = std::time::Instant::now();
            let iterations = 1000;
            for _ in 0..iterations {
                let _ = ht.cpu_hash("password123", "");
            }
            let elapsed = start.elapsed();
            let rate = iterations as f64 / elapsed.as_secs_f64();
            let _rate_str = if rate >= 1_000_000.0 {
                format!("{:>8.1} MH/s", rate / 1_000_000.0)
            } else if rate >= 1_000.0 {
                format!("{:>8.1} KH/s", rate / 1_000.0)
            } else {
                format!("{:>8.0} H/s  ", rate)
            };
            ui::print_bench_row(name, rate);
            results.push((name, rate));
            continue;
        }

        let (target_hash, target_hash_extra) = ht.cpu_hash(password, "");
        let attack_mode = AttackMode::BruteForce { password_len: 3 };
        let num_passwords = 62u32.pow(3);

        let mut gpu = pollster::block_on(gpu::GpuCracker::new(
            ht, attack_mode, target_hash, target_hash_extra,
            [0u32; 16], 0,
        ));

        if verbose {
            eprintln!("[verbose] {}: workgroup=128, num_passwords={}", name, num_passwords);
        }

        let start = std::time::Instant::now();
        let mut last_progress = 0u32;
        let mut total_hashes: u64 = 0;

        loop {
            gpu.poll();
            if let Some(data) = gpu.try_readback() {
                let elapsed = start.elapsed();
                let delta = data.progress.saturating_sub(last_progress);
                total_hashes += delta as u64;
                last_progress = data.progress;

                if elapsed >= bench_duration || data.progress >= num_passwords {
                    let secs = elapsed.as_secs_f64();
                    let hps = total_hashes as f64 / secs.max(0.001);
                    results.push((name, hps));
                    ui::print_bench_row(name, hps);
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    println!();
    ui::print_bench_footer(&results);
}
