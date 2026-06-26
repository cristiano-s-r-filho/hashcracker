use std::process::Command;
use std::path::PathBuf;

/// Path to the compiled hashcracker binary
fn hashcracker_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hashcracker"))
}

/// Helper: run hashcracker with args, return (stdout, stderr, success)
fn run(args: &[&str]) -> (String, String, bool) {
    let bin = hashcracker_bin();
    let output = Command::new(&bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("Failed to run {:?}: {}", bin, e));
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.success(),
    )
}

#[test]
fn test_help_exits_success() {
    let (stdout, _stderr, success) = run(&["--help"]);
    assert!(success);
    assert!(stdout.contains("Usage"));
    assert!(stdout.contains("hashcracker"));
}

#[test]
fn test_version_exits_success() {
    let (stdout, _stderr, success) = run(&["--version"]);
    assert!(success);
    assert!(!stdout.is_empty());
}

#[test]
fn test_stdout_mode_brute() {
    // --stdout generates candidates without GPU; --hash-type needed for entry setup
    let (stdout, _stderr, success) = run(&[
        "--mode", "brute",
        "--hash-type", "md5",
        "--stdout",
        "--quiet",
    ]);
    assert!(success);
    assert!(stdout.contains("a"), "Expected 'a' in stdout output");
}

#[test]
fn test_stdout_mode_mask() {
    let (stdout, _stderr, success) = run(&[
        "--mode", "mask",
        "--mask", "?l?l",
        "--hash-type", "md5",
        "--stdout",
        "--quiet",
    ]);
    assert!(success);
    assert!(stdout.contains("aa"));
    assert!(stdout.contains("ab"));
}

#[test]
fn test_cpu_wordlist_fallback_crc32() {
    // CRC32 is CPU-only (no GPU shader).
    // Wordlist filter requires words <= 4 chars.
    // CRC32("abcd") = 0xed82cd11
    use std::io::Write;
    let mut tmp = tempfile::NamedTempFile::new().expect("Create temp file");
    writeln!(tmp.as_file(), "abcd").expect("Write test word");
    let (stdout, stderr, success) = run(&[
        "--hash", "ed82cd11",
        "--hash-type", "crc32",
        "--mode", "wordlist",
        "--wordlist", tmp.path().to_str().unwrap(),
        "--quiet",
    ]);
    assert!(success, "CRC32 should crack 'abcd'. Stderr: {}", stderr);
}
