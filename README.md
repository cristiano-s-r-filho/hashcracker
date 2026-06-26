# hashcracker

GPU-accelerated password cracker — 41 hash types, single binary, runs everywhere (Vulkan/Metal/DX12).

```text
  ╔══════════════════════════════════════════════════════╗
  ║                   hashcracker  v0.1                  ║
  ║        GPU-Accelerated Password Cracking             ║
  ║    41 hash types · Vulkan/Metal/DX12 · Single Binary ║
  ╚══════════════════════════════════════════════════════╝
```

## Features

- **41 hash types**: raw MD5/SHA-1/SHA-256/SHA-512, NTLM, bcrypt, md5crypt, sha256crypt, sha512crypt, phpass, KeePass, 7-Zip, RAR5, PBKDF2, HMAC variants, and more
- **GPU-accelerated**: 24 types with Vulkan compute shaders (wgpu) — auto-detects your GPU
- **CPU-only**: 17 types fall back to CPU wordlist mode — no kernel driver needed
- **Auto-detect**: hash type detected from format prefix (`$1$`, `$6$`, `$keepass$`, etc.) or hex length
- **Multi-target**: crack multiple hashes in a single GPU dispatch
- **Attack modes**: brute-force, mask, wordlist, hybrid (word+mask), PRINCE, Markov, single-crack
- **Rules**: hashcat-compatible `.rule` files with stacked rules support
- **Session save/resume**: interrupt and resume cracking with `--session`
- **Potfile**: automatic cracked-password database at `~/.hashcracker/potfile`
- **Extraction**: built-in `--extract pdf` / `--extract zip` to produce native hashes
- **Output**: human-readable colored terminal + machine-readable JSON (`--json`)
- **Portable**: single compiled binary, Vulkan/Metal/DX12 via wgpu — no CUDA/OpenCL driver install

## Install

### Cargo

```bash
cargo install hashcracker
```

### Homebrew

```bash
brew install anomalyco/tap/hashcracker
```

### Scoop

```powershell
scoop bucket add hashcracker https://github.com/anomalyco/scoop-hashcracker
scoop install hashcracker
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/anomalyco/hashcracker/releases).

## Usage

```bash
# Crack a raw MD5 hash (auto-detect)
hashcracker --hash e99a18c428cb38d5f260853678922e03

# Crack with wordlist + rules
hashcracker --hashlist hashes.txt --wordlist rockyou.txt --rules best64.rule

# Crack an md5crypt hash (auto-detected from $1$ prefix)
hashcracker --hash '$1$c$TEPt3Oo2oa8cNB9HQmta7/'

# Mask attack
hashcracker --hash e99a18c428cb38d5f260853678922e03 --mode mask --mask '?l?l?d?d?d'

# PRINCE mode
hashcracker --hash '$6$salt$hash...' --mode prince --prince-dict words.txt

# Extract + crack a ZIP file
hashcracker --extract zip archive.zip --wordlist rockyou.txt

# Session save/resume
hashcracker --hashlist hashes.txt --wordlist rockyou.txt --session myrun
hashcracker --hashlist hashes.txt --wordlist rockyou.txt --session myrun --restore

# Benchmark
hashcracker --bench

# Show cracked passwords
hashcracker --show

# Machine-readable JSON output
hashcracker --hashlist hashes.txt --wordlist rockyou.txt --json
```

## Supported Hash Types (41)

| # | Type | Hashcat mode | GPU | 
|---|------|-------------|-----|
| 1 | MD5 | 0 | ✓ |
| 2 | MD4 | 900 | ✓ |
| 3 | NTLM | 1000 | ✓ |
| 4 | SHA-1 | 100 | ✓ |
| 5 | SHA-224 | 1410 | ✓ |
| 6 | SHA-256 | 1400 | ✓ |
| 7 | SHA-384 | 10870 | ✓ |
| 8 | SHA-512 | 1700 | ✓ |
| 9 | SHA-256d (Bitcoin) | 1411 | ✓ |
| 10 | SHA-512d | 1412 | ✓ |
| 11 | MySQL 4.1 | 300 | ✓ |
| 12 | MSSQL 2005 | 132 | ✓ |
| 13 | MSSQL 2012 | 1731 | ✓ |
| 14 | HMAC-SHA1 | 150 | ✓ |
| 15 | HMAC-SHA256 | 1450 | ✓ |
| 16 | HMAC-SHA512 | 1750 | ✓ |
| 17 | md5crypt | 500 | ✓ |
| 18 | sha256crypt | 7400 | ✓ |
| 19 | sha512crypt | 1800 | ✓ |
| 20 | phpass (WordPress) | 400 | ✓ |
| 21 | Drupal 7 | 7900 | ✓ |
| 22 | bcrypt | 3200 | ✓ |
| 23 | Apache APR1 | 1600 | ✓ |
| 24 | PBKDF2-SHA256 | 10900 | ✓ |
| 25 | Salted SHA-1 | 120 | CPU |
| 26 | Salted SHA-256 | 1410 | CPU |
| 27 | Salted SHA-512 | 1710 | CPU |
| 28 | PostgreSQL | 11000 | CPU |
| 29 | DB2 | 8500 | CPU |
| 30 | CRC32 | 11500 | CPU |
| 31 | GRUB 2 | 7200 | CPU |
| 32 | DCC (MS Cache) | 1100 | CPU |
| 33 | DCC2 (MS Cache 2) | 2100 | CPU |
| 34 | NTLMv2 | 5600 | CPU |
| 35 | PDF | 10500/10700 | CPU |
| 36 | LM | 3000 | CPU |
| 37 | WPA/WPA2 PMKID | 16800 | CPU |
| 38 | PKZIP | 17200 | CPU |
| 39 | KeePass | 13400 | CPU |
| 40 | 7-Zip | 11600 | CPU |
| 41 | RAR5 | 13000 | CPU |

## Why hashcracker?

**hashcat** is the gold standard — 320+ types, hand-tuned kernels, decades of optimization.
hashcracker doesn't compete on speed or hash count.

It wins on:
- **Portability**: one binary, Vulkan/Metal/DX12, no driver install
- **Memory safety**: Rust — the class of CVEs that hit hashcat (3 CVSS 9.8 in 2025-2026) can't exist
- **CI-ready**: JSON output, session save/resume, consistent exit codes
- **Extraction built in**: `--extract pdf` / `--extract zip` instead of `keepass2john || pdf2john || zip2john`
- **Zero setup**: `cargo install hashcracker` and it works

## License

MIT
