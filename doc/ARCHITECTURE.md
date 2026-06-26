# hashcracker Architecture

## Vision

Beat **John the Ripper** on feature coverage, UX, memory safety, and cross-platform support — while accepting that **hashcat** dominates on raw GPU throughput.

| vs | John the Ripper | hashcat |
|----|----------------|---------|
| GPU-native for all hash types | ✅ (wgpu) | ✅ (CUDA/OpenCL) |
| Memory safety | ✅ (Rust) | ❌ (C) | ❌ (C) |
| Cross-platform (Win/Mac/Linux) | ✅ (wgpu) | ❌ (Linux-only GPU) | ✅ |
| Hash type count (target) | **40+** | 400+ | 450+ |
| Single-binary (no 2john) | ✅ | ❌ | ✅ |
| Modern CLI / progress bars | ✅ | ❌ | ❌ |
| Raw throughput | adequate | slow (CPU) | **maximal** |
| Rule engine | ✅ (CPU+GPU) | ✅ | ✅ (in-kernel) |

## Design Principles

1. **Everything is GPU-native.** Every hash type gets a WGSL kernel. No fallback to CPU hashing.
2. **Hash module is a trait.** Adding a new hash = implement a trait + write a WGSL shader + add detection pattern.
3. **No external tools.** Hash extraction from files is built-in (no 2john, no zip2john, etc.).
4. **Sessions are transparent.** Save/restore, potfile, show/left all work out of the box.
5. **CLI-first, but scriptable.** Rich terminal output by default, `--json` for machine parsing.
6. **No unsafe Rust.** All GPU communication through safe wgpu abstractions.

## Module Map

```
hashcracker/
├── src/
│   ├── main.rs               # CLI entry, dispatch loop
│   ├── cli.rs                # Clap argument definitions
│   ├── session.rs            # Save/restore, potfile, show/left
│   │
│   ├── hashes/               # Hash type modules
│   │   ├── mod.rs            # HashModule trait + registry
│   │   ├── raw_md5.rs        # MD5 (hashcat -m 0)
│   │   ├── raw_sha1.rs       # SHA-1 (hashcat -m 100)
│   │   ├── raw_sha256.rs     # SHA-256 (hashcat -m 1400)
│   │   ├── raw_sha512.rs     # SHA-512 (hashcat -m 1700)
│   │   ├── ntlm.rs           # NTLM (hashcat -m 1000)
│   │   ├── md5crypt.rs       # $1$ (hashcat -m 500)
│   │   ├── sha256crypt.rs    # $5$ (hashcat -m 7400)
│   │   ├── sha512crypt.rs    # $6$ (hashcat -m 1800)
│   │   ├── bcrypt.rs         # $2b$ (hashcat -m 3200)
│   │   ├── phpass.rs         # $P$/Drupal7 $S$ (hashcat -m 400)
│   │   ├── raw_md4.rs        # MD4 (hashcat -m 900)
│   │   ├── pbkdf2_hmac.rs    # PBKDF2-HMAC-SHA256/SHA512
│   │   ├── sha1_salted.rs    # sha1($pass.$salt) style
│   │   └── detect.rs         # Auto-detection by prefix + length
│   │
│   ├── attack/               # Attack modes
│   │   ├── mod.rs            # AttackMode trait
│   │   ├── brute.rs          # Brute-force (base-N encoding)
│   │   ├── mask.rs           # Mask attack (?l?u?d pattern)
│   │   ├── wordlist.rs       # Dictionary attack
│   │   ├── hybrid.rs         # Wordlist + mask
│   │   ├── prince.rs         # PRINCE mode (word combinations)
│   │   ├── markov.rs         # Markov-chain incremental
│   │   ├── single.rs         # Single crack (metadata-based)
│   │   └── external.rs       # External filter/custom generator
│   │
│   ├── gpu/                  # GPU pipeline
│   │   ├── mod.rs            # GpuCracker abstraction
│   │   ├── dispatch.rs       # Workgroup sizing, dispatch loops
│   │   ├── pipeline.rs       # Pipeline compilation + caching
│   │   ├── buffer.rs         # Buffer management
│   │   └── shaders/          # WGSL shaders (one per hash × mode)
│   │       ├── md5/
│   │       │   ├── brute.wgsl
│   │       │   ├── mask.wgsl
│   │       │   └── wordlist.wgsl
│   │       ├── sha1/
│   │       │   ├── brute.wgsl
│   │       │   ├── mask.wgsl
│   │       │   └── wordlist.wgsl
│   │       ├── sha256/
│   │       ├── sha512/
│   │       ├── ntlm/
│   │       └── ...
│   │
│   ├── engine/               # Rule engine & candidate generation
│   │   ├── mod.rs
│   │   ├── rules.rs          # Rule parsing + application (moved from src/)
│   │   └── charset.rs        # Charset handling
│   │
│   ├── extract/              # Hash extraction from files (2john replacement)
│   │   ├── mod.rs
│   │   ├── zip.rs            # ZIP extraction
│   │   ├── pdf.rs            # PDF extraction
│   │   ├── office.rs         # Office documents
│   │   └── shadow.rs         # /etc/shadow parsing
│   │
│   └── ui/                   # Terminal output
│       ├── mod.rs
│       ├── progress.rs       # Progress bar + ETA
│       └── format.rs         # Table rendering, JSON output
```

## Core Abstractions

### `HashModule` trait

```rust
trait HashModule: Send + Sync {
    /// Unique identifier (e.g., "raw-md5", "bcrypt")
    fn name(&self) -> &'static str;

    /// hashcat-compatible mode number
    fn mode(&self) -> u32;

    /// Number of u32 words in the hash output
    fn digest_words(&self) -> u32;

    /// Verify a password against a hash on CPU
    fn cpu_verify(&self, password: &str, salt: &[u8], hash: &[u32]) -> bool;

    /// WGSL source for a given attack mode
    fn shader_source(&self, mode: &AttackModeType) -> &'static str;

    /// Does this hash require SHADER_INT64?
    fn needs_int64(&self) -> bool { false }

    /// Parsed hash representation (salt, rounds, hash bytes)
    fn parse_hash_string(&self, s: &str) -> Result<ParsedHash, ParseError>;

    /// Auto-detection signature
    fn detect_pattern(&self) -> &[HashPattern];
}
```

### `AttackMode` trait

```rust
trait AttackMode: Send + Sync {
    fn name(&self) -> &'static str;
    fn total_keyspace(&self) -> u64;
    fn keyspace_remaining(&self, progress: u32) -> u64;
    fn generate_candidates(&self, offset: u64, count: u64) -> Vec<Vec<u8>>;

    /// For modes that generate on-GPU (brute-force, mask)
    fn gpu_config(&self) -> GpuConfig;
    fn uses_word_buffer(&self) -> bool;
}
```

### Session lifecycle

```
── Startup ──→ Load potfile ──→ Filter already-cracked
    ↓
  Load hashes ──→ Auto-detect type ──→ Validate
    ↓
  Choose attack ──→ Restore checkpoint (if exists)
    ↓
  ┌─────────────────────────────────────────┐
  │  Dispatch GPU ←→ Poll progress (50ms)   │
  │    ↓ Found? → Write potfile             │
  │    ↓ Interrupt? → Save session          │
  │    ↓ Keyspace done? → Next mode/exit    │
  └─────────────────────────────────────────┘
    ↓
  Show summary ──→ Print uncracked ──→ Exit
```

## Hash Auto-Detection

Priority-ordered detection rules:

1. **Prefix match** (`$1$`, `$6$`, `$2b$`, `$argon2id$`, etc.) → immediate type
2. **Length + charset** (32 hex = MD5/NTLM/MD4 ambiguous; suggest and pick most common)
3. **User override** via `--hash-type` always wins
4. **Ambiguity resolution**: for 32-hex-char, try MD5 first (most common), fall back to NTLM

## Phases

### Phase 1: Foundation (current → next week)
- [x] 4 core hash types (MD5, SHA-1, SHA-256, SHA-512)
- [x] GPU pipeline (wgpu)
- [x] Brute-force, mask, wordlist, hybrid modes
- [x] Rule engine (CPU-side)
- [ ] **Refactor to trait-based system**
- [ ] **Potfile implementation**
- [ ] **Session save/restore**

### Phase 2: Hash Explosion (week 2-3)
- [ ] NTLM, MD4
- [ ] md5crypt (`$1$`)
- [ ] sha256crypt (`$5$`), sha512crypt (`$6$`)
- [ ] bcrypt (`$2a$`/`$2b$`/`$2y$`)
- [ ] phpass/WordPress (`$P$`)
- [ ] Drupal 7 (`$S$`)
- [ ] Salted variants (sha1($pass.$salt), sha256($salt.$pass), etc.)
- [ ] PBKDF2-HMAC-SHA256

### Phase 3: Attack Modes (week 3-4)
- [ ] PRINCE mode
- [ ] Markov-chain incremental
- [ ] Single crack mode
- [ ] External filters
- [ ] Rules-stack (`--rules-stack`)

### Phase 4: UX (week 4-5)
- [ ] Progress bar with ETA (indicatif)
- [ ] JSON output mode
- [ ] Quiet mode
- [ ] Color-coded status line (inspired by hashcat)
- [ ] `--show` / `--show=left`
- [ ] Benchmark (improved, per-hash)
- [ ] `--stdout` mode (generate candidates without cracking)

### Phase 5: Extraction (week 5-6)
- [ ] ZIP hash extraction (compatible with hashcat -m 17200/17210)
- [ ] PDF hash extraction
- [ ] /etc/shadow parsing
- [ ] Office document extraction

### Phase 6: Performance (week 6-8)
- [ ] Multi-GPU (one device per thread)
- [ ] LDS-optimized kernels
- [ ] Auto-tuned workgroup sizes
- [ ] Overlapped dispatch (double-buffered)
