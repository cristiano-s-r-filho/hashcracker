use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

static DEFAULT_POTFILE: LazyLock<PathBuf> = LazyLock::new(|| {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".hashcracker").join("potfile")
});

#[derive(Debug, Clone)]
pub struct Potfile {
    path: PathBuf,
    entries: Vec<(String, String)>, // (hash, password)
    cracked: HashSet<String>,       // set of hash strings already cracked
}

impl Potfile {
    pub fn new() -> Self {
        Self::with_path(DEFAULT_POTFILE.clone())
    }

    pub fn with_path(path: PathBuf) -> Self {
        let mut pf = Potfile {
            path,
            entries: Vec::new(),
            cracked: HashSet::new(),
        };
        let _ = pf.load();
        pf
    }

    pub fn load(&mut self) -> Result<(), String> {
        let content = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("Failed to read potfile: {}", e)),
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((hash, password)) = line.split_once(':') {
                let hash = hash.trim().to_string();
                let password = password.trim().to_string();
                self.entries.push((hash.clone(), password));
                self.cracked.insert(hash);
            }
        }
        Ok(())
    }

    pub fn is_cracked(&self, hash_hex: &str) -> bool {
        let clean = hash_hex.trim().strip_prefix("0x").unwrap_or(hash_hex.trim());
        self.cracked.contains(clean)
    }

    #[allow(dead_code)]
    pub fn get_password(&self, hash_hex: &str) -> Option<&str> {
        let clean = hash_hex.trim().strip_prefix("0x").unwrap_or(hash_hex.trim());
        self.entries.iter()
            .find(|(h, _)| h == clean)
            .map(|(_, p)| p.as_str())
    }

    pub fn record_crack(&mut self, hash_hex: &str, password: &str) {
        let clean = hash_hex.trim().strip_prefix("0x").unwrap_or(hash_hex.trim());
        if !self.cracked.contains(clean) {
            self.entries.push((clean.to_string(), password.to_string()));
            self.cracked.insert(clean.to_string());
        }
    }

    pub fn save(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create potfile directory: {}", e))?;
        }
        let content: String = self.entries.iter()
            .map(|(h, p)| format!("{}:{}\n", h, p))
            .collect();
        std::fs::write(&self.path, content)
            .map_err(|e| format!("Failed to write potfile: {}", e))
    }

    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(&self) -> &[(String, String)] {
        &self.entries
    }
}

impl Default for Potfile {
    fn default() -> Self {
        Self::new()
    }
}
