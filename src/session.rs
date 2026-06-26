use std::path::PathBuf;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

static DEFAULT_SESSION_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".hashcracker").join("sessions")
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub hash_type: String,
    pub attack_mode: String,
    pub target_hash: String,
    pub salt: String,
    pub password_len: u32,
    pub keyspace: u64,
    pub progress: u64,
    pub mask: Option<String>,
    pub wordlist: Option<String>,
    pub rules_file: Option<String>,
    pub timestamp: String,
    pub cracked_hashes: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct Session {
    name: String,
    dir: PathBuf,
    state: Option<SessionState>,
}

impl Session {
    pub fn new(name: &str) -> Self {
        Session {
            name: name.to_string(),
            dir: DEFAULT_SESSION_DIR.clone(),
            state: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_dir(name: &str, dir: PathBuf) -> Self {
        Session {
            name: name.to_string(),
            dir,
            state: None,
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.join(format!("{}.json", self.name))
    }

    pub fn save(&self, state: &SessionState) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("Failed to create session dir: {}", e))?;
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| format!("Failed to serialize session: {}", e))?;
        std::fs::write(self.path(), json)
            .map_err(|e| format!("Failed to write session: {}", e))
    }

    pub fn load(&mut self) -> Result<SessionState, String> {
        let content = std::fs::read_to_string(self.path())
            .map_err(|e| format!("Failed to read session: {}", e))?;
        let state: SessionState = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse session: {}", e))?;
        self.state = Some(state.clone());
        Ok(state)
    }

    pub fn exists(&self) -> bool {
        self.path().exists()
    }

    pub fn delete(&self) -> Result<(), String> {
        if self.path().exists() {
            std::fs::remove_file(self.path())
                .map_err(|e| format!("Failed to delete session: {}", e))
        } else {
            Ok(())
        }
    }

    #[allow(dead_code)]
    pub fn state(&self) -> Option<&SessionState> {
        self.state.as_ref()
    }
}
