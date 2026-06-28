const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/`~ ";
const MAX_LEN: usize = 32;

pub struct MarkovModel {
    transition: [[f64; 256]; 256],
    start: [f64; 256],
    chars: Vec<u8>,
}

impl MarkovModel {
    pub fn train(passwords: &[String]) -> Self {
        let mut counts = [[0u64; 256]; 256];
        let mut start_counts = [0u64; 256];
        let mut present = [false; 256];

        for pw in passwords {
            let bytes = pw.as_bytes();
            if bytes.is_empty() { continue; }
            let first = bytes[0] as usize;
            start_counts[first] += 1;
            present[first] = true;

            for i in 0..bytes.len() - 1 {
                let c1 = bytes[i] as usize;
                let c2 = bytes[i + 1] as usize;
                counts[c1][c2] += 1;
                present[c2] = true;
            }
        }

        let mut transition = [[0.0f64; 256]; 256];
        let mut start = [0.0f64; 256];

        for c1 in 0..256 {
            let total: u64 = counts[c1].iter().sum();
            if total > 0 {
                for c2 in 0..256 {
                    transition[c1][c2] = counts[c1][c2] as f64 / total as f64;
                }
            }
        }

        let start_total: u64 = start_counts.iter().sum();
        if start_total > 0 {
            for c in 0..256 {
                start[c] = start_counts[c] as f64 / start_total as f64;
            }
        }

        let mut chars = Vec::new();
        for c in 0..256 {
            if present[c] {
                chars.push(c as u8);
            }
        }
        if chars.is_empty() {
            chars = CHARSET.to_vec();
            for c in 0..256 {
                start[c] = 1.0 / 256.0;
                for c2 in 0..256 {
                    transition[c][c2] = 1.0 / 256.0;
                }
            }
        }

        MarkovModel { transition, start, chars }
    }

    pub fn generate(&self, max_len: usize, max_candidates: usize) -> Vec<String> {
        let max_len = max_len.min(MAX_LEN);
        let mut results = Vec::new();

        let mut start_chars: Vec<u8> = self.chars.clone();
        start_chars.sort_by(|a, b| {
            self.start[*b as usize].partial_cmp(&self.start[*a as usize]).unwrap_or(std::cmp::Ordering::Equal)
        });

        for &first in &start_chars {
            if results.len() >= max_candidates { break; }
            let mut current = vec![first];
            self.dfs_generate(&mut current, max_len, max_candidates, &mut results);
        }

        results
    }

    fn dfs_generate(&self, current: &mut Vec<u8>, max_len: usize, max_candidates: usize, results: &mut Vec<String>) {
        if results.len() >= max_candidates { return; }

        if current.len() >= 1 {
            if let Ok(s) = String::from_utf8(current.clone()) {
                results.push(s);
            }
        }

        if current.len() >= max_len { return; }

        let last = *current.last().unwrap() as usize;

        let mut followers: Vec<u8> = self.chars.clone();
        followers.sort_by(|a, b| {
            self.transition[last][*b as usize].partial_cmp(&self.transition[last][*a as usize])
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for &next in &followers {
            if results.len() >= max_candidates { break; }
            if self.transition[last][next as usize] <= 0.0 { continue; }
            current.push(next);
            self.dfs_generate(current, max_len, max_candidates, results);
            current.pop();
        }
    }
}
