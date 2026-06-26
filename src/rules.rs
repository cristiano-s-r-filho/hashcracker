use std::path::Path;

#[derive(Debug, Clone)]
pub enum Rule {
    Lowercase,
    Uppercase,
    Capitalize,
    InvertCapitalize,
    ToggleAll,
    ToggleCase(usize),
    Append(char),
    Prepend(char),
    Insert(usize, char),
    Delete(usize),
    RemoveAll(char),
    RemoveFirst(char),
    RemoveLast(char),
    ReplaceAll(char, char),
    Overwrite(usize, char),
    Reverse,
    Duplicate,
    DuplicateN(usize),
    Reflect,
    RotateLeft,
    RotateRight,
    Extract(usize, usize),
    PassThrough,
}

impl Rule {
    pub fn apply(&self, word: &str) -> Vec<String> {
        let chars: Vec<char> = word.chars().collect();
        let len = chars.len();
        match self {
            Rule::Lowercase => vec![word.to_lowercase()],
            Rule::Uppercase => vec![word.to_uppercase()],
            Rule::Capitalize => {
                let mut s = String::new();
                for (i, c) in chars.iter().enumerate() {
                    if i == 0 {
                        s.extend(c.to_uppercase());
                    } else {
                        s.extend(c.to_lowercase());
                    }
                }
                vec![s]
            }
            Rule::InvertCapitalize => {
                let mut s = String::new();
                for (i, c) in chars.iter().enumerate() {
                    if i == 0 {
                        s.extend(c.to_lowercase());
                    } else {
                        s.extend(c.to_uppercase());
                    }
                }
                vec![s]
            }
            Rule::ToggleCase(pos) => {
                if *pos >= len {
                    return vec![word.to_string()];
                }
                let mut s: String = chars.iter().collect();
                let range = s.char_indices().nth(*pos).map(|(i, c)| (i, c)).unwrap();
                let c = range.1;
                let toggled: String = if c.is_uppercase() {
                    c.to_lowercase().collect()
                } else {
                    c.to_uppercase().collect()
                };
                s.replace_range(range.0..range.0 + c.len_utf8(), &toggled);
                vec![s]
            }
            Rule::ToggleAll => {
                let s: String = chars.iter().map(|c| {
                    let toggled: String = if c.is_uppercase() {
                        c.to_lowercase().collect()
                    } else {
                        c.to_uppercase().collect()
                    };
                    toggled
                }).collect();
                vec![s]
            }
            Rule::Append(c) => vec![format!("{}{}", word, c)],
            Rule::Prepend(c) => vec![format!("{}{}", c, word)],
            Rule::Insert(pos, c) => {
                let pos = *pos.min(&len);
                let mut s: String = chars[..pos].iter().collect();
                s.push(*c);
                s.extend(chars[pos..].iter());
                vec![s]
            }
            Rule::Delete(pos) => {
                if *pos >= len {
                    return vec![word.to_string()];
                }
                let mut s: String = chars.iter().collect();
                let idx = s.char_indices().nth(*pos).map(|(i, _)| i).unwrap();
                s.remove(idx);
                vec![s]
            }
            Rule::RemoveAll(c) => {
                let s: String = chars.iter().filter(|&ch| ch != c).collect();
                vec![s]
            }
            Rule::RemoveFirst(c) => {
                if let Some(pos) = chars.iter().position(|ch| ch == c) {
                    let mut s: String = chars.iter().collect();
                    let idx = s.char_indices().nth(pos).map(|(i, _)| i).unwrap();
                    s.remove(idx);
                    vec![s]
                } else {
                    vec![word.to_string()]
                }
            }
            Rule::RemoveLast(c) => {
                if let Some(pos) = chars.iter().rposition(|ch| ch == c) {
                    let mut s: String = chars.iter().collect();
                    let idx = s.char_indices().nth(pos).map(|(i, _)| i).unwrap();
                    s.remove(idx);
                    vec![s]
                } else {
                    vec![word.to_string()]
                }
            }
            Rule::ReplaceAll(old, new) => {
                let s: String = chars.iter().map(|ch| if ch == old { *new } else { *ch }).collect();
                vec![s]
            }
            Rule::Overwrite(pos, c) => {
                if *pos >= len {
                    return vec![word.to_string()];
                }
                let mut s: String = chars.iter().collect();
                let idx = s.char_indices().nth(*pos).map(|(i, _)| i).unwrap();
                s.remove(idx);
                s.insert(idx, *c);
                vec![s]
            }
            Rule::Reverse => {
                let s: String = chars.iter().rev().collect();
                vec![s]
            }
            Rule::Duplicate => vec![format!("{}{}", word, word)],
            Rule::DuplicateN(n) => vec![word.repeat(*n)],
            Rule::Reflect => {
                let rev: String = chars.iter().rev().collect();
                vec![format!("{}{}", word, rev)]
            }
            Rule::RotateLeft => {
                if len <= 1 { return vec![word.to_string()]; }
                let s: String = chars[1..].iter().chain(std::iter::once(&chars[0])).collect();
                vec![s]
            }
            Rule::RotateRight => {
                if len <= 1 { return vec![word.to_string()]; }
                let s: String = std::iter::once(&chars[len - 1]).chain(chars[..len - 1].iter()).collect();
                vec![s]
            }
            Rule::Extract(from, count) => {
                if *from >= chars.len() {
                    return vec![String::new()];
                }
                let end = (*from + *count).min(chars.len());
                let s: String = chars[*from..end].iter().collect();
                vec![s]
            }
            Rule::PassThrough => vec![word.to_string()],
        }
    }
}

fn parse_rule_token(token: &str) -> Option<Rule> {
    if token.is_empty() {
        return None;
    }
    let mut it = token.chars();
    let cmd = it.next().unwrap();
    let rest: String = it.collect();
    match cmd {
        ':' if rest.is_empty() => Some(Rule::PassThrough),
        'l' if rest.is_empty() => Some(Rule::Lowercase),
        'u' if rest.is_empty() => Some(Rule::Uppercase),
        'c' if rest.is_empty() => Some(Rule::Capitalize),
        'C' if rest.is_empty() => Some(Rule::InvertCapitalize),
        'r' if rest.is_empty() => Some(Rule::Reverse),
        'd' if rest.is_empty() => Some(Rule::Duplicate),
        'f' if rest.is_empty() => Some(Rule::Reflect),
        '{' if rest.is_empty() => Some(Rule::RotateLeft),
        '}' if rest.is_empty() => Some(Rule::RotateRight),
        'T' if rest.is_empty() => Some(Rule::ToggleAll),
        't' => {
            let n: usize = rest.parse().ok()?;
            Some(Rule::ToggleCase(n))
        }
        '$' => rest.chars().next().map(Rule::Append),
        '^' => rest.chars().next().map(Rule::Prepend),
        'D' => {
            let n: usize = rest.parse().ok()?;
            Some(Rule::Delete(n))
        }
        'p' => {
            let n: usize = rest.parse().ok()?;
            let n = n.max(1);
            Some(Rule::DuplicateN(n))
        }
        'x' => {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            let remainder: String = rest.chars().skip(digits.len()).collect();
            let from: usize = digits.parse().ok()?;
            let count: usize = remainder.parse().ok()?;
            Some(Rule::Extract(from, count))
        }
        'i' => {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            let remainder: String = rest.chars().skip(digits.len()).collect();
            let n: usize = digits.parse().ok()?;
            let c = remainder.chars().next()?;
            Some(Rule::Insert(n, c))
        }
        'o' => {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            let remainder: String = rest.chars().skip(digits.len()).collect();
            let n: usize = digits.parse().ok()?;
            let c = remainder.chars().next()?;
            Some(Rule::Overwrite(n, c))
        }
        's' => {
            let mut rchars = rest.chars();
            let old = rchars.next()?;
            let new = rchars.next()?;
            Some(Rule::ReplaceAll(old, new))
        }
        '@' => rest.chars().next().map(Rule::RemoveAll),
        'Z' => rest.chars().next().map(Rule::RemoveFirst),
        'z' => rest.chars().next().map(Rule::RemoveLast),
        _ => None,
    }
}

pub fn parse_rule_line(line: &str) -> Vec<Rule> {
    line.split_whitespace()
        .filter_map(parse_rule_token)
        .collect()
}

pub fn parse_rule_file(path: &Path) -> Vec<Vec<Rule>> {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Failed to read rules file '{}': {}", path.display(), e);
        std::process::exit(1);
    });
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(parse_rule_line)
        .filter(|r| !r.is_empty())
        .collect()
}

pub fn apply_rules(word: &str, rules: &[Vec<Rule>]) -> Vec<String> {
    if rules.is_empty() {
        return vec![word.to_string()];
    }
    let mut results = Vec::with_capacity(rules.len());
    for rule_sequence in rules {
        let mut current = word.to_string();
        let mut overflow = false;
        for rule in rule_sequence {
            let outputs = rule.apply(&current);
            if outputs.is_empty() {
                overflow = true;
                break;
            }
            current = outputs.into_iter().next().unwrap_or_default();
            if current.len() > 32 {
                overflow = true;
                break;
            }
        }
        if !overflow && !current.is_empty() && current.len() <= 32 {
            results.push(current);
        }
    }
    results
}
