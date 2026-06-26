#[derive(Debug, Clone)]
pub enum Filter {
    MinLen(usize),
    MaxLen(usize),
    HasUpper,
    HasLower,
    HasDigit,
    HasSpecial,
    NoRepeats,
    MinClasses(u8),
}

impl Filter {
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(n) = s.strip_prefix("min-len=") {
            let v = n.parse::<usize>().map_err(|_| format!("Invalid min-len value '{}'", n))?;
            Ok(Filter::MinLen(v))
        } else if let Some(n) = s.strip_prefix("max-len=") {
            let v = n.parse::<usize>().map_err(|_| format!("Invalid max-len value '{}'", n))?;
            Ok(Filter::MaxLen(v))
        } else if let Some(n) = s.strip_prefix("min-classes=") {
            let v = n.parse::<u8>().map_err(|_| format!("Invalid min-classes value '{}'", n))?;
            if v > 4 {
                return Err(format!("min-classes must be 0-4, got {}", v));
            }
            Ok(Filter::MinClasses(v))
        } else {
            match s {
                "has-upper" => Ok(Filter::HasUpper),
                "has-lower" => Ok(Filter::HasLower),
                "has-digit" => Ok(Filter::HasDigit),
                "has-special" => Ok(Filter::HasSpecial),
                "no-repeats" => Ok(Filter::NoRepeats),
                _ => Err(format!("Unknown filter '{}'. Options: min-len=N, max-len=N, has-upper, has-lower, has-digit, has-special, no-repeats, min-classes=N", s)),
            }
        }
    }

    pub fn apply(&self, candidate: &str) -> bool {
        match self {
            Filter::MinLen(n) => candidate.len() >= *n,
            Filter::MaxLen(n) => candidate.len() <= *n,
            Filter::HasUpper => candidate.chars().any(|c| c.is_uppercase()),
            Filter::HasLower => candidate.chars().any(|c| c.is_lowercase()),
            Filter::HasDigit => candidate.chars().any(|c| c.is_ascii_digit()),
            Filter::HasSpecial => candidate.chars().any(|c| !c.is_alphanumeric()),
            Filter::NoRepeats => {
                let mut prev: Option<char> = None;
                for c in candidate.chars() {
                    if Some(c) == prev { return false; }
                    prev = Some(c);
                }
                true
            }
            Filter::MinClasses(n) => {
                let mut classes = 0u8;
                if candidate.chars().any(|c| c.is_uppercase()) { classes += 1; }
                if candidate.chars().any(|c| c.is_lowercase()) { classes += 1; }
                if candidate.chars().any(|c| c.is_ascii_digit()) { classes += 1; }
                if candidate.chars().any(|c| !c.is_alphanumeric()) { classes += 1; }
                classes >= *n
            }
        }
    }
}

pub fn parse_filters(filters: &[String]) -> Vec<Filter> {
    filters.iter().map(|s| Filter::parse(s).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    })).collect()
}

pub fn apply_filters(candidate: &str, filters: &[Filter]) -> bool {
    filters.iter().all(|f| f.apply(candidate))
}
