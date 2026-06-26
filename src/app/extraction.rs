use crate::hash_backend::{HashType, full_hash_slice};

pub fn handle_extraction(args: &crate::cli::Args, extract_type: &str) {
    match extract_type {
        "pdf" => {
            let password = args.password.as_deref().unwrap_or("");
            let file = if let Some(hash) = &args.hash {
                hash.clone()
            } else {
                eprintln!("Error: --extract pdf requires a PDF file path as --hash argument");
                std::process::exit(1);
            };
            if password.is_empty() {
                match crate::pdf_extract::extract_pdf_hash(&file) {
                    Ok(hash_str) => println!("{}", hash_str),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                match crate::pdf_extract::extract_pdf_hash(&file) {
                    Ok(hash_str) => {
                        println!("{}", hash_str);
                        let parsed = HashType::Pdf.module().parse_hash_string(&hash_str)
                            .expect("Failed to parse extracted hash");
                        let salt = &parsed.salt;
                        let dw = HashType::Pdf.module().digest_words() as usize;
                            let full = full_hash_slice(&parsed, dw);
                        if HashType::Pdf.module().cpu_verify(password, salt, &full[..dw]) {
                            eprintln!("✅ Password '{}' is correct", password);
                        } else {
                            eprintln!("❌ Password '{}' is INCORRECT", password);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
        "zip" => {
            let password = args.password.as_deref().unwrap_or("");
            let file = if let Some(hash) = &args.hash {
                hash.clone()
            } else {
                eprintln!("Error: --extract zip requires a ZIP file path as --hash argument");
                std::process::exit(1);
            };
            if password.is_empty() {
                match crate::zip_extract::extract_zip_hashes(&file) {
                    Ok(hashes) => {
                        for zh in &hashes {
                            println!("{}:{}", zh.filename, zh.hash_string);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                match crate::zip_extract::extract_zip_hashes(&file) {
                    Ok(hashes) => {
                        for zh in &hashes {
                            println!("{}:{}", zh.filename, zh.hash_string);
                            eprintln!("Verifying password '{}' against entry '{}'...", password, zh.filename);
                            let parsed = HashType::Pkzip.module().parse_hash_string(&zh.hash_string)
                                .expect("Failed to parse extracted pkzip hash");
                            let dw = HashType::Pkzip.module().digest_words() as usize;
                        let full = full_hash_slice(&parsed, dw);
                            if HashType::Pkzip.module().cpu_verify(password, &parsed.salt, &full[..dw]) {
                                eprintln!("✅ Password '{}' is correct for '{}'", password, zh.filename);
                            } else {
                                eprintln!("❌ Password '{}' is INCORRECT for '{}'", password, zh.filename);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
        _ => {
            eprintln!("Error: unsupported extraction type '{}'. Supported: pdf, zip", extract_type);
            std::process::exit(1);
        }
    }
}
