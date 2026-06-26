use std::sync::LazyLock;
use crate::hashes::HashModule;
use crate::hashes::raw_apr1::RawApr1;
use crate::hashes::raw_bcrypt::RawBcrypt;
use crate::hashes::raw_crc32::RawCrc32;
use crate::hashes::raw_db2::RawDb2;
use crate::hashes::raw_dcc::RawDcc;
use crate::hashes::raw_dcc2::RawDcc2;
use crate::hashes::raw_drupal7::RawDrupal7;
use crate::hashes::raw_grub2::RawGrub2;
use crate::hashes::raw_hmac_sha1::RawHmacSha1;
use crate::hashes::raw_hmac_sha256::RawHmacSha256;
use crate::hashes::raw_hmac_sha512::RawHmacSha512;
use crate::hashes::raw_lm::RawLm;
use crate::hashes::raw_md4::RawMd4;
use crate::hashes::raw_md5::RawMd5;
use crate::hashes::raw_md5crypt::RawMd5Crypt;
use crate::hashes::raw_mssql05::RawMssql05;
use crate::hashes::raw_mssql12::RawMssql12;
use crate::hashes::raw_mysql41::RawMysql41;
use crate::hashes::raw_ntlm::RawNtlm;
use crate::hashes::raw_ntlmv2::RawNtlmv2;
use crate::hashes::raw_pbkdf2_sha256::RawPbkdf2Sha256;
use crate::hashes::raw_pdf::RawPdf;
use crate::hashes::raw_phpass::RawPhpass;
use crate::hashes::raw_pkzip::RawPkzip;
use crate::hashes::raw_postgresql::RawPostgresql;
use crate::hashes::raw_salted::{RawSaltedSha1, RawSaltedSha256, RawSaltedSha512};
use crate::hashes::raw_sha1::RawSha1;
use crate::hashes::raw_sha224::RawSha224;
use crate::hashes::raw_sha256::RawSha256;
use crate::hashes::raw_sha256crypt::RawSha256Crypt;
use crate::hashes::raw_sha256d::RawSha256d;
use crate::hashes::raw_sha384::RawSha384;
use crate::hashes::raw_sha512::RawSha512;
use crate::hashes::raw_sha512crypt::RawSha512Crypt;
use crate::hashes::raw_sha512d::RawSha512d;
use crate::hashes::raw_7z::RawSevenZip;
use crate::hashes::raw_keepass::RawKeePass;
use crate::hashes::raw_rar5::RawRar5;
use crate::hashes::raw_wpa::RawWpa;

static HASH_MODULES: LazyLock<Vec<Box<dyn HashModule>>> = LazyLock::new(|| {
    vec![
        Box::new(RawApr1),
        Box::new(RawBcrypt),
        Box::new(RawCrc32),
        Box::new(RawDb2),
        Box::new(RawDcc),
        Box::new(RawDcc2),
        Box::new(RawDrupal7),
        Box::new(RawGrub2),
        Box::new(RawHmacSha1),
        Box::new(RawHmacSha256),
        Box::new(RawHmacSha512),
        Box::new(RawLm),
        Box::new(RawMd4),
        Box::new(RawMd5),
        Box::new(RawMd5Crypt),
        Box::new(RawMssql05),
        Box::new(RawMssql12),
        Box::new(RawMysql41),
        Box::new(RawNtlm),
        Box::new(RawNtlmv2),
        Box::new(RawPbkdf2Sha256),
        Box::new(RawPdf),
        Box::new(RawPhpass),
        Box::new(RawPkzip),
        Box::new(RawPostgresql),
        Box::new(RawSaltedSha1),
        Box::new(RawSaltedSha256),
        Box::new(RawSaltedSha512),
        Box::new(RawSha1),
        Box::new(RawSha224),
        Box::new(RawSha256),
        Box::new(RawSha256Crypt),
        Box::new(RawSha256d),
        Box::new(RawSha384),
        Box::new(RawSha512),
        Box::new(RawSha512Crypt),
        Box::new(RawSha512d),
        Box::new(RawWpa),
        Box::new(RawKeePass),
        Box::new(RawSevenZip),
        Box::new(RawRar5),
    ]
});

#[allow(dead_code)]
pub fn all_modules() -> &'static Vec<Box<dyn HashModule>> {
    &HASH_MODULES
}

pub fn find_by_name(name: &str) -> Option<&'static dyn HashModule> {
    let lower = name.to_lowercase();
    let normalized = lower.replace('-', "");
    HASH_MODULES.iter().find(|m| {
        let mname = m.name().to_lowercase().replace('-', "");
        mname == normalized
    }).map(|b| b.as_ref())
}

pub fn find_by_prefix(s: &str) -> Vec<&'static dyn HashModule> {
    let mut results: Vec<&'static dyn HashModule> = HASH_MODULES
        .iter()
        .filter(|m| {
            m.detect_patterns().iter().any(|p| {
                p.prefix.map_or(false, |pre| s.starts_with(pre))
            })
        })
        .map(|b| b.as_ref())
        .collect();
    results.sort_by_key(|m| {
        m.detect_patterns().iter().map(|p| p.priority).min().unwrap_or(255)
    });
    results
}

pub fn find_by_hex_len(len: usize) -> Vec<&'static dyn HashModule> {
    let mut results: Vec<&'static dyn HashModule> = HASH_MODULES
        .iter()
        .filter(|m| {
            m.detect_patterns().iter().any(|p| {
                p.hex_len.map_or(false, |h| h == len)
            })
        })
        .map(|b| b.as_ref())
        .collect();
    results.sort_by_key(|m| {
        m.detect_patterns().iter().map(|p| p.priority).min().unwrap_or(255)
    });
    results
}

fn find_salted_by_hex_len(len: usize) -> Option<&'static dyn HashModule> {
    let module: Option<&'static dyn HashModule> = match len {
        40 => Some(&RawSaltedSha1),
        64 => Some(&RawSaltedSha256),
        128 => Some(&RawSaltedSha512),
        _ => None,
    };
    module
}

pub fn autodetect(s: &str) -> Option<&'static dyn HashModule> {
    let trimmed = s.trim();
    let prefix_results = find_by_prefix(trimmed);
    if !prefix_results.is_empty() {
        return Some(prefix_results[0]);
    }

    if let Some(colon_pos) = trimmed.find(':') {
        let hash_part = &trimmed[..colon_pos];
        let clean_hash = hash_part.strip_prefix("0x").unwrap_or(hash_part);
        if clean_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            let salted = find_salted_by_hex_len(clean_hash.len());
            if salted.is_some() {
                return salted;
            }
            let hex_results = find_by_hex_len(clean_hash.len());
            if !hex_results.is_empty() {
                return Some(hex_results[0]);
            }
        }
    }

    let clean = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if clean.chars().all(|c| c.is_ascii_hexdigit()) {
        let hex_results = find_by_hex_len(clean.len());
        if !hex_results.is_empty() {
            return Some(hex_results[0]);
        }
    }
    None
}
