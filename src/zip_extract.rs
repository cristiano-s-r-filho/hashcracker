
pub struct ZipEncryptedEntry {
    pub filename: String,
    pub compression_method: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub encrypted_data: Vec<u8>,
}

pub struct ZipHash {
    pub hash_string: String,
    pub filename: String,
}

pub fn extract_zip_hashes(path: &str) -> Result<Vec<ZipHash>, String> {
    let data = std::fs::read(path).map_err(|e| format!("Cannot read {}: {}", path, e))?;
    let entries = find_encrypted_entries(&data)?;
    if entries.is_empty() {
        return Err("No encrypted entries found in ZIP file".to_string());
    }

    Ok(entries
        .into_iter()
        .map(|e| ZipHash {
            hash_string: format_pkzip_hash(&e),
            filename: e.filename,
        })
        .collect())
}

fn format_pkzip_hash(entry: &ZipEncryptedEntry) -> String {
    let crc_dec = entry.crc32;
    let comp_size_dec = entry.compressed_size;
    let mode = if entry.compression_method == 0 {
        0u32
    } else {
        1u32
    };

    let data_len = entry.encrypted_data.len();

    let magic_start = if data_len >= 12 { data_len - 12 } else { 0 };
    let main_data = &entry.encrypted_data[..magic_start];
    let magic_bytes = &entry.encrypted_data[magic_start..];

    format!(
        "$pkzip$2*1*{}*0*{}*{}*{}*0*0*0*0*0*0*0*0*0*{}*$/pkzip$",
        mode,
        crc_dec,
        comp_size_dec,
        hex::encode(main_data),
        hex::encode(magic_bytes),
    )
}

fn find_eocd(data: &[u8]) -> Result<usize, String> {
    let min_eocd = 22;
    if data.len() < min_eocd {
        return Err("File too small to be a valid ZIP archive".to_string());
    }
    let search_start = if data.len() > 65557 + min_eocd {
        data.len() - 65557 - min_eocd
    } else {
        0
    };
    for i in (search_start..data.len() - min_eocd + 1).rev() {
        if &data[i..i + 4] == b"PK\x05\x06" {
            return Ok(i);
        }
    }
    Err("Could not find End of Central Directory record".to_string())
}

fn find_encrypted_entries(data: &[u8]) -> Result<Vec<ZipEncryptedEntry>, String> {
    let eocd_pos = find_eocd(data)?;

    let cd_offset = u32::from_le_bytes(
        data[eocd_pos + 16..eocd_pos + 20]
            .try_into()
            .map_err(|_| "Invalid EOCD offset")?,
    ) as usize;
    let cd_entries = u16::from_le_bytes(
        data[eocd_pos + 10..eocd_pos + 12]
            .try_into()
            .map_err(|_| "Invalid EOCD entry count")?,
    );

    if cd_offset >= data.len() {
        return Err("Invalid central directory offset".to_string());
    }

    let mut entries = Vec::new();
    let mut pos = cd_offset;

    for _ in 0..cd_entries {
        if pos + 46 > data.len() {
            break;
        }
        if &data[pos..pos + 4] != b"PK\x01\x02" {
            break;
        }

        let bit_flag = u16::from_le_bytes(data[pos + 8..pos + 10].try_into().unwrap());
        let compression = u16::from_le_bytes(data[pos + 10..pos + 12].try_into().unwrap());
        let crc32 = u32::from_le_bytes(data[pos + 16..pos + 20].try_into().unwrap());
        let comp_size = u32::from_le_bytes(data[pos + 20..pos + 24].try_into().unwrap());
        let _uncomp_size = u32::from_le_bytes(data[pos + 24..pos + 28].try_into().unwrap());
        let filename_len = u16::from_le_bytes(data[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(data[pos + 30..pos + 32].try_into().unwrap()) as usize;
        let comment_len = u16::from_le_bytes(data[pos + 32..pos + 34].try_into().unwrap()) as usize;
        let local_offset =
            u32::from_le_bytes(data[pos + 42..pos + 46].try_into().unwrap()) as usize;

        let filename = if pos + 46 + filename_len <= data.len() {
            String::from_utf8_lossy(&data[pos + 46..pos + 46 + filename_len]).to_string()
        } else {
            String::new()
        };

        let is_encrypted = (bit_flag & 1) != 0;
        let is_strong = (bit_flag & 0x20) != 0;
        let is_directory = filename.ends_with('/') || filename.ends_with('\\');

        pos += 46 + filename_len + extra_len + comment_len;

        if !is_encrypted || is_strong || is_directory {
            continue;
        }
        if crc32 == 0 {
            continue;
        }
        if comp_size == 0 {
            continue;
        }

        let encrypted_data =
            if local_offset + 30 < data.len() && &data[local_offset..local_offset + 4] == b"PK\x03\x04"
            {
                let local_fn_len = u16::from_le_bytes(
                    data[local_offset + 26..local_offset + 28]
                        .try_into()
                        .unwrap_or([0u8; 2]),
                ) as usize;
                let local_extra_len = u16::from_le_bytes(
                    data[local_offset + 28..local_offset + 30]
                        .try_into()
                        .unwrap_or([0u8; 2]),
                ) as usize;
                let data_start = local_offset + 30 + local_fn_len + local_extra_len;
                let data_end = data_start + comp_size as usize;
                if data_start < data.len() {
                    let end = data_end.min(data.len());
                    data[data_start..end].to_vec()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

        if encrypted_data.is_empty() {
            continue;
        }

        entries.push(ZipEncryptedEntry {
            filename,
            compression_method: compression,
            crc32,
            compressed_size: comp_size,
            encrypted_data,
        });
    }

    Ok(entries)
}

fn make_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for i in 0..256u32 {
        let mut crc = i;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        table[i as usize] = crc;
    }
    table
}

static CRC32_TABLE: std::sync::LazyLock<[u32; 256]> = std::sync::LazyLock::new(make_crc32_table);

fn pkzip_update_keys(password: &str) -> (u32, u32, u32) {
    let mut key0: u32 = 0x12345678;
    let mut key1: u32 = 0x23456789;
    let mut key2: u32 = 0x34567890;

    for &c in password.as_bytes() {
        let c = c as u32;
        key0 = CRC32_TABLE[((key0 ^ c) & 0xFF) as usize] ^ (key0 >> 8);
        key1 = (key1.wrapping_add(key0 & 0xFF)).wrapping_mul(0x08088405).wrapping_add(1);
        key2 = CRC32_TABLE[((key2 ^ (key1 >> 24)) & 0xFF) as usize] ^ (key2 >> 8);
    }

    (key0, key1, key2)
}

fn pkzip_decrypt_byte(key0: &mut u32, key1: &mut u32, key2: &mut u32, ciphertext: u8) -> u8 {
    let temp = *key2 | 3;
    let decrypt_byte = (((temp.wrapping_mul(temp ^ 1)) >> 8) & 0xFF) as u8;
    let plaintext = ciphertext ^ decrypt_byte;

    let c = ciphertext as u32;
    *key0 = CRC32_TABLE[((*key0 ^ c) & 0xFF) as usize] ^ (*key0 >> 8);
    *key1 = (key1.wrapping_add(*key0 & 0xFF)).wrapping_mul(0x08088405).wrapping_add(1);
    *key2 = CRC32_TABLE[((*key2 ^ (*key1 >> 24)) & 0xFF) as usize] ^ (*key2 >> 8);

    plaintext
}

pub fn pkzip_decrypt(password: &str, data: &[u8]) -> Vec<u8> {
    let (mut key0, mut key1, mut key2) = pkzip_update_keys(password);
    let mut result = data.to_vec();
    for byte in result.iter_mut() {
        *byte = pkzip_decrypt_byte(&mut key0, &mut key1, &mut key2, *byte);
    }
    result
}

pub fn pkzip_verify(password: &str, crc32: u32, data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }

    let decrypted = pkzip_decrypt(password, &data[..12]);
    if decrypted.len() < 12 {
        return false;
    }

    if decrypted[10] != decrypted[11] {
        return false;
    }

    let crc_high = ((crc32 >> 24) & 0xFF) as u8;
    decrypted[10] == crc_high
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkzip_cipher_roundtrip() {
        let password = "test";
        let plaintext = b"Hello World!!!!!!";

        let mut key0: u32 = 0x12345678;
        let mut key1: u32 = 0x23456789;
        let mut key2: u32 = 0x34567890;

        for &c in password.as_bytes() {
            let c = c as u32;
            key0 = CRC32_TABLE[((key0 ^ c) & 0xFF) as usize] ^ (key0 >> 8);
            key1 = (key1.wrapping_add(key0 & 0xFF)).wrapping_mul(0x08088405).wrapping_add(1);
            key2 = CRC32_TABLE[((key2 ^ (key1 >> 24)) & 0xFF) as usize] ^ (key2 >> 8);
        }

        let mut encrypted = plaintext.to_vec();
        for byte in encrypted.iter_mut() {
            let temp = key2 | 3;
            let encrypt_byte = (((temp.wrapping_mul(temp ^ 1)) >> 8) & 0xFF) as u8;
            *byte ^= encrypt_byte;

            let c = *byte as u32;
            key0 = CRC32_TABLE[((key0 ^ c) & 0xFF) as usize] ^ (key0 >> 8);
            key1 = (key1.wrapping_add(key0 & 0xFF)).wrapping_mul(0x08088405).wrapping_add(1);
            key2 = CRC32_TABLE[((key2 ^ (key1 >> 24)) & 0xFF) as usize] ^ (key2 >> 8);
        }

        let decrypted = pkzip_decrypt(password, &encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_pkzip_verify() {
        let crc32: u32 = 0x12345678;
        let crc_high = ((crc32 >> 24) & 0xFF) as u8;

        let mut check_bytes = [0u8; 12];
        for i in 0..10 {
            check_bytes[i] = (i * 7 + 3) as u8;
        }
        check_bytes[10] = crc_high;
        check_bytes[11] = crc_high;

        let password = "test";
        let mut key0: u32 = 0x12345678;
        let mut key1: u32 = 0x23456789;
        let mut key2: u32 = 0x34567890;

        for &c in password.as_bytes() {
            let c = c as u32;
            key0 = CRC32_TABLE[((key0 ^ c) & 0xFF) as usize] ^ (key0 >> 8);
            key1 = (key1.wrapping_add(key0 & 0xFF)).wrapping_mul(0x08088405).wrapping_add(1);
            key2 = CRC32_TABLE[((key2 ^ (key1 >> 24)) & 0xFF) as usize] ^ (key2 >> 8);
        }

        let mut encrypted_check = check_bytes;
        for byte in encrypted_check.iter_mut() {
            let temp = key2 | 3;
            let encrypt_byte = (((temp.wrapping_mul(temp ^ 1)) >> 8) & 0xFF) as u8;
            *byte ^= encrypt_byte;

            let c = *byte as u32;
            key0 = CRC32_TABLE[((key0 ^ c) & 0xFF) as usize] ^ (key0 >> 8);
            key1 = (key1.wrapping_add(key0 & 0xFF)).wrapping_mul(0x08088405).wrapping_add(1);
            key2 = CRC32_TABLE[((key2 ^ (key1 >> 24)) & 0xFF) as usize] ^ (key2 >> 8);
        }

        assert!(pkzip_verify(password, crc32, &encrypted_check));
        assert!(!pkzip_verify("wrong", crc32, &encrypted_check));
    }
}
