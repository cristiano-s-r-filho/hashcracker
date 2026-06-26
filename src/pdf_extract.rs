// PDF hash extraction — compatible with hashcat -m 10500/10700 and JtR pdf2john

pub const PDF_PADDING: &[u8; 32] = b"\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";

pub struct PdfHash {
    pub v: u32,
    pub r: u32,
    pub length: u32,
    pub p: i32,
    pub encrypt_meta: bool,
    pub id: Vec<u8>,
    pub u: Vec<u8>,
    pub o: Vec<u8>,
    pub ue: Vec<u8>,
    pub oe: Vec<u8>,
}

/// Extract a $pdf$ hash string from a PDF file
pub fn extract_pdf_hash(path: &str) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| format!("Cannot read {}: {}", path, e))?;
    let pdf = parse_pdf(&data)?;
    Ok(format_pdf_hash(&pdf))
}

fn format_pdf_hash(pdf: &PdfHash) -> String {
    let id_hex = hex::encode(&pdf.id);
    let id_len = pdf.id.len();
    let u_hex = hex::encode(&pdf.u);
    let u_len = pdf.u.len();
    let o_hex = hex::encode(&pdf.o);
    let o_len = pdf.o.len();
    let meta = if pdf.encrypt_meta { 1 } else { 0 };

    let mut hash = format!(
        "$pdf${}*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}",
        pdf.v, pdf.r, pdf.length, pdf.p, meta,
        id_len, id_hex, u_len, u_hex, o_len, o_hex
    );

    if !pdf.ue.is_empty() {
        let ue_hex = hex::encode(&pdf.ue);
        let ue_len = pdf.ue.len();
        let oe_hex = hex::encode(&pdf.oe);
        let oe_len = pdf.oe.len();
        hash.push_str(&format!("*{}*{}*{}*{}", ue_len, ue_hex, oe_len, oe_hex));
    }

    hash
}

fn parse_pdf(data: &[u8]) -> Result<PdfHash, String> {
    // Find trailer
    let trailer = find_trailer(data)?;

    // Extract /ID from trailer
    let id = extract_id(&trailer)?;

    // Find /Encrypt reference in trailer
    let encrypt_ref = find_encrypt_ref(&trailer)?;
    let enc_dict = get_pdf_object(data, &encrypt_ref)?;

    // Extract encryption parameters
    let v = extract_int(&enc_dict, b"/V")?;
    let r = extract_int(&enc_dict, b"/R")?;
    let length = extract_length(&enc_dict, v);
    let p = extract_int_signed(&enc_dict, b"/P")?;
    let encrypt_meta = extract_encrypt_meta(&enc_dict);
    let u = extract_bytes(&enc_dict, b"/U")?;
    let o = extract_bytes(&enc_dict, b"/O")?;

    let (ue, oe) = if v == 5 {
        (extract_bytes(&enc_dict, b"/UE").unwrap_or_default(),
         extract_bytes(&enc_dict, b"/OE").unwrap_or_default())
    } else {
        (Vec::new(), Vec::new())
    };

    Ok(PdfHash { v, r, length, p, encrypt_meta, id, u, o, ue, oe })
}

fn find_trailer(data: &[u8]) -> Result<Vec<u8>, String> {
    // Find "trailer" keyword, then capture everything up to ">>" followed by "startxref"
    let trailer_pos = find_bytes(data, b"trailer")
        .ok_or_else(|| "Could not find trailer keyword".to_string())?;

    // Search forward for "startxref" from trailer position
    let startxref_pos = find_bytes_from(data, b"startxref", trailer_pos)
        .ok_or_else(|| "Could not find startxref after trailer".to_string())?;

    // The trailer content is from trailer_pos to startxref_pos
    let trailer_data = &data[trailer_pos..startxref_pos];
    Ok(trailer_data.to_vec())
}

fn find_encrypt_ref(trailer: &[u8]) -> Result<String, String> {
    let pattern = b"/Encrypt";
    let pos = find_bytes(trailer, pattern)
        .ok_or_else(|| "File is not encrypted (no /Encrypt in trailer)".to_string())?;

    // Find the object reference: "N N R" after /Encrypt  
    let rest = &trailer[pos + pattern.len()..];
    // Find the first complete "N N R" pattern  
    let ref_str = extract_ref(rest)?;
    Ok(ref_str)
}

fn extract_ref(data: &[u8]) -> Result<String, String> {
    let s = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8 in PDF".to_string())?;
    let s = s.trim_start();
    let parts: Vec<&str> = s.splitn(3, |c: char| c.is_whitespace() || c == '/' || c == '>' || c == ']')
        .collect();
    if parts.len() < 3 {
        return Err("Cannot parse object reference".to_string());
    }
    let obj_num = parts[0].trim();
    let gen_num = parts[1].trim();
    if obj_num.parse::<u32>().is_err() || gen_num.parse::<u32>().is_err() {
        return Err(format!("Invalid object reference: {} {}", obj_num, gen_num));
    }
    Ok(format!("{} {} R", obj_num, gen_num))
}

fn get_pdf_object(data: &[u8], ref_str: &str) -> Result<Vec<u8>, String> {
    let obj_pattern = ref_str.replace(" R", " obj");
    let start = find_bytes(data, obj_pattern.as_bytes())
        .ok_or_else(|| format!("Could not find object {}", ref_str))?;

    let end = find_bytes_from(data, b"endobj", start)
        .ok_or_else(|| format!("Could not find endobj for {}", ref_str))?;

    let end_obj_end = end + b"endobj".len();
    let obj_data = &data[start..end_obj_end];
    Ok(obj_data.to_vec())
}

fn extract_id(trailer: &[u8]) -> Result<Vec<u8>, String> {
    let pattern = b"/ID";
    let pos = find_bytes(trailer, pattern);
    let id_data = match pos {
        Some(p) => {
            let rest = &trailer[p + pattern.len()..];
            extract_hex_content(rest).unwrap_or_default()
        }
        None => Vec::new(),
    };
    if id_data.is_empty() {
        return Err("Could not find /ID in trailer".to_string());
    }
    Ok(id_data)
}

fn extract_hex_content(data: &[u8]) -> Option<Vec<u8>> {
    // Find content between < and >
    let start = find_bytes(data, b"<")?;
    let end = find_bytes_from(data, b">", start + 1)?;
    let hex_str = std::str::from_utf8(&data[start + 1..end]).ok()?;
    // Take only hex chars
    let clean: String = hex_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    hex::decode(&clean).ok()
}

fn extract_int(data: &[u8], key: &[u8]) -> Result<u32, String> {
    let pos = find_bytes(data, key)
        .ok_or_else(|| format!("Could not find {:?} in encryption dictionary", key))?;
    let rest = &data[pos + key.len()..];
    let s = std::str::from_utf8(rest).map_err(|_| "Invalid UTF-8".to_string())?;
    let s = s.trim_start();
    let num_str: String = s.chars().take_while(|c| c.is_ascii_digit() || *c == '-').collect();
    num_str.parse::<u32>().map_err(|e| format!("Cannot parse integer for {:?}: {}", key, e))
}

fn extract_int_signed(data: &[u8], key: &[u8]) -> Result<i32, String> {
    let pos = find_bytes(data, key)
        .ok_or_else(|| format!("Could not find {:?} in encryption dictionary", key))?;
    let rest = &data[pos + key.len()..];
    let s = std::str::from_utf8(rest).map_err(|_| "Invalid UTF-8".to_string())?;
    let s = s.trim_start();
    let num_str: String = s.chars().take_while(|c| c.is_ascii_digit() || *c == '-').collect();
    num_str.parse::<i32>().map_err(|e| format!("Cannot parse signed integer for {:?}: {}", key, e))
}

fn extract_length(data: &[u8], v: u32) -> u32 {
    if v == 1 {
        return 40; // Default for V=1
    }
    // Try to find /Length
    let pos = find_bytes(data, b"/Length");
    match pos {
        Some(p) => {
            let rest = &data[p + 7..];
            let s = std::str::from_utf8(rest).unwrap_or("");
            let s = s.trim_start();
            let num_str: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
            num_str.parse::<u32>().unwrap_or(128) // Default to 128
        }
        None => 128, // Default for V >= 2
    }
}

fn extract_encrypt_meta(data: &[u8]) -> bool {
    let pos = find_bytes(data, b"/EncryptMetadata");
    match pos {
        Some(p) => {
            let rest = &data[p + 16..];
            let s = std::str::from_utf8(rest).unwrap_or("");
            let s = s.trim_start();
            !s.starts_with("false")
        }
        None => true, // Default: metadata is encrypted
    }
}

fn extract_bytes(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let pos = find_bytes(data, key)
        .ok_or_else(|| format!("Could not find {:?} in encryption dictionary", String::from_utf8_lossy(key)))?;
    let rest = &data[pos + key.len()..];
    let s = std::str::from_utf8(rest).map_err(|_| "Invalid UTF-8".to_string())?;
    let s = s.trim_start();

    if s.starts_with('<') {
        // Hex string: <hex>
        let end = s.find('>').ok_or_else(|| "Unterminated hex string".to_string())?;
        let hex_str: String = s[1..end].chars().filter(|c| c.is_ascii_hexdigit()).collect();
        hex::decode(&hex_str).map_err(|e| format!("Invalid hex: {}", e))
    } else if s.starts_with('(') {
        // Literal string: (bytes)
        let mut result = Vec::new();
        let mut chars = s[1..].chars();
        loop {
            match chars.next() {
                None => return Err("Unterminated literal string".to_string()),
                Some(')') => break,
                Some('\\') => {
                    match chars.next() {
                        Some('n') => result.push(b'\n'),
                        Some('r') => result.push(b'\r'),
                        Some('t') => result.push(b'\t'),
                        Some('(') => result.push(b'('),
                        Some(')') => result.push(b')'),
                        Some('\\') => result.push(b'\\'),
                        Some(c) => result.push(c as u8),
                        None => break,
                    }
                }
                Some(c) => result.push(c as u8),
            }
        }
        Ok(result)
    } else {
        // Could be hex with angle brackets on next line or inline hex without <>
        Err(format!("Unknown byte format for {:?}: starts with '{}'", key, &s[..s.len().min(10)]))
    }
}

fn find_bytes(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len()).position(|w| w == pattern)
}

fn find_bytes_from(data: &[u8], pattern: &[u8], start: usize) -> Option<usize> {
    if start >= data.len() { return None; }
    data[start..].windows(pattern.len()).position(|w| w == pattern).map(|p| p + start)
}

#[test]
fn test_extract_pdf_hash() {
    // Use the pdf2hashcat.py to generate a reference hash, then verify our parser.
    // For now, we only test that the format string is valid.
    let test_hash = "$pdf$2*3*128*-4*1*16*733ab0e911f8aa4c77782aa056996f57*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000";

    // Verify format is parseable
    let parsed = crate::hashes::raw_pdf::parse_pdf_hash(test_hash).unwrap();
    assert_eq!(parsed.v, 2);
    assert_eq!(parsed.r, 3);
    assert_eq!(parsed.length, 128);
    assert_eq!(parsed.p, -4);
    assert!(parsed.encrypt_meta);
    assert_eq!(parsed.id.len(), 16);
    assert_eq!(parsed.u.len(), 32);
    assert_eq!(parsed.o.len(), 32);
}
