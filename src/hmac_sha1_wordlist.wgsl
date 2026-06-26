struct Config {
    target_hash: array<u32, 8>,
    password_len: u32,
    num_passwords: u32,
    found_flag: atomic<u32>,
    found_password: array<u32, 4>,
    mask: array<u32, 16>,
    mask_len: u32,
    target_hash_extra: array<u32, 8>,
    salt: array<u32, 16>,
    salt_len: u32,
    range_start: u32,
    range_end: u32,
    num_targets: u32,
}

struct Progress {
    count: atomic<u32>,
}
struct TargetEntry {
    hash: array<u32, 8>,
    hash_extra: array<u32, 8>,
}

struct WordEntry {
    chars: array<u32, 5>,
    len: u32,
}

@group(0) @binding(0) var<storage, read_write> config: Config;
@group(0) @binding(1) var<storage, read_write> progress: Progress;
@group(0) @binding(2) var<storage, read> word_buf: array<WordEntry>;
@group(0) @binding(3) var<storage, read> targets: array<TargetEntry>;

fn left_rotate(x: u32, n: u32) -> u32 { return (x << n) | (x >> (32u - n)); }

fn sha1_block(state: ptr<function, array<u32, 5>>, block: array<u32, 16>) {
    var w: array<u32, 80>;
    for (var i = 0u; i < 16u; i++) { w[i] = block[i]; }
    for (var i = 16u; i < 80u; i++) { w[i] = left_rotate(w[i - 3u] ^ w[i - 8u] ^ w[i - 14u] ^ w[i - 16u], 1u); }
    var a = (*state)[0u]; var b = (*state)[1u]; var c = (*state)[2u]; var d = (*state)[3u]; var e = (*state)[4u];
    for (var i = 0u; i < 80u; i++) {
        var f: u32; var k: u32;
        if (i < 20u) { f = (b & c) | ((~b) & d); k = 0x5A827999u; }
        else if (i < 40u) { f = b ^ c ^ d; k = 0x6ED9EBA1u; }
        else if (i < 60u) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6u; }
        let tmp = left_rotate(a, 5u) + f + e + k + w[i];
        e = d; d = c; c = left_rotate(b, 30u); b = a; a = tmp;
    }
    (*state)[0u] += a; (*state)[1u] += b; (*state)[2u] += c; (*state)[3u] += d; (*state)[4u] += e;
}

fn set_byte(buf: ptr<function, array<u32, 64>>, pos: u32, val: u32) {
    let w = pos / 4u;
    let s = (pos % 4u) * 8u;
    (*buf)[w] |= (val & 0xFFu) << s;
}

fn sha1_bytes(data: array<u32, 64>, len: u32) -> array<u32, 8> {
    var state: array<u32, 5> = array<u32, 5>(
        0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u,
    );

    var offset = 0u;
    while (offset + 64u <= len) {
        var block: array<u32, 16>;
        for (var i = 0u; i < 16u; i++) { block[i] = 0u; }
        for (var i = 0u; i < 64u; i++) {
            let val = (data[(offset + i) / 4u] >> (((offset + i) % 4u) * 8u)) & 0xFFu;
            let w = i / 4u;
            let s = (3u - (i % 4u)) * 8u;
            block[w] |= val << s;
        }
        sha1_block(&state, block);
        offset += 64u;
    }

    var block: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { block[i] = 0u; }
    let remaining = len - offset;
    for (var i = 0u; i < remaining; i++) {
        let val = (data[(offset + i) / 4u] >> (((offset + i) % 4u) * 8u)) & 0xFFu;
        let w = i / 4u;
        let s = (3u - (i % 4u)) * 8u;
        block[w] |= val << s;
    }

    let pad_pos = remaining;
    let pad_w = pad_pos / 4u;
    let pad_s = (3u - (pad_pos % 4u)) * 8u;
    block[pad_w] |= 0x80u << pad_s;

    if (remaining >= 56u) {
        sha1_block(&state, block);
        for (var i = 0u; i < 16u; i++) { block[i] = 0u; }
    }

    block[15u] = len * 8u;
    sha1_block(&state, block);

    return array<u32, 8>(state[0u], state[1u], state[2u], state[3u], state[4u], 0u, 0u, 0u);
}

fn hmac_sha1(pwd: array<u32, 5>, len: u32) -> array<u32, 8> {
    var msg: array<u32, 64>;
    for (var i = 0u; i < 64u; i++) { msg[i] = 0u; }
    var pos = 0u;

    // ipad_xor_key (64 bytes)
    for (var j = 0u; j < 64u; j++) {
        let key_byte = select(0x36u, pwd[len - 1u - (j % len)] & 0xFFu, j < len);
        set_byte(&msg, pos + j, key_byte ^ 0x36u);
    }
    pos += 64u;

    // salt
    for (var i = 0u; i < config.salt_len; i++) {
        set_byte(&msg, pos + i, config.salt[config.salt_len - 1u - i] & 0xFFu);
    }
    pos += config.salt_len;

    let inner = sha1_bytes(msg, pos);

    // opad_xor_key + inner_hash
    for (var i = 0u; i < 64u; i++) { msg[i] = 0u; }
    pos = 0u;

    for (var j = 0u; j < 64u; j++) {
        let key_byte = select(0x5Cu, pwd[len - 1u - (j % len)] & 0xFFu, j < len);
        set_byte(&msg, pos + j, key_byte ^ 0x5Cu);
    }
    pos += 64u;

    // inner hash bytes (5 big-endian u32 words)
    for (var k = 0u; k < 5u; k++) {
        let w = inner[k];
        set_byte(&msg, pos + k * 4u + 0u, (w >> 24u) & 0xFFu);
        set_byte(&msg, pos + k * 4u + 1u, (w >> 16u) & 0xFFu);
        set_byte(&msg, pos + k * 4u + 2u, (w >> 8u) & 0xFFu);
        set_byte(&msg, pos + k * 4u + 3u, w & 0xFFu);
    }
    pos += 20u;

    return sha1_bytes(msg, pos);
}

const MAX_DISPATCH_X: u32 = 65535u;

@compute @workgroup_size(128)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let index = id.y * MAX_DISPATCH_X * 128u + id.x;
    if (index >= config.range_end) { return; }
    if (atomicLoad(&config.found_flag) != 0u) { atomicAdd(&progress.count, 1u); return; }    let entry = word_buf[index];
    let hash = hmac_sha1(entry.chars, entry.len);
    var match_found = false;
    for (var t = 0u; t < config.num_targets; t++) {
        var t_match = true;
        for (var i = 0u; i < 5u; i++) { if (hash[i] != targets[t].hash[i]) { t_match = false; } }
        if (t_match) { match_found = true; }
    }
    if (match_found) {
        let prev = atomicCompareExchangeWeak(&config.found_flag, 0u, 1u);
        if (prev.old_value == 0u) { config.found_password[0] = index; }
    }
    atomicAdd(&progress.count, 1u);
}
