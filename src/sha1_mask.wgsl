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

@group(0) @binding(0) var<storage, read_write> config: Config;
@group(0) @binding(1) var<storage, read_write> progress: Progress;
@group(0) @binding(2) var<storage, read> targets: array<TargetEntry>;

const CS_SIZES: array<u32, 5> = array<u32, 5>(26u, 26u, 10u, 62u, 0u);

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

fn sha1(pwd: array<u32, 4>, len: u32) -> array<u32, 8> {
    var state: array<u32, 5> = array<u32, 5>(
        0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u,
    );
    var block: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { block[i] = 0u; }

    for (var i = 0u; i < len && i < 16u; i++) {
        let ch = pwd[len - 1u - i] & 0xFFu;
        let dst_word = i / 4u;
        let dst_shift = (3u - (i % 4u)) * 8u;
        block[dst_word] |= ch << dst_shift;
    }

    // Salt (big-endian, right after password)
    for (var i = 0u; i < config.salt_len && i < 16u; i++) {
        let ch = config.salt[config.salt_len - 1u - i] & 0xFFu;
        let dst_byte = len + i;
        let dst_word = dst_byte / 4u;
        let dst_shift = (3u - (dst_byte % 4u)) * 8u;
        block[dst_word] |= ch << dst_shift;
    }

    let pad_byte = len + config.salt_len;
    let pad_word = pad_byte / 4u;
    let pad_shift = (3u - (pad_byte % 4u)) * 8u;
    block[pad_word] |= 0x80u << pad_shift;

    block[15u] = (len + config.salt_len) * 8u;

    sha1_block(&state, block);
    return array<u32, 8>(state[0u], state[1u], state[2u], state[3u], state[4u], 0u, 0u, 0u);
}

fn char_from_digit(d: u32) -> u32 {
    if (d < 26u) { return d + 97u; }
    else if (d < 52u) { return d - 26u + 65u; }
    else { return d - 52u + 48u; }
}

fn mask_index_to_password(index: u32) -> array<u32, 4> {
    var pwd: array<u32, 4>;
    var remaining = index;
    for (var i = 0u; i < 4u; i++) {
        if (i < config.mask_len) {
            let cs = config.mask[i];
            let sz = CS_SIZES[cs];
            let d = remaining % sz;
            if (cs == 0u) { pwd[i] = d + 97u; }
            else if (cs == 1u) { pwd[i] = d + 65u; }
            else if (cs == 2u) { pwd[i] = d + 48u; }
            else { pwd[i] = char_from_digit(d); }
            remaining = remaining / sz;
        } else { pwd[i] = 0u; }
    }
    return pwd;
}

@compute @workgroup_size(128)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let index = config.range_start + id.y * 65535u * 128u + id.x;
    if (index >= config.range_end) { return; }
    if (atomicLoad(&config.found_flag) != 0u) { atomicAdd(&progress.count, 1u); return; }    let pwd = mask_index_to_password(index);
    let hash = sha1(pwd, config.mask_len);
    var match_found = false;
    for (var t = 0u; t < config.num_targets; t++) {
        var t_match = true;
        for (var i = 0u; i < 5u; i++) { if (hash[i] != targets[t].hash[i]) { t_match = false; } }
        if (t_match) { match_found = true; }
    }
    if (match_found) {
        let prev = atomicCompareExchangeWeak(&config.found_flag, 0u, 1u);
        if (prev.old_value == 0u) { config.found_password = pwd; }
    }
    atomicAdd(&progress.count, 1u);
}
