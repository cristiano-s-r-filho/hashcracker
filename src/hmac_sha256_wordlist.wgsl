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

const K: array<u32, 64> = array<u32, 64>(
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
);

fn rotr(x: u32, n: u32) -> u32 { return (x >> n) | (x << (32u - n)); }
fn ch(x: u32, y: u32, z: u32) -> u32 { return (x & y) ^ ((~x) & z); }
fn maj(x: u32, y: u32, z: u32) -> u32 { return (x & y) ^ (x & z) ^ (y & z); }
fn sig0(x: u32) -> u32 { return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u); }
fn sig1(x: u32) -> u32 { return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u); }
fn gam0(x: u32) -> u32 { return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u); }
fn gam1(x: u32) -> u32 { return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u); }

fn sha256_block(state: ptr<function, array<u32, 8>>, block: array<u32, 16>) {
    var w: array<u32, 64>;
    for (var i = 0u; i < 16u; i++) { w[i] = block[i]; }
    for (var i = 16u; i < 64u; i++) { w[i] = gam1(w[i - 2u]) + w[i - 7u] + gam0(w[i - 15u]) + w[i - 16u]; }
    var a = (*state)[0u]; var b = (*state)[1u]; var c = (*state)[2u]; var d = (*state)[3u];
    var e = (*state)[4u]; var f = (*state)[5u]; var g = (*state)[6u]; var h = (*state)[7u];
    for (var i = 0u; i < 64u; i++) {
        let t1 = h + sig1(e) + ch(e, f, g) + K[i] + w[i];
        let t2 = sig0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    (*state)[0u] += a; (*state)[1u] += b; (*state)[2u] += c; (*state)[3u] += d;
    (*state)[4u] += e; (*state)[5u] += f; (*state)[6u] += g; (*state)[7u] += h;
}

fn set_byte(buf: ptr<function, array<u32, 64>>, pos: u32, val: u32) {
    let w = pos / 4u;
    let s = (pos % 4u) * 8u;
    (*buf)[w] |= (val & 0xFFu) << s;
}

fn sha256_bytes(data: array<u32, 64>, len: u32) -> array<u32, 8> {
    var state: array<u32, 8> = array<u32, 8>(
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
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
        sha256_block(&state, block);
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
        sha256_block(&state, block);
        for (var i = 0u; i < 16u; i++) { block[i] = 0u; }
    }

    block[14u] = 0u;
    block[15u] = len * 8u;
    sha256_block(&state, block);

    return state;
}

fn hmac_sha256(pwd: array<u32, 5>, len: u32) -> array<u32, 8> {
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

    let inner = sha256_bytes(msg, pos);

    // opad_xor_key + inner_hash
    for (var i = 0u; i < 64u; i++) { msg[i] = 0u; }
    pos = 0u;

    for (var j = 0u; j < 64u; j++) {
        let key_byte = select(0x5Cu, pwd[len - 1u - (j % len)] & 0xFFu, j < len);
        set_byte(&msg, pos + j, key_byte ^ 0x5Cu);
    }
    pos += 64u;

    // inner hash bytes (8 big-endian u32 words = 32 bytes)
    for (var k = 0u; k < 8u; k++) {
        let w = inner[k];
        set_byte(&msg, pos + k * 4u + 0u, (w >> 24u) & 0xFFu);
        set_byte(&msg, pos + k * 4u + 1u, (w >> 16u) & 0xFFu);
        set_byte(&msg, pos + k * 4u + 2u, (w >> 8u) & 0xFFu);
        set_byte(&msg, pos + k * 4u + 3u, w & 0xFFu);
    }
    pos += 32u;

    return sha256_bytes(msg, pos);
}

const MAX_DISPATCH_X: u32 = 65535u;

@compute @workgroup_size(128)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let index = id.y * MAX_DISPATCH_X * 128u + id.x;
    if (index >= config.range_end) { return; }
    if (atomicLoad(&config.found_flag) != 0u) { atomicAdd(&progress.count, 1u); return; }    let entry = word_buf[index];
    let hash = hmac_sha256(entry.chars, entry.len);
    var match_found = false;
    for (var t = 0u; t < config.num_targets; t++) {
        var t_match = true;
        for (var i = 0u; i < 8u; i++) { if (hash[i] != targets[t].hash[i]) { t_match = false; } }
        if (t_match) { match_found = true; }
    }
    if (match_found) {
        let prev = atomicCompareExchangeWeak(&config.found_flag, 0u, 1u);
        if (prev.old_value == 0u) { config.found_password[0] = index; }
    }
    atomicAdd(&progress.count, 1u);
}
