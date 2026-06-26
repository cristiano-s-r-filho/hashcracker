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

const CHARSET_SIZE: u32 = 62u;

fn left_rotate(x: u32, n: u32) -> u32 { return (x << n) | (x >> (32u - n)); }

fn F(x: u32, y: u32, z: u32) -> u32 { return (x & y) | ((~x) & z); }
fn G(x: u32, y: u32, z: u32) -> u32 { return (x & y) | (x & z) | (y & z); }
fn H(x: u32, y: u32, z: u32) -> u32 { return x ^ y ^ z; }

fn md4_block(state: ptr<function, array<u32, 4>>, block: array<u32, 16>) {
    var a = (*state)[0u]; var b = (*state)[1u]; var c = (*state)[2u]; var d = (*state)[3u];

    // Round 1
    for (var i = 0u; i < 16u; i += 4u) {
        a = a + F(b,c,d) + block[i];     a = left_rotate(a, 3u);
        d = d + F(a,b,c) + block[i+1u];  d = left_rotate(d, 7u);
        c = c + F(d,a,b) + block[i+2u];  c = left_rotate(c, 11u);
        b = b + F(c,d,a) + block[i+3u];  b = left_rotate(b, 19u);
    }

    let perm2 = array<u32, 16>(0u, 4u, 8u, 12u, 1u, 5u, 9u, 13u, 2u, 6u, 10u, 14u, 3u, 7u, 11u, 15u);
    for (var i = 0u; i < 16u; i += 4u) {
        a = a + G(b,c,d) + block[perm2[i]]     + 0x5a827999u; a = left_rotate(a, 3u);
        d = d + G(a,b,c) + block[perm2[i+1u]]  + 0x5a827999u; d = left_rotate(d, 5u);
        c = c + G(d,a,b) + block[perm2[i+2u]]  + 0x5a827999u; c = left_rotate(c, 9u);
        b = b + G(c,d,a) + block[perm2[i+3u]]  + 0x5a827999u; b = left_rotate(b, 13u);
    }

    let perm3 = array<u32, 16>(0u, 8u, 4u, 12u, 2u, 10u, 6u, 14u, 1u, 9u, 5u, 13u, 3u, 11u, 7u, 15u);
    for (var i = 0u; i < 16u; i += 4u) {
        a = a + H(b,c,d) + block[perm3[i]]     + 0x6ed9eba1u; a = left_rotate(a, 3u);
        d = d + H(a,b,c) + block[perm3[i+1u]]  + 0x6ed9eba1u; d = left_rotate(d, 9u);
        c = c + H(d,a,b) + block[perm3[i+2u]]  + 0x6ed9eba1u; c = left_rotate(c, 11u);
        b = b + H(c,d,a) + block[perm3[i+3u]]  + 0x6ed9eba1u; b = left_rotate(b, 15u);
    }

    (*state)[0u] += a; (*state)[1u] += b; (*state)[2u] += c; (*state)[3u] += d;
}

fn md4(pwd: array<u32, 4>, len: u32) -> array<u32, 8> {
    var state: array<u32, 4> = array<u32, 4>(
        0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u,
    );
    var block: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { block[i] = 0u; }

    for (var i = 0u; i < len && i < 16u; i++) {
        let ch = pwd[len - 1u - i] & 0xFFu;
        let dst_word = i / 4u;
        let dst_shift = (i % 4u) * 8u;
        block[dst_word] |= ch << dst_shift;
    }

    let pad_byte = len;
    let pad_word = pad_byte / 4u;
    let pad_shift = (pad_byte % 4u) * 8u;
    block[pad_word] |= 0x80u << pad_shift;

    block[14u] = len * 8u;
    block[15u] = 0u;

    md4_block(&state, block);
    return array<u32, 8>(state[0u], state[1u], state[2u], state[3u], 0u, 0u, 0u, 0u);
}

fn char_from_digit(d: u32) -> u32 {
    if (d < 26u) { return d + 97u; }
    else if (d < 52u) { return d - 26u + 65u; }
    else { return d - 52u + 48u; }
}

fn index_to_password(index: u32, len: u32) -> array<u32, 4> {
    var pwd: array<u32, 4>;
    var remaining = index;
    for (var i = 0u; i < 4u; i++) {
        if (i < len) {
            let d = remaining % CHARSET_SIZE;
            pwd[i] = char_from_digit(d);
            remaining = remaining / CHARSET_SIZE;
        } else { pwd[i] = 0u; }
    }
    return pwd;
}

const MAX_DISPATCH_X: u32 = 65535u;

@compute @workgroup_size(128)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let index = config.range_start + id.y * MAX_DISPATCH_X * 128u + id.x;
    if (index >= config.range_end) { return; }
    if (atomicLoad(&config.found_flag) != 0u) { atomicAdd(&progress.count, 1u); return; }    let pwd = index_to_password(index, config.password_len);
    let hash = md4(pwd, config.password_len);
    var match_found = false;
    for (var t = 0u; t < config.num_targets; t++) {
        var t_match = true;
        for (var i = 0u; i < 4u; i++) { if (hash[i] != targets[t].hash[i]) { t_match = false; } }
        if (t_match) { match_found = true; }
    }
    if (match_found) {
        let prev = atomicCompareExchangeWeak(&config.found_flag, 0u, 1u);
        if (prev.old_value == 0u) { config.found_password = pwd; }
    }
    atomicAdd(&progress.count, 1u);
}
