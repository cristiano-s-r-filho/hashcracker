// NTLM = MD4(UTF-16LE(password)) — Mask variant

const MAX_DISPATCH_X: u32 = 65535u;
const PASSWORD_MAX: u32 = 4u;

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

const CS_SIZES: array<u32, 4> = array<u32, 4>(26u, 26u, 10u, 62u);

@group(0) @binding(0) var<storage, read_write> config: Config;
@group(0) @binding(1) var<storage, read_write> progress: Progress;
@group(0) @binding(2) var<storage, read> targets: array<TargetEntry>;

fn mask_index_to_password(idx: u32, mask: ptr<function, array<u32, 16>>, len: u32) -> array<u32, 4> {
    var pwd: array<u32, 4>;
    var remaining = idx;
    for (var i = 0u; i < len; i = i + 1u) {
        let sz = CS_SIZES[(*mask)[i]];
        let d = remaining % sz;
        remaining = remaining / sz;
        let c = select(select(select(d + 97u, d + 65u, (*mask)[i] == 1u), d + 48u, (*mask)[i] == 2u),
            select(select(d + 97u, d + 65u - 26u, d < 52u), d - 52u + 48u, true),
            (*mask)[i] == 3u);
        pwd[len - 1u - i] = c;
    }
    return pwd;
}

fn rotl(x: u32, n: u32) -> u32 {
    return (x << n) | (x >> (32u - n));
}

fn md4_f(x: u32, y: u32, z: u32) -> u32 { return (x & y) | ((~x) & z); }
fn md4_g(x: u32, y: u32, z: u32) -> u32 { return (x & y) | (x & z) | (y & z); }
fn md4_h(x: u32, y: u32, z: u32) -> u32 { return x ^ y ^ z; }

const MD4_K: array<u32, 3> = array<u32, 3>(0u, 0x5A827999u, 0x6ED9EBA1u);

const MD4_S: array<u32, 48> = array<u32, 48>(
    3u, 7u, 11u, 19u, 3u, 7u, 11u, 19u, 3u, 7u, 11u, 19u, 3u, 7u, 11u, 19u,
    3u, 5u, 9u, 13u, 3u, 5u, 9u, 13u, 3u, 5u, 9u, 13u, 3u, 5u, 9u, 13u,
    3u, 9u, 11u, 15u, 3u, 9u, 11u, 15u, 3u, 9u, 11u, 15u, 3u, 9u, 11u, 15u,
);

const MD4_W: array<u32, 48> = array<u32, 48>(
    0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u,
    0u, 4u, 8u, 12u, 1u, 5u, 9u, 13u, 2u, 6u, 10u, 14u, 3u, 7u, 11u, 15u,
    0u, 8u, 4u, 12u, 2u, 10u, 6u, 14u, 1u, 9u, 5u, 13u, 3u, 11u, 7u, 15u
);

fn md4_compress(state: ptr<function, array<u32, 4>>, block: ptr<function, array<u32, 16>>) {
    var a = (*state)[0u]; var b = (*state)[1u]; var c = (*state)[2u]; var d = (*state)[3u];
    var aa = a; var bb = b; var cc = c; var dd = d;

    for (var i = 0u; i < 16u; i = i + 1u) {
        let s = MD4_S[i]; let k = MD4_K[0u]; let w = (*block)[MD4_W[i]];
        a = rotl(a + md4_f(b, c, d) + w + k, s);
        var tmp = d; d = c; c = b; b = a; a = tmp;
    }
    for (var i = 0u; i < 16u; i = i + 1u) {
        let n = 16u + i; let s = MD4_S[n]; let k = MD4_K[1u]; let w = (*block)[MD4_W[n]];
        a = rotl(a + md4_g(b, c, d) + w + k, s);
        var tmp = d; d = c; c = b; b = a; a = tmp;
    }
    for (var i = 0u; i < 16u; i = i + 1u) {
        let n = 32u + i; let s = MD4_S[n]; let k = MD4_K[2u]; let w = (*block)[MD4_W[n]];
        a = rotl(a + md4_h(b, c, d) + w + k, s);
        var tmp = d; d = c; c = b; b = a; a = tmp;
    }
    (*state)[0u] = a + aa; (*state)[1u] = b + bb; (*state)[2u] = c + cc; (*state)[3u] = d + dd;
}

fn ntlm_hash(pwd: array<u32, 4>, len: u32) -> array<u32, 4> {
    var msg: array<u32, 16>;
    for (var i = 0u; i < 16u; i = i + 1u) { msg[i] = 0u; }

    var bit_len: u32 = 0u;
    for (var i = 0u; i < len; i = i + 1u) {
        let ch = pwd[len - 1u - i];
        let word_idx = (i * 2u) / 4u;
        let byte_in_word = (i * 2u) % 4u;
        msg[word_idx] = msg[word_idx] | (ch << (byte_in_word * 8u));
        bit_len = bit_len + 16u;
    }

    let total_bytes = len * 2u;
    let pad_byte_idx = total_bytes;
    let pad_word_idx = pad_byte_idx / 4u;
    let pad_byte_offset = pad_byte_idx % 4u;
    msg[pad_word_idx] = msg[pad_word_idx] | (0x80u << (pad_byte_offset * 8u));

    msg[14u] = bit_len;
    msg[15u] = 0u;

    var state: array<u32, 4> = array<u32, 4>(0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u);
    md4_compress(&state, &msg);
    return state;
}

@compute @workgroup_size(128)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let index = config.range_start + id.y * MAX_DISPATCH_X * 128u + id.x;
    if (index >= config.range_end) { return; }
    if (atomicLoad(&config.found_flag) != 0u) { atomicAdd(&progress.count, 1u); return; }    var mask = config.mask;
    let pwd = mask_index_to_password(index, &mask, config.mask_len);
    let hash = ntlm_hash(pwd, config.mask_len);

    var found = false;
    for (var t = 0u; t < config.num_targets; t++) {
        if (hash[0u] == targets[t].hash[0u] && hash[1u] == targets[t].hash[1u] &&
            hash[2u] == targets[t].hash[2u] && hash[3u] == targets[t].hash[3u]) {
            found = true;
        }
    }

    if (found) {
        atomicCompareExchangeWeak(&config.found_flag, 0u, 1u);
        for (var i = 0u; i < config.mask_len; i = i + 1u) {
            config.found_password[i] = pwd[i];
        }
    }
    atomicAdd(&progress.count, 1u);
}
