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

const CS: array<u32, 4> = array<u32, 4>(26u, 26u, 10u, 62u);

const K: array<u32, 64> = array<u32, 64>(
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u,
);

const S: array<u32, 64> = array<u32, 64>(
    7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u,
    7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u,
    5u,  9u, 14u, 20u, 5u,  9u, 14u, 20u,
    5u,  9u, 14u, 20u, 5u,  9u, 14u, 20u,
    4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u,
    4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u,
    6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u,
    6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u,
);

fn left_rotate(x: u32, n: u32) -> u32 { return (x << n) | (x >> (32u - n)); }

fn md5_block(state: ptr<function, array<u32, 4>>, block: array<u32, 16>) {
    var a = (*state)[0u]; var b = (*state)[1u]; var c = (*state)[2u]; var d = (*state)[3u];
    for (var i = 0u; i < 64u; i++) {
        var f: u32; var g: u32;
        if (i < 16u) { f = (b & c) | ((~b) & d); g = i; }
        else if (i < 32u) { f = (d & b) | ((~d) & c); g = (5u * i + 1u) % 16u; }
        else if (i < 48u) { f = b ^ c ^ d; g = (3u * i + 5u) % 16u; }
        else { f = c ^ (b | (~d)); g = (7u * i) % 16u; }
        f = f + a + K[i] + block[g];
        let old_b = b; a = d; d = c; c = old_b; b = old_b + left_rotate(f, S[i]);
    }
    (*state)[0u] += a; (*state)[1u] += b; (*state)[2u] += c; (*state)[3u] += d;
}

fn phpass_hash(pwd: array<u32, 4>, len: u32) -> array<u32, 8> {
    let count = 1u << config.salt[8u];
    let salt_len = 8u;

    var state: array<u32, 4> = array<u32, 4>(0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u);
    var block: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { block[i] = 0u; }

    for (var i = 0u; i < salt_len; i++) {
        let ch = config.salt[salt_len - 1u - i] & 0xFFu;
        block[i / 4u] |= ch << ((i % 4u) * 8u);
    }
    for (var i = 0u; i < len; i++) {
        let ch = pwd[len - 1u - i] & 0xFFu;
        let dst = salt_len + i;
        block[dst / 4u] |= ch << ((dst % 4u) * 8u);
    }
    let total = salt_len + len;
    block[total / 4u] |= 0x80u << ((total % 4u) * 8u);
    block[14u] = total * 8u;
    block[15u] = 0u;
    md5_block(&state, block);

    for (var j = 0u; j < count; j++) {
        var next_state: array<u32, 4> = array<u32, 4>(0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u);
        for (var i = 0u; i < 16u; i++) { block[i] = 0u; }

        block[0] = state[0];
        block[1] = state[1];
        block[2] = state[2];
        block[3] = state[3];

        for (var i = 0u; i < len; i++) {
            let ch = pwd[len - 1u - i] & 0xFFu;
            let dst = 16u + i;
            block[dst / 4u] |= ch << ((dst % 4u) * 8u);
        }
        let total2 = 16u + len;
        block[total2 / 4u] |= 0x80u << ((total2 % 4u) * 8u);
        block[14u] = total2 * 8u;
        block[15u] = 0u;
        md5_block(&next_state, block);
        state = next_state;
    }

    return array<u32, 8>(state[0u], state[1u], state[2u], state[3u], 0u, 0u, 0u, 0u);
}

fn char_from_charset(d: u32, cs_id: u32) -> u32 {
    if (cs_id == 0u) { return d + 97u; }
    else if (cs_id == 1u) { return d + 65u; }
    else if (cs_id == 2u) { return d + 48u; }
    else {
        if (d < 26u) { return d + 97u; }
        else if (d < 52u) { return d - 26u + 65u; }
        else { return d - 52u + 48u; }
    }
}

fn index_to_password(index: u32, mask: ptr<function, array<u32, 16>>, len: u32) -> array<u32, 4> {
    var pwd: array<u32, 4>;
    var remaining = index;
    for (var i = 0u; i < 4u; i++) {
        if (i < len) {
            let sz = CS[(*mask)[i]];
            let d = remaining % sz;
            pwd[i] = char_from_charset(d, (*mask)[i]);
            remaining = remaining / sz;
        } else { pwd[i] = 0u; }
    }
    return pwd;
}

const MAX_DISPATCH_X: u32 = 65535u;

@compute @workgroup_size(128)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let index = config.range_start + id.y * MAX_DISPATCH_X * 128u + id.x;
    if (index >= config.range_end) { return; }
    if (atomicLoad(&config.found_flag) != 0u) { atomicAdd(&progress.count, 1u); return; }    let pwd = index_to_password(index, &config.mask, config.mask_len);
    let hash = phpass_hash(pwd, config.mask_len);
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
