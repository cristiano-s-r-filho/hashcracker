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

fn set_byte(buf: ptr<function, array<u32, 64>>, pos: u32, val: u32) {
    let w = pos / 4u;
    let s = (pos % 4u) * 8u;
    (*buf)[w] |= (val & 0xFFu) << s;
}

fn md5_bytes(data: array<u32, 64>, len: u32) -> array<u32, 4> {
    var state: array<u32, 4> = array<u32, 4>(
        0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u,
    );

    var offset = 0u;
    while (offset + 64u <= len) {
        var block: array<u32, 16>;
        for (var i = 0u; i < 16u; i++) { block[i] = 0u; }
        for (var i = 0u; i < 64u; i++) {
            let val = (data[(offset + i) / 4u] >> (((offset + i) % 4u) * 8u)) & 0xFFu;
            let w = i / 4u;
            let s = (i % 4u) * 8u;
            block[w] |= val << s;
        }
        md5_block(&state, block);
        offset += 64u;
    }

    var block: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { block[i] = 0u; }
    let remaining = len - offset;
    for (var i = 0u; i < remaining; i++) {
        let val = (data[(offset + i) / 4u] >> (((offset + i) % 4u) * 8u)) & 0xFFu;
        let w = i / 4u;
        let s = (i % 4u) * 8u;
        block[w] |= val << s;
    }

    let pad_pos = remaining;
    block[pad_pos / 4u] |= 0x80u << ((pad_pos % 4u) * 8u);

    if (remaining >= 56u) {
        md5_block(&state, block);
        for (var i = 0u; i < 16u; i++) { block[i] = 0u; }
    }

    block[14u] = len * 8u;
    block[15u] = 0u;
    md5_block(&state, block);

    return state;
}

fn md5crypt_hash(pwd: array<u32, 5>, pwd_len: u32) -> array<u32, 4> {
    var digest: array<u32, 4>;
    var msg: array<u32, 64>;
    var pos: u32;

    // digest_b = MD5(password + salt + password)
    for (var i = 0u; i < 64u; i++) { msg[i] = 0u; }
    pos = 0u;
    for (var i = 0u; i < pwd_len; i++) {
        set_byte(&msg, pos + i, pwd[pwd_len - 1u - i] & 0xFFu);
    }
    pos += pwd_len;
    for (var i = 0u; i < config.salt_len; i++) {
        set_byte(&msg, pos + i, config.salt[config.salt_len - 1u - i] & 0xFFu);
    }
    pos += config.salt_len;
    for (var i = 0u; i < pwd_len; i++) {
        set_byte(&msg, pos + i, pwd[pwd_len - 1u - i] & 0xFFu);
    }
    pos += pwd_len;
    var digest_b = md5_bytes(msg, pos);

    // Build full initial message: password + "$1$" + salt + digest_b + bit processing
    for (var i = 0u; i < 64u; i++) { msg[i] = 0u; }
    pos = 0u;
    for (var i = 0u; i < pwd_len; i++) {
        set_byte(&msg, pos + i, pwd[pwd_len - 1u - i] & 0xFFu);
    }
    pos += pwd_len;
    set_byte(&msg, pos, 0x24u); pos++;
    set_byte(&msg, pos, 0x31u); pos++;
    set_byte(&msg, pos, 0x24u); pos++;
    for (var i = 0u; i < config.salt_len; i++) {
        set_byte(&msg, pos + i, config.salt[config.salt_len - 1u - i] & 0xFFu);
    }
    pos += config.salt_len;

    var j = 0u;
    while (j < pwd_len) {
        let n = min(pwd_len - j, 16u);
        for (var k = 0u; k < n; k++) {
            let byte_idx = k % 4u;
            let word_idx = k / 4u;
            set_byte(&msg, pos + k, (digest_b[word_idx] >> (byte_idx * 8u)) & 0xFFu);
        }
        pos += n;
        j += 16u;
    }

    var n = pwd_len;
    while (n > 0u) {
        if ((n & 1u) != 0u) {
            set_byte(&msg, pos, 0u);
        } else {
            set_byte(&msg, pos, pwd[pwd_len - 1u] & 0xFFu);
        }
        pos++;
        n = n >> 1u;
    }

    digest = md5_bytes(msg, pos);

    // 1000 rounds
    for (var i = 0u; i < 1000u; i++) {
        for (var k = 0u; k < 64u; k++) { msg[k] = 0u; }
        pos = 0u;

        if ((i & 1u) != 0u) {
            for (var k = 0u; k < pwd_len; k++) {
                set_byte(&msg, pos + k, pwd[pwd_len - 1u - k] & 0xFFu);
            }
            pos += pwd_len;
        } else {
            for (var k = 0u; k < 4u; k++) {
                set_byte(&msg, pos + k * 4u + 0u, (digest[k] >> 0u) & 0xFFu);
                set_byte(&msg, pos + k * 4u + 1u, (digest[k] >> 8u) & 0xFFu);
                set_byte(&msg, pos + k * 4u + 2u, (digest[k] >> 16u) & 0xFFu);
                set_byte(&msg, pos + k * 4u + 3u, (digest[k] >> 24u) & 0xFFu);
            }
            pos += 16u;
        }

        if ((i % 3u) != 0u) {
            for (var k = 0u; k < config.salt_len; k++) {
                set_byte(&msg, pos + k, config.salt[config.salt_len - 1u - k] & 0xFFu);
            }
            pos += config.salt_len;
        }

        if ((i % 7u) != 0u) {
            for (var k = 0u; k < pwd_len; k++) {
                set_byte(&msg, pos + k, pwd[pwd_len - 1u - k] & 0xFFu);
            }
            pos += pwd_len;
        }

        if ((i & 1u) != 0u) {
            for (var k = 0u; k < 4u; k++) {
                set_byte(&msg, pos + k * 4u + 0u, (digest[k] >> 0u) & 0xFFu);
                set_byte(&msg, pos + k * 4u + 1u, (digest[k] >> 8u) & 0xFFu);
                set_byte(&msg, pos + k * 4u + 2u, (digest[k] >> 16u) & 0xFFu);
                set_byte(&msg, pos + k * 4u + 3u, (digest[k] >> 24u) & 0xFFu);
            }
            pos += 16u;
        } else {
            for (var k = 0u; k < pwd_len; k++) {
                set_byte(&msg, pos + k, pwd[pwd_len - 1u - k] & 0xFFu);
            }
            pos += pwd_len;
        }

        digest = md5_bytes(msg, pos);
    }

    return digest;
}

const MAX_DISPATCH_X: u32 = 65535u;

@compute @workgroup_size(128)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let index = id.y * MAX_DISPATCH_X * 128u + id.x;
    if (index >= config.range_end) { return; }
    if (atomicLoad(&config.found_flag) != 0u) { atomicAdd(&progress.count, 1u); return; }    let entry = word_buf[index];
    let hash = md5crypt_hash(entry.chars, entry.len);
    var match_found = false;
    for (var t = 0u; t < config.num_targets; t++) {
        var t_match = true;
        for (var i = 0u; i < 4u; i++) { if (hash[i] != targets[t].hash[i]) { t_match = false; } }
        if (t_match) { match_found = true; }
    }
    if (match_found) {
        let prev = atomicCompareExchangeWeak(&config.found_flag, 0u, 1u);
        if (prev.old_value == 0u) { config.found_password[0] = index; }
    }
    atomicAdd(&progress.count, 1u);
}
