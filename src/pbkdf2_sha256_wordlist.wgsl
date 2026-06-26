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

const SIGMA: array<u32, 64> = array<u32, 64>(
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

fn sha256_block(state: ptr<function, array<u32, 8>>, block: array<u32, 16>) {
    var w: array<u32, 64>;
    for (var i = 0u; i < 16u; i++) { w[i] = block[i]; }
    for (var i = 16u; i < 64u; i++) {
        let s0 = ((w[i - 15u] >> 7u) | (w[i - 15u] << 25u)) ^
                 ((w[i - 15u] >> 18u) | (w[i - 15u] << 14u)) ^
                 (w[i - 15u] >> 3u);
        let s1 = ((w[i - 2u] >> 17u) | (w[i - 2u] << 15u)) ^
                 ((w[i - 2u] >> 19u) | (w[i - 2u] << 13u)) ^
                 (w[i - 2u] >> 10u);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }
    var a = (*state)[0u]; var b = (*state)[1u]; var c = (*state)[2u]; var d = (*state)[3u];
    var e = (*state)[4u]; var f = (*state)[5u]; var g = (*state)[6u]; var hh = (*state)[7u];
    for (var i = 0u; i < 64u; i++) {
        let S1 = ((e >> 6u) | (e << 26u)) ^ ((e >> 11u) | (e << 21u)) ^ ((e >> 25u) | (e << 7u));
        let ch = (e & f) ^ ((~e) & g);
        let temp1 = hh + S1 + ch + SIGMA[i] + w[i];
        let S0 = ((a >> 2u) | (a << 30u)) ^ ((a >> 13u) | (a << 19u)) ^ ((a >> 22u) | (a << 10u));
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = S0 + maj;
        hh = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }
    (*state)[0u] += a; (*state)[1u] += b; (*state)[2u] += c; (*state)[3u] += d;
    (*state)[4u] += e; (*state)[5u] += f; (*state)[6u] += g; (*state)[7u] += hh;
}

fn sha256_init() -> array<u32, 8> {
    return array<u32, 8>(0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                         0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u);
}

fn sha256_two_block(block0: array<u32, 16>, msg: ptr<function, array<u32, 16>>, msg_len: u32) -> array<u32, 8> {
    var state = sha256_init();
    sha256_block(&state, block0);
    var block1: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { block1[i] = 0u; }
    for (var i = 0u; i < msg_len && i < 64u; i++) {
        let src_word = i / 4u;
        let src_shift = (3u - (i % 4u)) * 8u;
        let byte = ((*msg)[src_word] >> src_shift) & 0xFFu;
        let dst_word = i / 4u;
        let dst_shift = (3u - (i % 4u)) * 8u;
        block1[dst_word] |= byte << dst_shift;
    }
    let pad_byte = msg_len;
    if (pad_byte < 64u) {
        let pw = pad_byte / 4u;
        let ps = (3u - (pad_byte % 4u)) * 8u;
        block1[pw] |= 0x80u << ps;
    }
    block1[15u] = (64u + msg_len) * 8u;
    sha256_block(&state, block1);
    return state;
}

fn hmac_sha256(password: array<u32, 5>, pwd_len: u32, msg: ptr<function, array<u32, 16>>, msg_len: u32) -> array<u32, 8> {
    var key: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { key[i] = 0u; }
    for (var i = 0u; i < pwd_len && i < 64u; i++) {
        let byte = password[pwd_len - 1u - i] & 0xFFu;
        let dst_word = i / 4u;
        let dst_shift = (3u - (i % 4u)) * 8u;
        key[dst_word] |= byte << dst_shift;
    }
    var ipad: array<u32, 16>;
    var opad: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) {
        let k = key[i];
        var ip: u32 = 0u; var op: u32 = 0u;
        for (var b = 0u; b < 4u; b++) {
            let shift = b * 8u;
            let kb = (k >> shift) & 0xFFu;
            ip |= (kb ^ 0x36u) << shift;
            op |= (kb ^ 0x5cu) << shift;
        }
        ipad[i] = ip;
        opad[i] = op;
    }
    var inner = sha256_two_block(ipad, msg, msg_len);
    var inner_data: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { inner_data[i] = 0u; }
    for (var i = 0u; i < 8u; i++) { inner_data[i] = inner[i]; }
    var outer = sha256_two_block(opad, &inner_data, 32u);
    return outer;
}

fn pbkdf2_sha256(password: array<u32, 5>, pwd_len: u32, iterations: u32) -> array<u32, 8> {
    var msg: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { msg[i] = 0u; }
    for (var i = 0u; i < config.salt_len && i < 16u; i++) {
        let byte = config.salt[config.salt_len - 1u - i] & 0xFFu;
        let dst_word = i / 4u;
        let dst_shift = (3u - (i % 4u)) * 8u;
        msg[dst_word] |= byte << dst_shift;
    }
    // Append block index (1) as big-endian u32
    let salt_bytes = config.salt_len;
    for (var b = 0u; b < 4u; b++) {
        let byte_pos = salt_bytes + b;
        let dst_word = byte_pos / 4u;
        let dst_shift = (3u - (byte_pos % 4u)) * 8u;
        let byte_val = (1u >> (24u - b * 8u)) & 0xFFu;
        msg[dst_word] |= byte_val << dst_shift;
    }
    var u = hmac_sha256(password, pwd_len, &msg, salt_bytes + 4u);
    var result = u;
    for (var i = 1u; i < iterations; i++) {
        var u_data: array<u32, 16>;
        for (var j = 0u; j < 16u; j++) { u_data[j] = 0u; }
        for (var j = 0u; j < 8u; j++) { u_data[j] = u[j]; }
        u = hmac_sha256(password, pwd_len, &u_data, 32u);
        for (var j = 0u; j < 8u; j++) {
            result[j] ^= u[j];
        }
    }
    return result;
}

const MAX_DISPATCH_X: u32 = 65535u;

@compute @workgroup_size(128)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let index = id.y * MAX_DISPATCH_X * 128u + id.x;
    if (index >= config.range_end) { return; }
    if (atomicLoad(&config.found_flag) != 0u) { atomicAdd(&progress.count, 1u); return; }    let entry = word_buf[index];
    let iterations = config.target_hash_extra[0];
    let hash = pbkdf2_sha256(entry.chars, entry.len, iterations);
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
