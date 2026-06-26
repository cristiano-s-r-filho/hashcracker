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

const K: array<u64, 80> = array<u64, 80>(
    0x428a2f98d728ae22u, 0x7137449123ef65cdu, 0xb5c0fbcfec4d3b2fu, 0xe9b5dba58189dbbcu,
    0x3956c25bf348b538u, 0x59f111f1b605d019u, 0x923f82a4af194f9bu, 0xab1c5ed5da6d8118u,
    0xd807aa98a3030242u, 0x12835b0145706fbeu, 0x243185be4ee4b28cu, 0x550c7dc3d5ffb4e2u,
    0x72be5d74f27b896fu, 0x80deb1fe3b1696b1u, 0x9bdc06a725c71235u, 0xc19bf174cf692694u,
    0xe49b69c19ef14ad2u, 0xefbe4786384f25e3u, 0x0fc19dc68b8cd5b5u, 0x240ca1cc77ac9c65u,
    0x2de92c6f592b0275u, 0x4a7484aa6ea6e483u, 0x5cb0a9dcbd41fbd4u, 0x76f988da831153b5u,
    0x983e5152ee66dfabu, 0xa831c66d2db43210u, 0xb00327c898fb213fu, 0xbf597fc7beef0ee4u,
    0xc6e00bf33da88fc2u, 0xd5a79147930aa725u, 0x06ca6351e003826fu, 0x142929670a0e6e70u,
    0x27b70a8546d22ffcu, 0x2e1b21385c26c926u, 0x4d2c6dfc5ac42aedu, 0x53380d139d95b3dfu,
    0x650a73548baf63deu, 0x766a0abb3c77b2a8u, 0x81c2c92e47edaee6u, 0x92722c851482353bu,
    0xa2bfe8a14cf10364u, 0xa81a664bbc423001u, 0xc24b8b70d0f89791u, 0xc76c51a30654be30u,
    0xd192e819d6ef5218u, 0xd69906245565a910u, 0xf40e35855771202au, 0x106aa07032bbd1b8u,
    0x19a4c116b8d2d0c8u, 0x1e376c085141ab53u, 0x2748774cdf8eeb99u, 0x34b0bcb5e19b48a8u,
    0x391c0cb3c5c95a63u, 0x4ed8aa4ae3418acbu, 0x5b9cca4f7763e373u, 0x682e6ff3d6b2b8a3u,
    0x748f82ee5defb2fcu, 0x78a5636f43172f60u, 0x84c87814a1f0ab72u, 0x8cc702081a6439ecu,
    0x90befffa23631e28u, 0xa4506cebde82bde9u, 0xbef9a3f7b2c67915u, 0xc67178f2e372532bu,
    0xca273eceea26619cu, 0xd186b8c721c0c207u, 0xeada7dd6cde0eb1eu, 0xf57d4f7fee6ed178u,
    0x06f067aa72176fbau, 0x0a637dc5a2c898a6u, 0x113f9804bef90daeu, 0x1b710b35131c471bu,
    0x28db77f523047d84u, 0x32caab7b40c72493u, 0x3c9ebe0a15c9bebcu, 0x431d67c49c100d4cu,
    0x4cc5d4becb3e42b6u, 0x597f299cfc657e2au, 0x5fcb6fab3ad6faecu, 0x6c44198c4a475817u,
);

fn rotr64(x: u64, n: u64) -> u64 { return (x >> n) | (x << (64u - n)); }
fn ch64(x: u64, y: u64, z: u64) -> u64 { return (x & y) ^ ((~x) & z); }
fn maj64(x: u64, y: u64, z: u64) -> u64 { return (x & y) ^ (x & z) ^ (y & z); }
fn sig0_64(x: u64) -> u64 { return rotr64(x, 28u) ^ rotr64(x, 34u) ^ rotr64(x, 39u); }
fn sig1_64(x: u64) -> u64 { return rotr64(x, 14u) ^ rotr64(x, 18u) ^ rotr64(x, 41u); }
fn gam0_64(x: u64) -> u64 { return rotr64(x, 1u) ^ rotr64(x, 8u) ^ (x >> 7u); }
fn gam1_64(x: u64) -> u64 { return rotr64(x, 19u) ^ rotr64(x, 61u) ^ (x >> 6u); }

fn sha384_block(state: ptr<function, array<u64, 8>>, block: array<u64, 16>) {
    var w: array<u64, 80>;
    for (var i = 0u; i < 16u; i++) { w[i] = block[i]; }
    for (var i = 16u; i < 80u; i++) { w[i] = gam1_64(w[i - 2u]) + w[i - 7u] + gam0_64(w[i - 15u]) + w[i - 16u]; }
    var a = (*state)[0u]; var b = (*state)[1u]; var c = (*state)[2u]; var d = (*state)[3u];
    var e = (*state)[4u]; var f = (*state)[5u]; var g = (*state)[6u]; var h = (*state)[7u];
    for (var i = 0u; i < 80u; i++) {
        let t1 = h + sig1_64(e) + ch64(e, f, g) + K[i] + w[i];
        let t2 = sig0_64(a) + maj64(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    (*state)[0u] += a; (*state)[1u] += b; (*state)[2u] += c; (*state)[3u] += d;
    (*state)[4u] += e; (*state)[5u] += f; (*state)[6u] += g; (*state)[7u] += h;
}

fn sha384(pwd: array<u32, 4>, len: u32) -> array<u64, 8> {
    var state: array<u64, 8> = array<u64, 8>(
        0xcbbb9d5dc1059ed8u, 0x629a292a367cd507u, 0x9159015a3070dd17u, 0x152fecd8f70e5939u,
        0x67332667ffc00b31u, 0x8eb44a8768581511u, 0xdb0c2e0d64f98fa7u, 0x47b5481dbefa4fa4u,
    );

    var block: array<u64, 16>;
    for (var i = 0u; i < 16u; i++) { block[i] = 0u; }

    for (var i = 0u; i < len && i < 32u; i++) {
        let ch = u64(pwd[len - 1u - i] & 0xFFu);
        let dst_byte = i;
        let dst_word = dst_byte / 8u;
        let dst_shift = u64((7u - (dst_byte % 8u)) * 8u);
        block[dst_word] |= ch << dst_shift;
    }

    for (var i = 0u; i < config.salt_len && i < 32u; i++) {
        let ch = u64(config.salt[config.salt_len - 1u - i] & 0xFFu);
        let dst_byte = len + i;
        let dst_word = dst_byte / 8u;
        let dst_shift = u64((7u - (dst_byte % 8u)) * 8u);
        block[dst_word] |= ch << dst_shift;
    }

    let pad_byte = len + config.salt_len;
    let pad_word = pad_byte / 8u;
    let pad_shift = u64((7u - (pad_byte % 8u)) * 8u);
    block[pad_word] |= 0x80u << pad_shift;

    block[15u] = u64(len + config.salt_len) * 8u;

    sha384_block(&state, block);
    return state;
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

fn check_match(hash: array<u64, 8>) -> bool {
    for (var t = 0u; t < config.num_targets; t++) {
        var t_match = true;
        for (var i = 0u; i < 6u; i++) {
            let hi = targets[t].hash[i];
            let lo = targets[t].hash_extra[i];
            let w = (u64(hi)) | (u64(lo) << 32u);
            if (hash[i] != w) { t_match = false; }
        }
        if (t_match) { return true; }
    }
    return false;
}

@compute @workgroup_size(128)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let index = config.range_start + id.y * 65535u * 128u + id.x;
    if (index >= config.range_end) { return; }
    if (atomicLoad(&config.found_flag) != 0u) { atomicAdd(&progress.count, 1u); return; }    let pwd = mask_index_to_password(index);
    let hash = sha384(pwd, config.mask_len);
    if (check_match(hash)) {
        let prev = atomicCompareExchangeWeak(&config.found_flag, 0u, 1u);
        if (prev.old_value == 0u) { config.found_password = pwd; }
    }
    atomicAdd(&progress.count, 1u);
}
