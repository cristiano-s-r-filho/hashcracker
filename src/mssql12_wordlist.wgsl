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

fn rotr64(x: u64, n: u32) -> u64 { return (x >> n) | (x << (64u - n)); }
fn shr64(x: u64, n: u32) -> u64 { return x >> n; }

const KH: array<u32, 80> = array<u32, 80>(
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
    0xca273eceu, 0xd186b8c7u, 0xeada7dd6u, 0xf57d4f7fu,
    0x06f067aau, 0x0a637dc5u, 0x113f9804u, 0x1b710b35u,
    0x28db77f5u, 0x32caab7bu, 0x3c9ebe0au, 0x431d67c4u,
    0x4cc5d4beu, 0x597f299cu, 0x5fcb6fabu, 0x6c44198cu,
);

const KL: array<u32, 80> = array<u32, 80>(
    0xd728ae22u, 0x23ef65cdu, 0xec4d3b2fu, 0x8189dbbcu,
    0xf348b538u, 0xb605d019u, 0xaf194f9bu, 0xda6d8118u,
    0xa3030242u, 0x45706fbeu, 0x4ee4b28cu, 0xd5ffb4e2u,
    0xf27b896fu, 0x3b1696b1u, 0x25c71235u, 0xcf692694u,
    0x9ef14ad2u, 0x384f25e3u, 0x8b8cd5b5u, 0x77ac9c65u,
    0x592b0275u, 0x6ea6e483u, 0xbd41fbd4u, 0x831153b5u,
    0xee66dfabu, 0x2db43210u, 0x98fb213fu, 0xbeef0ee4u,
    0x3da88fc2u, 0x930aa725u, 0xe003826fu, 0x0a0e6e70u,
    0x46d22ffcu, 0x5c26c926u, 0x5ac42aedu, 0x9d95b3dfu,
    0x8baf63deu, 0x3c77b2a8u, 0x47edaee6u, 0x1482353bu,
    0x4cf10364u, 0xbc423001u, 0xd0f89791u, 0x0654be30u,
    0xd6ef5218u, 0x5565a910u, 0x5771202au, 0x32bbd1b8u,
    0xb8d2d0c8u, 0x5141ab53u, 0xdf8eeb99u, 0xe19b48a8u,
    0xc5c95a63u, 0xe3418acbu, 0x7763e373u, 0xd6b2b8a3u,
    0x5defb2fcu, 0x43172f60u, 0xa1f0ab72u, 0x1a6439ecu,
    0x23631e28u, 0xde82bde9u, 0xb2c67915u, 0xe372532bu,
    0xea26619cu, 0x21c0c207u, 0xcde0eb1eu, 0xee6ed178u,
    0x72176fbau, 0xa2c898a6u, 0xbef90daeu, 0x131c471bu,
    0x23047d84u, 0x40c72493u, 0x15c9bebcu, 0x9c100d4cu,
    0xcb3e42b6u, 0xfc657e2au, 0x3ad6faecu, 0x4a475817u,
);

fn sha512_block(state: ptr<function, array<u64, 8>>, block: array<u64, 16>) {
    var w: array<u64, 80>;
    for (var i = 0u; i < 16u; i++) { w[i] = block[i]; }
    for (var i = 16u; i < 80u; i++) {
        let s0 = rotr64(w[i - 15u], 1u) ^ rotr64(w[i - 15u], 8u) ^ shr64(w[i - 15u], 7u);
        let s1 = rotr64(w[i - 2u], 19u) ^ rotr64(w[i - 2u], 61u) ^ shr64(w[i - 2u], 6u);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }
    var a = (*state)[0u]; var b = (*state)[1u]; var c = (*state)[2u]; var d = (*state)[3u];
    var e = (*state)[4u]; var f = (*state)[5u]; var g = (*state)[6u]; var h = (*state)[7u];
    for (var i = 0u; i < 80u; i++) {
        let k = (u64(KH[i]) << 32u) | u64(KL[i]);
        let s1 = rotr64(e, 14u) ^ rotr64(e, 18u) ^ rotr64(e, 41u);
        let ch = (e & f) ^ ((~e) & g);
        let t1 = h + s1 + ch + k + w[i];
        let s0 = rotr64(a, 28u) ^ rotr64(a, 34u) ^ rotr64(a, 39u);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    (*state)[0u] += a; (*state)[1u] += b; (*state)[2u] += c; (*state)[3u] += d;
    (*state)[4u] += e; (*state)[5u] += f; (*state)[6u] += g; (*state)[7u] += h;
}

fn sha512(pwd: array<u32, 5>, len: u32) -> array<u64, 8> {
    var state: array<u64, 8>;

    let siv_hi = array<u32, 8>(0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u);
    let siv_lo = array<u32, 8>(0xf3bcc908u, 0x84caa73bu, 0xfe94f82bu, 0x5f1d36f1u, 0xade682d1u, 0x2b3e6c1fu, 0xfb41bd6bu, 0x137e2179u);
    for (var i = 0u; i < 8u; i++) {
        state[i] = (u64(siv_hi[i]) << 32u) | u64(siv_lo[i]);
    }

    var block: array<u64, 16>;
    for (var i = 0u; i < 16u; i++) { block[i] = u64(0u); }

    // Salt bytes first (big-endian)
    for (var i = 0u; i < config.salt_len && i < 16u; i++) {
        let ch = config.salt[config.salt_len - 1u - i] & 0xFFu;
        let dst_byte = i;
        let dst_word = dst_byte / 8u;
        let dst_shift = (7u - (dst_byte % 8u)) * 8u;
        block[dst_word] |= u64(ch) << dst_shift;
    }

    // Uppercase password bytes after salt
    for (var i = 0u; i < len && i < 16u; i++) {
        let c = pwd[len - 1u - i] & 0xFFu;
        let ch = select(c, c - 32u, c >= 97u && c <= 122u);
        let dst_byte = config.salt_len + i;
        let dst_word = dst_byte / 8u;
        let dst_shift = (7u - (dst_byte % 8u)) * 8u;
        block[dst_word] |= u64(ch) << dst_shift;
    }

    let total_len = config.salt_len + len;
    let pad_byte = total_len;
    let pad_word = pad_byte / 8u;
    let pad_shift = (7u - (pad_byte % 8u)) * 8u;
    block[pad_word] |= u64(0x80u) << pad_shift;

    block[15u] = u64(total_len) * u64(8u);

    sha512_block(&state, block);
    return state;
}

fn check_match(hash: array<u64, 8>) -> bool {
    for (var t = 0u; t < config.num_targets; t++) {
        var t_match = true;
        for (var i = 0u; i < 8u; i++) {
            let low = u32(hash[i] & u64(0xFFFFFFFFu));
            let high = u32(hash[i] >> 32u);
            if (low != targets[t].hash[i]) { t_match = false; }
            if (high != targets[t].hash_extra[i]) { t_match = false; }
        }
        if (t_match) { return true; }
    }
    return false;
}

const MAX_DISPATCH_X: u32 = 65535u;

@compute @workgroup_size(128)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let index = id.y * MAX_DISPATCH_X * 128u + id.x;
    if (index >= config.range_end) { return; }
    if (atomicLoad(&config.found_flag) != 0u) { atomicAdd(&progress.count, 1u); return; }
    let entry = word_buf[index];
    let hash = sha512(entry.chars, entry.len);
    if (check_match(hash)) {
        let prev = atomicCompareExchangeWeak(&config.found_flag, 0u, 1u);
        if (prev.old_value == 0u) { config.found_password[0] = index; }
    }
    atomicAdd(&progress.count, 1u);
}
