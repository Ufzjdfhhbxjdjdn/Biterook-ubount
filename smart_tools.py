import hashlib
import secp256k1 as ice

N = ice.N

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hash160(pubkey: bytes) -> bytes:
    sha = hashlib.new('ripemd160')
    sha.update(hashlib.sha256(pubkey).digest())
    return sha.digest()

def extract_rsz(script: str) -> tuple:
    try:
        sig_len = int(script[2:4], 16)
        der_sig = script[4:4 + sig_len*2]
        r_len = int(der_sig[6:8], 16)
        r = der_sig[8:8 + r_len*2]
        s_offset = 8 + r_len*2 + 2
        s_len = int(der_sig[8 + r_len*2:8 + r_len*2 + 2], 16)
        s = der_sig[s_offset:s_offset + s_len*2]
        return r, s
    except:
        return '', ''

def extract_pubkey(script: str) -> str:
    try:
        sig_len = int(script[2:4], 16)
        pubkey_len_index = 4 + sig_len * 2
        pubkey_len = int(script[pubkey_len_index:pubkey_len_index+2], 16)
        pubkey = script[pubkey_len_index+2:]
        return pubkey
    except:
        return ''

def extract_rsz_pubkey(script: str) -> tuple:
    r, s = extract_rsz(script)
    pub = extract_pubkey(script)
    return r, s, pub

def get_signing_hash(rawtx: str, script_pubkey: str) -> str:
    try:
        e = rawtx + script_pubkey + "01000000"
        z = sha256(sha256(bytes.fromhex(e))).hex()
        return z
    except:
        return ''

def is_r_similar(r1, r2, threshold=0.9):
    if len(r1) != len(r2): return False
    diff = sum(c1 != c2 for c1, c2 in zip(bin(int(r1, 16))[2:].zfill(256), bin(int(r2, 16))[2:].zfill(256)))
    similarity = 1 - (diff / 256)
    return similarity >= threshold

def smiler(r1, r2):
    if r1 == r2:
        print(f'[⚠️] Exact match between r1 and r2: {r1}')
    elif is_r_similar(r1, r2, 0.94):
        print(f'[⚠️] R values are highly similar: r1={r1}, r2={r2}')
    else:
        print(f'[OK] No strong similarity between r1 and r2')

def find_similar_r_pairs(r_list, threshold=0.9):
    similar_pairs = []
    for i in range(len(r_list)):
        for j in range(i+1, len(r_list)):
            if is_r_similar(r_list[i], r_list[j], threshold):
                similar_pairs.append((i, j, r_list[i], r_list[j]))
                smiler(r_list[i], r_list[j])
    return similar_pairs

def find_duplicate_r(r_list):
    seen = set()
    for i, r in enumerate(r_list):
        if r in seen:
            print(f'[⚠️] Duplicate r value: {r} (index {i})')
        seen.add(r)

def s_is_weak(s: int) -> bool:
    return s < 2**10 or s > N - 2**10

def analyze_s_values(s_list):
    for i, s in enumerate(s_list):
        if s_is_weak(s):
            print(f'[⚠️] Weak s value (index {i}): {hex(s)}')

def find_duplicate_s(s_list):
    seen = set()
    for i, s in enumerate(s_list):
        if s in seen:
            print(f'[⚠️] Duplicate s value: {hex(s)} (index {i})')
        seen.add(s)

def find_duplicate_z(z_list):
    seen = set()
    for i, z in enumerate(z_list):
        if z in seen:
            print(f'[⚠️] Duplicate z value: {hex(z)} (index {i})')
        seen.add(z)

def z_is_zero(z: int) -> bool:
    return z == 0

def analyze_z_values(z_list):
    for i, z in enumerate(z_list):
        if z_is_zero(z):
            print(f'[⚠️] z=0 at index {i}')

def check_rsz_to_pubkey_match(r: int, s: int, z: int, pub_hex: str):
    RP1 = ice.pub2upub('02' + hex(r)[2:].zfill(64))
    RP2 = ice.pub2upub('03' + hex(r)[2:].zfill(64))
    sdr = (s * pow(r, N - 2, N)) % N
    zdr = (z * pow(r, N - 2, N)) % N
    FF1 = ice.point_subtraction(ice.point_multiplication(RP1, sdr), ice.scalar_multiplication(zdr))
    FF2 = ice.point_subtraction(ice.point_multiplication(RP2, sdr), ice.scalar_multiplication(zdr))
    pub = ice.pub2upub(pub_hex)
    if FF1 == pub or FF2 == pub:
        print('[✓] RSZ ↔ PubKey match confirmed.')
    else:
        print('[x] RSZ ↔ PubKey mismatch.')

def getk1(r1, s1, z1, r2, s2, z2, m):
    nr = (s2 * m * r1 + z1 * r2 - z2 * r1) % N
    dr = (s1 * r2 - s2 * r1) % N
    return (nr * pow(dr, N - 2, N)) % N

def getpvk(r1, s1, z1, r2, s2, z2, m):
    x1 = (s2 * z1 - s1 * z2 + m * s1 * s2) % N
    xi = pow((s1 * r2 - s2 * r1), N - 2, N)
    return (x1 * xi) % N

def analyze_all(r_list, s_list, z_list, pub_list):
    print('\n🔍 R similarity and duplication check:')
    find_duplicate_r(r_list)
    find_similar_r_pairs([hex(r)[2:].zfill(64) for r in r_list], threshold=0.94)

    print('\n🔍 Weak or duplicate S check:')
    analyze_s_values(s_list)
    find_duplicate_s(s_list)

    print('\n🔍 Z duplication or weakness check:')
    analyze_z_values(z_list)
    find_duplicate_z(z_list)

    print('\n🔍 RSZ to PubKey consistency:')
    for i in range(len(r_list)):
        try:
            check_rsz_to_pubkey_match(r_list[i], s_list[i], z_list[i], pub_list[i])
        except:
            print(f'[x] RSZ ↔ PubKey match failed at index {i}')