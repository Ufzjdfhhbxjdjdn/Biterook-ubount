import re
import hashlib

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hash160(pubkey: bytes) -> bytes:
    sha = hashlib.new('ripemd160')
    sha.update(hashlib.sha256(pubkey).digest())
    return sha.digest()

def detect_script_type(script: str) -> str:
    """Detect script type from scriptSig or witness structure."""
    if script.startswith("76a914") and script.endswith("88ac"):
        return "P2PKH"
    elif script.startswith("0014"):
        return "P2WPKH"
    elif script.startswith("a914") and script.endswith("87"):
        return "P2SH"
    elif script.startswith("0020"):
        return "P2WSH"
    elif script.startswith("2102") or script.startswith("4104"):
        return "P2PK"
    else:
        return "unknown"

def extract_rsz(script: str) -> tuple:
    """Extract r, s from scriptSig assuming DER-encoded signature."""
    try:
        sig_len = int(script[2:4], 16)
        der_sig = script[4:4+sig_len*2]
        r_len = int(der_sig[6:8], 16)
        r = der_sig[8:8 + r_len*2]
        s_offset = 8 + r_len*2 + 2
        s_len = int(der_sig[8 + r_len*2:8 + r_len*2 + 2], 16)
        s = der_sig[s_offset:s_offset + s_len*2]
        return r, s
    except:
        return '', ''

def extract_pubkey(script: str) -> str:
    """Extract pubkey from scriptSig if possible."""
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
    """Compute the sighash (z) for the transaction input using legacy format."""
    try:
        e = rawtx + script_pubkey + "01000000"
        z = sha256(sha256(bytes.fromhex(e))).hex()
        return z
    except:
        return ''
# ==============================================================================
# Smart Similar R Detection - Injected AI Logic
def is_r_similar(r1, r2, threshold=0.9):
    # Compare similarity of two r values by bitwise hamming distance
    if len(r1) != len(r2):
        return False
    diff = sum(c1 != c2 for c1, c2 in zip(bin(int(r1, 16))[2:].zfill(256), bin(int(r2, 16))[2:].zfill(256)))
    similarity = 1 - (diff / 256)
    return similarity >= threshold

def find_similar_r_pairs(r_list, threshold=0.9):
    similar_pairs = []
    for i in range(len(r_list)):
        for j in range(i+1, len(r_list)):
            if is_r_similar(r_list[i], r_list[j], threshold):
                similar_pairs.append((i, j, r_list[i], r_list[j]))
    return similar_pairs
# ==============================================================================
