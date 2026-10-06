#!/usr/bin/env python3
"""Signer watch: find new signer / owner roles taken by watched wallets.

Two sources, both free:
  1. BSC event logs (NodeReal RPC) for a block window:
       SafeSetup / AddedOwner / RemovedOwner   -> Safe signer changes
       OwnershipTransferred (new or old owner) -> contract ownership
       RoleGranted (account)                   -> AccessControl roles
       Transfer from 0x0 (mint)                -> new-token genesis supply
  2. Safe Transaction Service "owners/<addr>/safes" on 6 chains, diffed
     against the previous snapshot -> Safes joined or left on any chain.

Inputs : --wallets  JSON [{"a": addr, "g": group}] (deposit addresses already removed)
         --prev     previous Safe snapshot JSON ({} or missing on the first run)
Outputs: --out      JSON with events, new snapshot and run stats

Keys are read from ~/.config/nodereal_url. Nothing is printed that contains keys.
"""
import argparse, json, os, sys, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
from Crypto.Hash import keccak

RPC = open(os.path.expanduser('~/.config/nodereal_url')).read().strip()
ZERO32 = '0x' + '0' * 64

def k256(s):
    k = keccak.new(digest_bits=256); k.update(s.encode()); return '0x' + k.hexdigest()

T = {
    'SafeSetup': k256('SafeSetup(address,address[],uint256,address,address)'),
    'AddedOwner': k256('AddedOwner(address)'),
    'RemovedOwner': k256('RemovedOwner(address)'),
    'OwnershipTransferred': k256('OwnershipTransferred(address,address)'),
    'RoleGranted': k256('RoleGranted(bytes32,address,address)'),
    'Transfer': k256('Transfer(address,address,uint256)'),
}
ROLES = {'0x' + '0' * 64: 'DEFAULT_ADMIN_ROLE'}
for r in ['MINTER_ROLE', 'PAUSER_ROLE', 'BURNER_ROLE', 'ADMIN_ROLE', 'OPERATOR_ROLE', 'UPGRADER_ROLE', 'MANAGER_ROLE']:
    ROLES[k256(r)] = r

SAFE_CHAINS = {'bsc': 'bsc', 'ethereum': 'mainnet', 'base': 'base', 'arbitrum': 'arbitrum', 'polygon': 'polygon', 'optimism': 'optimism'}

def rpc(method, params, tries=5):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    for i in range(tries):
        try:
            rq = urllib.request.Request(RPC, data=body, headers={'Content-Type': 'application/json'})
            j = json.load(urllib.request.urlopen(rq, timeout=90))
            if 'result' in j:
                return j['result']
            err = j.get('error')
        except Exception as e:
            err = str(e)[:120]
        time.sleep(1 + 2 * i)
    raise RuntimeError(f'rpc {method} failed: {err}')

def checksum(a):
    a = a.lower()[2:]
    h = keccak.new(digest_bits=256); h.update(a.encode()); h = h.hexdigest()
    return '0x' + ''.join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(a))

def topic_addr(a):
    return '0x' + '0' * 24 + a.lower()[2:]

def word_addr(w):
    return '0x' + w[-40:].lower()

# ---------- token / contract helpers ----------
_meta = {}
def call(to, data):
    try:
        return rpc('eth_call', [{'to': to, 'data': data}, 'latest'], tries=2)
    except Exception:
        return None

def dec_str(h):
    if not h or h == '0x':
        return ''
    b = bytes.fromhex(h[2:])
    try:
        if len(b) >= 64:
            ln = int.from_bytes(b[32:64], 'big')
            return b[64:64 + ln].decode('utf-8', 'ignore').strip()
        return b.rstrip(b'\x00').decode('utf-8', 'ignore').strip()
    except Exception:
        return ''

def meta(addr):
    if addr in _meta:
        return _meta[addr]
    m = {'name': dec_str(call(addr, '0x06fdde03')), 'symbol': dec_str(call(addr, '0x95d89b41'))}
    ts = call(addr, '0x18160ddd')
    m['supply'] = int(ts, 16) if ts and ts != '0x' else None
    o = call(addr, '0xa0e67e2b')  # getOwners() -> Safe
    if o and len(o) > 130:
        n = int(o[66:130], 16)
        m['safe_owners'] = ['0x' + o[130 + 64 * i + 24:130 + 64 * (i + 1)] for i in range(n)]
        th = call(addr, '0xe75235b8')
        m['safe_threshold'] = int(th, 16) if th else None
    _meta[addr] = m
    return m

def label_of(addr):
    m = meta(addr)
    if 'safe_owners' in m:
        return f"Safe {m.get('safe_threshold')}/{len(m['safe_owners'])}"
    nm = (m.get('symbol') or m.get('name') or '')[:40]
    return nm or 'contract'

# ---------- 1) BSC logs ----------
def get_logs(frm, to, topics):
    out, step = [], 2000
    b = frm
    while b <= to:
        e = min(b + step - 1, to)
        out += rpc('eth_getLogs', [{'fromBlock': hex(b), 'toBlock': hex(e), 'topics': topics}])
        b = e + 1
    return out

def block_ts(bn, cache={}):
    if bn not in cache:
        cache[bn] = int(rpc('eth_getBlockByNumber', [hex(bn), False])['timestamp'], 16)
    return cache[bn]

SPAM_WORDS = ('http', '.com', '.io', 'claim', 'visit', 'reward', 'airdrop', 'free', '$', 'www')

def scan_logs(wallets, frm, to):
    W = {w['a'].lower(): w for w in wallets}
    LT = [topic_addr(a) for a in W]
    ev = []
    def add(kind, wallet, target, log, detail):
        ev.append({'type': kind, 'chain': 'bsc', 'wallet': wallet, 'group': W[wallet].get('g', ''),
                   'target': target, 'target_label': label_of(target) if target else '',
                   'detail': detail, 'tx': log['transactionHash'], 'block': int(log['blockNumber'], 16),
                   'log': int(log['logIndex'], 16)})
    # F1: newOwner / role account in list (topic2)
    for l in get_logs(frm, to, [[T['OwnershipTransferred'], T['RoleGranted']], None, LT]):
        t0, who = l['topics'][0], word_addr(l['topics'][2])
        if t0 == T['OwnershipTransferred']:
            prev = word_addr(l['topics'][1])
            if prev == '0x' + '0' * 40:
                add('contract_owner_new', who, l['address'].lower(), l, 'became owner at creation (likely deployer)')
            else:
                add('contract_owner', who, l['address'].lower(), l, f'ownership received from {prev}')
        else:
            role = ROLES.get(l['topics'][1], l['topics'][1][:10] + '…')
            add('role_granted', who, l['address'].lower(), l, f'granted {role}')
    # F2: old owner in list, Safe v1.4.x Added/RemovedOwner (topic1)
    for l in get_logs(frm, to, [[T['OwnershipTransferred'], T['AddedOwner'], T['RemovedOwner']], LT]):
        t0, who = l['topics'][0], word_addr(l['topics'][1])
        if t0 == T['OwnershipTransferred']:
            new = word_addr(l['topics'][2])
            if new in W:  # already reported as receiver
                continue
            add('contract_owner_left', who, l['address'].lower(), l, f'gave ownership to {new}')
        elif t0 == T['AddedOwner']:
            add('safe_signer_added', who, l['address'].lower(), l, 'added as signer')
        else:
            add('safe_signer_removed', who, l['address'].lower(), l, 'removed as signer')
    # F3: SafeSetup (owners in data) and Safe v1.3.0 Added/RemovedOwner (owner in data)
    for l in get_logs(frm, to, [[T['SafeSetup'], T['AddedOwner'], T['RemovedOwner']]]):
        t0, d = l['topics'][0], l['data'][2:]
        if t0 == T['SafeSetup']:
            try:
                off = int(d[0:64], 16) // 32
                n = int(d[64 * off:64 * (off + 1)], 16)
                owners = [word_addr(d[64 * (off + 1 + i):64 * (off + 2 + i)]) for i in range(n)]
                th = int(d[64:128], 16)
            except Exception:
                continue
            for o in owners:
                if o in W:
                    add('safe_signer_new', o, l['address'].lower(), l, f'signer of a NEW Safe ({th}/{len(owners)})')
        elif len(l['topics']) == 1 and len(d) >= 64:
            who = word_addr(d[:64])
            if who in W:
                add('safe_signer_added' if t0 == T['AddedOwner'] else 'safe_signer_removed', who, l['address'].lower(), l,
                    'added as signer' if t0 == T['AddedOwner'] else 'removed as signer')
    # F4: mints to list (ERC20 only: 3 topics), keep >= 1% of supply, skip LP / spam
    for l in get_logs(frm, to, [T['Transfer'], ZERO32, LT]):
        if len(l['topics']) != 3 or l['data'] in ('0x', ''):
            continue
        who, tok, v = word_addr(l['topics'][2]), l['address'].lower(), int(l['data'], 16)
        m = meta(tok)
        nm = f"{m.get('name','')} {m.get('symbol','')}".lower()
        if 'lp' in nm.split() or 'pancake' in nm or 'uniswap' in nm or any(s in nm for s in SPAM_WORDS):
            continue
        sup = m.get('supply') or 0
        if sup and v * 100 >= sup:
            add('genesis_mint', who, tok, l, f'received {v*100/sup:.1f}% of supply at mint')
    # de-dup and timestamps
    seen, out = set(), []
    for e in sorted(ev, key=lambda x: (x['block'], x['log'])):
        k = (e['type'], e['wallet'], e['target'], e['tx'])
        if k in seen:
            continue
        seen.add(k)
        e['ts'] = block_ts(e['block'])
        out.append(e)
    return out

# ---------- 2) Safe Transaction Service snapshot ----------
def safes_of(addr, net):
    u = f'https://safe-transaction-{net}.safe.global/api/v1/owners/{checksum(addr)}/safes/'
    for i in range(5):
        try:
            return [s.lower() for s in json.load(urllib.request.urlopen(urllib.request.Request(u, headers={'User-Agent': 'Mozilla/5.0'}), timeout=30))['safes']]
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return []
            time.sleep(2 + 3 * i)
        except Exception:
            time.sleep(2 + 2 * i)
    return None  # unknown (do not diff)

def safe_info(safe, net):
    u = f'https://safe-transaction-{net}.safe.global/api/v1/safes/{checksum(safe)}/'
    try:
        j = json.load(urllib.request.urlopen(urllib.request.Request(u, headers={'User-Agent': 'Mozilla/5.0'}), timeout=30))
        return {'threshold': j.get('threshold'), 'owners': [o.lower() for o in j.get('owners', [])]}
    except Exception:
        return {}

def snapshot(wallets, chains, workers=8):
    snap, unknown = {}, 0
    jobs = [(w['a'].lower(), c) for w in wallets for c in chains]
    with ThreadPoolExecutor(workers) as ex:
        res = list(ex.map(lambda j: safes_of(j[0], SAFE_CHAINS[j[1]]), jobs))
    for (a, c), r in zip(jobs, res):
        if r is None:
            unknown += 1
            snap.setdefault(c, {}).setdefault('__unknown__', []).append(a)
            continue
        for s in r:
            snap.setdefault(c, {}).setdefault(s, []).append(a)
    return snap, unknown

def diff(prev, cur, wallets):
    G = {w['a'].lower(): w.get('g', '') for w in wallets}
    ev = []
    for c, safes in cur.items():
        unk = set(cur.get(c, {}).get('__unknown__', []))
        for s, ws in safes.items():
            if s == '__unknown__':
                continue
            old = set(prev.get(c, {}).get(s, []))
            for w in set(ws) - old:
                ev.append({'type': 'safe_signer_joined', 'chain': c, 'wallet': w, 'group': G.get(w, ''), 'target': s,
                           'target_label': 'Safe', 'detail': 'now a signer (Safe API)'})
        for s, ws in prev.get(c, {}).items():
            if s == '__unknown__':
                continue
            for w in set(ws) - set(safes.get(s, [])) - unk:
                if w in G:
                    ev.append({'type': 'safe_signer_left', 'chain': c, 'wallet': w, 'group': G.get(w, ''), 'target': s,
                               'target_label': 'Safe', 'detail': 'no longer a signer (Safe API)'})
    return ev

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--wallets', required=True)
    ap.add_argument('--prev', default='')
    ap.add_argument('--out', required=True)
    ap.add_argument('--hours', type=float, default=26)
    ap.add_argument('--from-block', type=int)
    ap.add_argument('--to-block', type=int)
    ap.add_argument('--chains', default=','.join(SAFE_CHAINS))
    ap.add_argument('--no-snapshot', action='store_true')
    a = ap.parse_args()
    wallets = json.load(open(a.wallets))
    t0 = time.time()
    head = a.to_block or int(rpc('eth_blockNumber', []), 16)
    frm = a.from_block if a.from_block else head - int(a.hours * 3600 / 0.45)
    events = scan_logs(wallets, frm, head)
    prev = json.load(open(a.prev)) if a.prev and os.path.exists(a.prev) else {}
    snap, unknown = ({}, 0) if a.no_snapshot else snapshot(wallets, a.chains.split(','))
    if snap and prev:
        bsc_seen = {(e['wallet'], e['target']) for e in events if e['chain'] == 'bsc'}
        events += [e for e in diff(prev, snap, wallets) if (e['wallet'], e['target']) not in bsc_seen or e['chain'] != 'bsc']
    for e in events:
        if e['type'].startswith('safe_signer') and e.get('target'):
            net = SAFE_CHAINS.get(e['chain'])
            info = safe_info(e['target'], net) if net else {}
            if info:
                e['target_label'] = f"Safe {info.get('threshold')}/{len(info.get('owners', []))}"
                e['co_signers_in_list'] = sorted(set(info.get('owners', [])) & {w['a'].lower() for w in wallets} - {e['wallet']})
    out = {'run_ts': int(time.time()), 'from_block': frm, 'to_block': head, 'wallets': len(wallets),
           'chains': a.chains.split(','), 'events': events, 'snapshot': snap, 'snapshot_unknown': unknown,
           'first_run': not prev, 'seconds': round(time.time() - t0)}
    json.dump(out, open(a.out, 'w'))
    print(json.dumps({k: v for k, v in out.items() if k not in ('events', 'snapshot')} | {'events': len(events)}))

if __name__ == '__main__':
    main()
