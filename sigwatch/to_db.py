#!/usr/bin/env python3
"""Turn a scan.py result into artifact-db documents (one JSON file per document).

  python3 to_db.py --run run.json --cache cache.json --prev-dir prev/ --out-dir docs/

prev/ holds what the db had before this run (as saved by ArtifactData read with out_dir):
  prev/sigwatch_safes/<chain>.json, prev/sigwatch_days/<date>.json
docs/ gets:
  docs/sigwatch/state.json, docs/sigwatch/cache.json,
  docs/sigwatch_safes/<chain>.json, docs/sigwatch_days/<date>.json
and docs/prev_snapshot.json is written for the NEXT scan when called with --snapshot-only.
"""
import argparse, glob, json, os, time, datetime, urllib.request
from Crypto.Hash import keccak

SAFE_NET = {'bsc': 'bsc', 'ethereum': 'mainnet', 'base': 'base', 'arbitrum': 'arbitrum', 'polygon': 'polygon', 'optimism': 'optimism'}

def checksum(a):
    a = a.lower()[2:]
    h = keccak.new(digest_bits=256); h.update(a.encode()); h = h.hexdigest()
    return '0x' + ''.join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(a))

def body(path):
    j = json.load(open(path))
    return j.get('data', j) if isinstance(j, dict) else j

def safe_info(safe, chain):
    u = f'https://safe-transaction-{SAFE_NET[chain]}.safe.global/api/v1/safes/{checksum(safe)}/'
    for i in range(3):
        try:
            j = json.load(urllib.request.urlopen(urllib.request.Request(u, headers={'User-Agent': 'Mozilla/5.0'}), timeout=30))
            return j.get('threshold'), len(j.get('owners', []))
        except Exception:
            time.sleep(1 + i)
    return None, None

def prev_snapshot(prev_dir):
    snap = {}
    for f in glob.glob(os.path.join(prev_dir, 'sigwatch_safes', '*.json')):
        chain = os.path.basename(f)[:-5]
        for r in body(f).get('rows', []):
            snap.setdefault(chain, {})[r['safe']] = r['wallets']
    return snap

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--run'); ap.add_argument('--cache'); ap.add_argument('--prev-dir', default='prev')
    ap.add_argument('--out-dir', default='docs'); ap.add_argument('--wallets')
    ap.add_argument('--backfill', action='store_true', help='history load: do not report events as new')
    ap.add_argument('--snapshot-only', action='store_true', help='only write prev_snapshot.json from prev-dir')
    a = ap.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)
    if a.snapshot_only:
        json.dump(prev_snapshot(a.prev_dir), open(os.path.join(a.out_dir, 'prev_snapshot.json'), 'w'))
        return
    run = json.load(open(a.run))
    groups = {w['a']: w['g'] for w in json.load(open(a.wallets))} if a.wallets else {}
    for d in ('sigwatch', 'sigwatch_safes', 'sigwatch_days'):
        os.makedirs(os.path.join(a.out_dir, d), exist_ok=True)
    # Safes: keep threshold/owner counts from the previous rows, look up only new Safes
    old = {}
    for f in glob.glob(os.path.join(a.prev_dir, 'sigwatch_safes', '*.json')):
        for r in body(f).get('rows', []):
            old[(os.path.basename(f)[:-5], r['safe'])] = r
    total = 0
    for chain, safes in (run.get('snapshot') or {}).items():
        rows = []
        for s, ws in sorted(safes.items()):
            if s == '__unknown__':
                continue
            o = old.get((chain, s), {})
            th, n = (o.get('threshold'), o.get('owners_n')) if 'threshold' in o else safe_info(s, chain)
            ws = sorted(set(ws))
            rows.append({'safe': s, 'wallets': ws, 'groups': [groups.get(w, '') for w in ws], 'threshold': th, 'owners_n': n})
        total += len(rows)
        json.dump({'chain': chain, 'updated_ts': run['run_ts'], 'rows': rows}, open(os.path.join(a.out_dir, 'sigwatch_safes', chain + '.json'), 'w'))
    # Days: merge new events into the existing day documents
    by_day = {}
    for e in run.get('events', []):
        e = dict(e); e['found_ts'] = run['run_ts']
        day = datetime.datetime.utcfromtimestamp(e.get('ts') or run['run_ts']).strftime('%Y-%m-%d')
        by_day.setdefault(day, []).append(e)
    for day, evs in by_day.items():
        pf = os.path.join(a.prev_dir, 'sigwatch_days', day + '.json')
        cur = body(pf).get('events', []) if os.path.exists(pf) else []
        keys = {(x['type'], x['chain'], x['wallet'], x.get('target'), x.get('tx')) for x in cur}
        for e in evs:
            k = (e['type'], e['chain'], e['wallet'], e.get('target'), e.get('tx'))
            if k not in keys:
                cur.append(e); keys.add(k)
        cur.sort(key=lambda x: x.get('ts') or x.get('found_ts') or 0)
        json.dump({'date': day, 'run_ts': run['run_ts'], 'events': cur}, open(os.path.join(a.out_dir, 'sigwatch_days', day + '.json'), 'w'))
    cache = json.load(open(a.cache)) if a.cache else {}
    json.dump(cache, open(os.path.join(a.out_dir, 'sigwatch', 'cache.json'), 'w'))
    state = {'last_run_ts': run['run_ts'], 'wallets': run['wallets'], 'deposit_excluded': len(cache.get('deposit', [])),
             'chains': run.get('chains', []), 'from_block': run.get('from_block'), 'to_block': run.get('to_block'),
             'events_last': len(run.get('events', [])), 'safes_total': total, 'first_run': run.get('first_run', False),
             'snapshot_unknown': run.get('snapshot_unknown', 0),
             'last_events': run.get('events', [])[-50:] if not a.backfill else []}
    json.dump(state, open(os.path.join(a.out_dir, 'sigwatch', 'state.json'), 'w'))
    # Public file for the page (no sign-in needed): state + Safes + last 30 day documents
    days = {}
    for f in glob.glob(os.path.join(a.prev_dir, 'sigwatch_days', '*.json')) + glob.glob(os.path.join(a.out_dir, 'sigwatch_days', '*.json')):
        d = body(f); days[d['date']] = d  # files written this run come last and win
    safes = {}
    for f in glob.glob(os.path.join(a.out_dir, 'sigwatch_safes', '*.json')):
        safes[os.path.basename(f)[:-5]] = body(f).get('rows', [])
    pub = {k: v for k, v in state.items()}
    pub.update({'safes': safes, 'days': [days[k] for k in sorted(days, reverse=True)[:30]]})
    os.makedirs(os.path.join(a.out_dir, 'public'), exist_ok=True)
    json.dump(pub, open(os.path.join(a.out_dir, 'public', 'sigwatch.json'), 'w'), separators=(',', ':'))
    print(json.dumps({'safes_total': total, 'day_docs': sorted(by_day), 'events': len(run.get('events', []))}))

if __name__ == '__main__':
    main()
