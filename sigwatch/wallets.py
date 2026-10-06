#!/usr/bin/env python3
"""Build the watch list for scan.py from Arkham entities, minus exchange deposit addresses.

  python3 wallets.py --entity A=<arkham entity id> --entity B=<arkham entity id> \
      --cache cache.json --out wallets.json

cache.json (kept between runs): {"checked": {addr: label}, "deposit": [addr, ...]}
Only addresses not yet in "checked" cost an Arkham label lookup.
The Arkham key is read from ~/.config/arkham_key and never printed.
"""
import argparse, json, os, time, urllib.request, urllib.error

K = open(os.path.expanduser('~/.config/arkham_key')).read().strip()

def ark(path):
    rq = urllib.request.Request('https://api.arkm.com' + path, headers={'API-Key': K, 'User-Agent': 'Mozilla/5.0'})
    for i in range(4):
        try:
            return json.load(urllib.request.urlopen(rq, timeout=60))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(3 + 3 * i); continue
            return {}
        except Exception:
            time.sleep(2)
    return {}

def label(addr):
    j = ark(f'/intelligence/address/{addr}?chain=bsc')
    time.sleep(0.35)
    return ((j.get('arkhamLabel') or {}).get('name') or '') + ' | ' + ((j.get('arkhamEntity') or {}).get('name') or '')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--entity', action='append', required=True, help='GROUP=entity_id')
    ap.add_argument('--cache', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    cache = json.load(open(a.cache)) if os.path.exists(a.cache) else {'checked': {}, 'deposit': []}
    if 'checked' not in cache and isinstance(cache.get('data'), dict):  # file saved by an ArtifactData read
        cache = cache['data']
    checked, deposit = cache.get('checked', {}), set(cache.get('deposit', []))
    rows, new_lookups = {}, 0
    for spec in a.entity:
        g, eid = spec.split('=', 1)
        ent = ark(f'/user/entities/{eid}')
        for addr in (ent.get('addresses') or {}).get('evm', []):
            rows.setdefault(addr.lower(), g)
    for addr in rows:
        if addr not in checked:
            checked[addr] = label(addr); new_lookups += 1
            if 'deposit' in checked[addr].lower():
                deposit.add(addr)
    wallets = [{'a': x, 'g': g} for x, g in sorted(rows.items()) if x not in deposit]
    json.dump(wallets, open(a.out, 'w'))
    json.dump({'checked': checked, 'deposit': sorted(deposit)}, open(a.cache, 'w'))
    print(json.dumps({'entity_wallets': len(rows), 'deposit_excluded': len([x for x in rows if x in deposit]),
                      'watched': len(wallets), 'new_label_lookups': new_lookups}))

if __name__ == '__main__':
    main()
