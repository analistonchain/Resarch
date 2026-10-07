# Signer watch

Daily check of whether a watched wallet took a new signer or owner role.

What it looks for:

| Source | Chains | Finds |
|---|---|---|
| Event logs (NodeReal RPC) | BNB Chain | new Safe with the wallet as signer, signer added or removed, contract ownership received or given away (incl. at deployment), AccessControl role granted, ≥1% of a new token's supply received at mint |
| Safe Transaction Service | BNB Chain, Ethereum, Base, Arbitrum, Polygon, Optimism | Safes the wallet signs today, compared with the previous day |

No wallet list, entity id or key lives in this folder. The list comes from Arkham entities at run time
(`wallets.py`), exchange deposit addresses are dropped using Arkham labels (only new addresses cost a
label lookup), and keys are read from the `NODEREAL_URL` / `ARKHAM_KEY` environment variables, else from `~/.config/`.

## One run

```
python3 sigwatch/wallets.py --entity A=<entity id> --entity B=<entity id> --cache cache.json --out wallets.json
python3 sigwatch/to_db.py --snapshot-only --prev-dir prev --out-dir docs     # previous Safe snapshot from the db read
python3 sigwatch/scan.py --wallets wallets.json --prev docs/prev_snapshot.json --out run.json --hours 26
python3 sigwatch/to_db.py --run run.json --cache cache.json --wallets wallets.json --prev-dir prev --out-dir docs
```

`docs/` then holds one JSON file per artifact-db document (`sigwatch/state`, `sigwatch/cache`,
`sigwatch_safes/<chain>`, `sigwatch_days/<date>`), written to the report page's database.
A run takes about 10 minutes, almost all of it the Safe API pass.
