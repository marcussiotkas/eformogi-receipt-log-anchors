# Eformogi Receipt-Log Anchors

External anchor for Eformogi's append-only receipt ledger. **Git commit history is the external timestamp** — Eformogi cannot rewrite it, which is the point.

## Layout

- `sth/<tree_size>.json` — Signed Tree Heads: the canonical signed body (`{version, log_id, tree_size, root_hash, chain_hash, timestamp, key_id}`) plus an Ed25519 `signature` (`z` + base58btc).
- `latest.json` — pointer to the newest STH.
- `leaves/<first>-<last>.jsonl` — the leaf payloads appended since the previous anchor. Each line is exactly `{"issued_at","prefix","receipt_id","sha256"}` — **never PII**. This makes the full log publicly reconstructible even if Eformogi's database is lost.

## Verify

Signing key: `did:web:eformogi.com#key-1` — public JWK at [https://eformogi.com/.well-known/did.json](https://eformogi.com/.well-known/did.json). Public JWK x (cross-check): `Oo09J95ausJIDH4nnNNy6wfKgveRbGgDsX9V3Y0xyMQ`

Any receipt exported from Eformogi verifies offline against these tree heads:

```bash
curl "https://eformogi.com/api/receipt-proof?id=<receipt_id>" > proof.json
node scripts/verify-receipt-offline.js --proof proof.json   # from the eformogi repo
```

Hashing: RFC 6962 (0x00 leaf / 0x01 node domain separation), SHA-256. STH bytes: `utf8("eformogi-sth-v1:" + canonical_json(body))`.

Writes to this repo come only from Eformogi's daily tree-head cron. If something stops being true here, that is itself the signal.
