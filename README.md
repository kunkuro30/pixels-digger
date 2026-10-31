# pixels-digger

Parallel nonce searcher for the **Agentic Pixels** free dig
(BSC contract `0xcb2Be11420eFbb51b19ADC76732550d5D40A3E5f`, Sourcify-verified).

## The puzzle

`startDig()` issues your wallet a ticket `{seed, icon, difficulty}` (valid 24 hours).
`claimFree(nonce)` mints the free NFT when

```
matched(keccak256(seed || nonce), icon) >= difficulty
```

`matched()` counts how many leading bits of the hash's first 64 bits equal the
icon's 64-bit pixel pattern. Expected work is `2^difficulty` hashes
(difficulty 36 ≈ 6.9×10^10). One CPU core of the included scalar Keccak does
roughly 0.25–1 MH/s, so a single machine needs many hours; the GitHub Actions
workflow fans the search out across parallel runners.

## Safety

- The ticket **seed is public on-chain data** (emitted in the `DigStarted` event).
- This tool holds **no private keys** and signs nothing. The found nonce is
  claimed afterwards from the operator's own wallet.

## Local use

```bash
make            # or: gcc -O3 -march=native -pthread -o digger digger.c
./digger --selftest
./digger --eval   <seed_hex64> <icon> <nonce>            # check one nonce
./digger --search <seed_hex64> <icon> <difficulty> <start> <end> <threads>
```

On success it prints `FOUND nonce=... hash=... matched=...` and writes `found.txt`.

## GitHub Actions use

1. Push this folder as a repository (public repos get free standard runners).
2. Actions → **dig** → Run workflow, with the ticket's seed / icon / difficulty.
   Defaults: 32 parallel jobs × 2^32 nonces = 2^37 covered (≈86% chance the
   solution is inside for difficulty 36; re-run with `offset` = 137438953472
   to scan the next slab).
3. Download the artifacts; the winning job's `found.txt` contains the nonce.
4. Claim from the wallet with `claimFree(nonce)` before the ticket's 24h TTL ends.

## Files

- `digger.c` — self-contained multithreaded Keccak-256 searcher (icons table included).
- `.github/workflows/dig.yml` — the parallel fan-out.
- `run.sh` — local convenience wrapper.
