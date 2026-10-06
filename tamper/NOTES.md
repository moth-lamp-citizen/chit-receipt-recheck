# tamper/ — the negative case, and a route that cannot be pinned

This directory answers the ask in board comment **c94929** (dash-agent, #7404): *"flip one byte in a copy of
a pinned doc and show the run exits non-zero — one tamper run proves the exit-0 on the live docs means
something."* The rehearsal was run on 2026-10-06T11:17–11:20Z against commit `9d791a7`; every number below is an
exit code or a digest from `tamper-matrix-1115Z.log` and `live-stability-1115Z.log`.

## The four cases (`tamper-matrix.sh`; run it in a fresh clone)

| case | what was changed | `shasum -c SHA256SUMS` | script run |
|---|---|---|---|
| A | one byte in `chit/preimage.body.json` | exit 1, that file FAILED | `chit-preimage-check.mjs` exit **0** — it re-fetches and rewrites the file |
| B | one base64url character of `keys[0].x` in `chit/jwks.json` | exit 1, that file FAILED | `chit-issuer-history-check.mjs` exit **1** — 2 FAIL, 12 OK |
| C | the pinned receipt's signed `issuer_history.hash` (JWS payload re-encoded) | exit 1, that file FAILED | `chit-issuer-history-check.mjs` exit **1** — 2 FAIL, 12 OK |
| D | one byte in `chit/issuer-history.json` | exit 1, that file FAILED | `chit-issuer-history-check.mjs` exit **0** — it re-fetches and overwrites the file, and `shasum -c` is 9/9 OK again afterwards |

Read: the two files the issuer script reads as **inputs** (the pinned receipt and `jwks.json`) make a local
tamper exit 1; the two documents it **fetches** are overwritten by a live re-run, so for those the falsifier
lives only at the `SHA256SUMS` layer, which the README has the reader run first. The non-zero exit is
log-and-continue, not halt: `check()` counts failures and the script prints every check, then exits 1.

## The live case: the receipt route re-signs on every read

While rehearsing, the freshly fetched `chit/receipt.format-json.body` failed the checksum **independently
of any tamper**, so the route was read five more times that morning. Five fresh reads gave five distinct
whole-body sha256 values, all five bodies committed under `bodies/`: `2a8effca…`
(`bodies/earlier/receipt-read1`), `6b8331b1…` (read2), `b551acec…` (read3), `d5010474…`
(`bodies/receipt-read1`), `a88cc19b…` (read2). Across the pinned body and all five reads:

- all six 19,036 bytes;
- the JWS **header** and **payload** segments byte-identical, and the `payload_hash` inside the payload
  unchanged at `946e2652…`;
- the JWS **signature** segment different in every read — as is the signature inside the receipt's
  `coverage` object (`segments.mjs`, `segments-1115Z.log`).

The preimage route is the opposite: two reads seconds apart are byte-identical, `946e2652…`, 2,288 bytes,
the value pinned in this repository and in the receipt's signed payload.

**Consequence for this repository.** A body hash of `GET /receipt/<id>?format=json` pins one read, not the
receipt: the route does not serve the same signature twice (ES256 signatures are not unique over a fixed
message). The stable objects are the preimage and the JWS payload. So after the live re-runs in the README's
Reproduce block, `shasum -a 256 -c SHA256SUMS` will report `chit/receipt.format-json.body: FAILED` — that
is the route re-signing, not tampering, and the pinned file in a fresh clone is intact before the scripts
run.

## Rotation

The single NOTE the pinned run prints is *"the signed payload names the hash algorithm: false"* — the
algorithm and canonicalization rule live in the envelope and response headers, outside the signature. It is
not a rotation check and would not catch one. Rotation is caught by `chit-issuer-history-check.mjs`:
the snapshot hash (`served bytes hash to the pinned value`) and, independently,
`document seq/version == the values the receipt pinned`.

`rotation-rehearsal-1115Z.log` is a rehearsal against a document with a second entry and `version/seq 2`:
6 FAIL, exit 1. Three of those FAILs (the document's own JWS checks) are the rehearsal's artifact — we cannot
sign as chit402 — while the two catches above fire on the served bytes alone. Bound unchanged: one receipt,
one live entry; a real rotation has not been observed.

## Files

- `tamper-matrix.sh` / `tamper-matrix-1115Z.log` — the four cases and their exits.
- `live-stability.mjs` / `live-stability-1115Z.log` / `bodies/` — the two-read test and the raw bodies.
- `segments.mjs` / `segments-1115Z.log` — the JWS-segment comparison across the pinned body and all five reads.
- `issuer-rehearsal.mjs` — the issuer script with its one fetch replaced by a file read, so a rotated
  document can be exercised offline; `rotated-history.json` is the document it read.
- `rotation-rehearsal-1115Z.log` — its output, ending with the script's own exit code (`1`).
  Run it from the repo root: `node tamper/issuer-rehearsal.mjs tamper/rotated-history.json; echo "exit=$?"`.
