#!/bin/bash
# tamper/tamper-matrix.sh — the negative case for the pinned instruments, rehearsed four ways.
# Run from a fresh clone's root:   bash tamper/tamper-matrix.sh
# Needs: node, shasum. Cases B and C run chit-issuer-history-check.mjs, which makes one live GET to
# api.chit402.com; cases A and D run chit-preimage-check.mjs, which re-fetches three routes.
# The script mutates chit/ in place and restores it from a backup on exit (trap), so a copy is safe.
set -u
cd "$(dirname "$0")/.." || exit 2
BK=$(mktemp -d) || exit 2
cp -R chit "$BK/"
restore() { rm -rf chit; cp -R "$BK/chit" chit; }
trap 'restore; rm -rf "$BK"' EXIT
say() { printf '%s\n' "$*"; }
sum() { shasum -a 256 -c SHA256SUMS >/tmp/tamper-shasum.out 2>&1; say "  shasum -c exit=$?"; grep FAILED /tmp/tamper-shasum.out || say "  (no FAILED line)"; }

say "############ A — one byte flipped in chit/preimage.body.json ############"
node -e 'const fs=require("fs");const p="chit/preimage.body.json";const b=fs.readFileSync(p);b[b.length-2]^=0x01;fs.writeFileSync(p,b);'
sum
node chit-preimage-check.mjs > /tmp/tamper-A.out 2>&1; say "  chit-preimage-check.mjs exit=$? ($(tail -1 /tmp/tamper-A.out))"
say "  -> the script re-fetches and overwrites that file; the checksum layer is what catches the flip."

say
say "############ B — one hex character changed in chit/jwks.json (keys[0].x) ############"
restore
node -e 'const fs=require("fs");const p="chit/jwks.json";const j=JSON.parse(fs.readFileSync(p,"utf8"));const k=(j.keys||j)[0];k.x=(k.x[0]==="a"?"b":"a")+k.x.slice(1);fs.writeFileSync(p,JSON.stringify(j,null,2)+"\n");'
sum
node chit-issuer-history-check.mjs > /tmp/tamper-B.out 2>&1; say "  chit-issuer-history-check.mjs exit=$?"
grep -E "FAIL|result:" /tmp/tamper-B.out | sed "s/^/  /"

say
say "############ C — the pinned receipt's signed issuer_history.hash changed ############"
restore
node -e 'const fs=require("fs");const p="chit/receipt.format-json.body";const R=JSON.parse(fs.readFileSync(p,"utf8"));const [h,pl,s]=R.issuer_signature.jws.split(".");const P=JSON.parse(Buffer.from(pl,"base64url").toString("utf8"));P.issuer_history.hash="0".repeat(64);R.issuer_signature.jws=[h,Buffer.from(JSON.stringify(P)).toString("base64url"),s].join(".");fs.writeFileSync(p,JSON.stringify(R));'
sum
node chit-issuer-history-check.mjs > /tmp/tamper-C.out 2>&1; say "  chit-issuer-history-check.mjs exit=$?"
grep -E "FAIL|result:" /tmp/tamper-C.out | sed "s/^/  /"

say
say "############ D — one byte flipped in chit/issuer-history.json (a fetched document) ############"
restore
node -e 'const fs=require("fs");const p="chit/issuer-history.json";const b=fs.readFileSync(p);b[Math.floor(b.length/2)]^=0x01;fs.writeFileSync(p,b);'
sum
node chit-issuer-history-check.mjs > /tmp/tamper-D.out 2>&1; say "  chit-issuer-history-check.mjs exit=$? ($(tail -1 /tmp/tamper-D.out))"
sum
say
say "Read: the two files the scripts read as inputs (the pinned receipt, jwks.json) make a tamper exit 1;"
say "the two fetched documents are overwritten by a live re-run, so only shasum -c sees a flip in them."
