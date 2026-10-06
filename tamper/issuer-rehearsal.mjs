#!/usr/bin/env node
// REHEARSAL VARIANT (tamper/): the fetch of /.well-known/issuer-history.json is replaced by a file read,
// so a rotated document can be exercised offline. Usage from the repo root:
//   node tamper/issuer-rehearsal.mjs tamper/rotated-history.json ; echo "exit=$?"
// Second half of the c94614 re-run: the issuer-history document the receipt pins.
// The receipt's SIGNED payload carries issuer_history {hash, version, seq}; this script fetches
// https://api.chit402.com/.well-known/issuer-history.json, recomputes the entry chain the document's
// own canonicalization text names, and checks whether the served bytes hash to the pinned value.
// Read-only, unauthenticated public GETs only.
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

// HERE is the repository root (this file lives in tamper/), so the script reads ./chit/.
const HERE = path.join(path.dirname(new URL(import.meta.url).pathname), "..");
const API = "https://api.chit402.com";
const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const b64u = (s) => Buffer.from(s, "base64url");
// Sort keys recursively and stringify ONCE. (A first version of this script returned
// JSON.stringify(...) from the recursive helper, which double-encoded every nested value; the two
// FAILs it printed were this script's bug, not chit402's, and were fixed here rather than shipped.)
const canon = (v) => Array.isArray(v) ? v.map(canon)
  : (v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])])) : v);
const jcs = (v) => JSON.stringify(canon(v));
const say = (...a) => console.log(...a);
let failures = 0;
const check = (label, ok, detail = "") => { if (!ok) failures++; say(`  ${ok ? "OK  " : "FAIL"} ${label}${detail ? " — " + detail : ""}`); };

const receipt = JSON.parse(readFileSync(path.join(HERE, "chit", "receipt.format-json.body"), "utf8"));
const pinned = JSON.parse(b64u(receipt.issuer_signature.jws.split(".")[1]).toString("utf8")).issuer_history;

const raw = readFileSync(process.argv[2]);
const r = { status: "REHEARSAL-LOCAL" };
const doc = JSON.parse(raw.toString("utf8"));

say(`# chit402 issuer-history re-run — ${new Date().toISOString()}`);
say(`# receipt pins issuer_history ${JSON.stringify(pinned)}`);
say(`# GET ${API}/.well-known/issuer-history.json -> ${r.status}, ${raw.length} bytes`);
say(`# document: schema=${doc.schema} version=${doc.version} seq=${doc.seq} entries=${doc.entries.length} head_hash=${doc.head_hash}\n`);

// 1. does the served document hash to the value the signed receipt pins?
say("## 1. snapshot hash");
const servedHash = sha256(raw);
const jcsHash = sha256(Buffer.from(jcs(doc), "utf8"));
say(`  sha256(bytes as served)        = ${servedHash}`);
say(`  sha256(JCS re-serialization)   = ${jcsHash}`);
say(`  pinned inside the signed receipt = ${pinned.hash}`);
check("served bytes hash to the pinned value", servedHash === pinned.hash);
check("the pinned value is also the JCS hash (i.e. served bytes are JCS)", jcsHash === pinned.hash,
  servedHash === jcsHash ? "the two agree" : "as-served and JCS hashes DIFFER");

// is the served document key-sorted at every level? (tells a stranger whether 'as served' == 'JCS')
const sortedEverywhere = (v, p = "$") => {
  if (Array.isArray(v)) return v.every((x, i) => sortedEverywhere(x, `${p}[${i}]`));
  if (!v || typeof v !== "object") return true;
  const ks = Object.keys(v);
  const ok = ks.every((k, i) => i === 0 || ks[i - 1] < k);
  if (!ok) say(`  keys out of order at ${p}: ${ks.join(",")}`);
  return ok && ks.every((k) => sortedEverywhere(v[k], `${p}.${k}`));
};
check("every object in the served document has its keys in sorted order", sortedEverywhere(doc));

// 2. the entry chain, by the document's own rule
say("\n## 2. entry chain (rule: SHA-256 of the JCS UTF-8 bytes of the entry without entry_hash)");
let prev = null, chainOk = true;
for (const [i, e] of doc.entries.entries()) {
  const body = { ...e }; delete body.entry_hash;
  const recomputed = sha256(Buffer.from(jcs(body), "utf8"));
  const hashOk = recomputed === e.entry_hash;
  const linkOk = (e.prev_hash ?? null) === prev;
  chainOk = chainOk && hashOk && linkOk;
  say(`  entry[${i}] kid=${e.kid} status=${e.status} not_before=${e.not_before}`);
  check(`entry[${i}] entry_hash recomputes from the entry without entry_hash`, hashOk, hashOk ? "" : `recomputed ${recomputed}, served ${e.entry_hash}`);
  check(`entry[${i}] prev_hash links to the previous entry`, linkOk, `prev_hash=${e.prev_hash} expected ${prev}`);
  prev = e.entry_hash;
}
check("head_hash == last entry_hash", doc.head_hash === prev, `${doc.head_hash} vs ${prev}`);
check("document seq/version == the values the receipt pinned",
  doc.version === pinned.version && doc.seq === pinned.seq, `${doc.version}/${doc.seq} vs ${pinned.version}/${pinned.seq}`);
check("entry kid == the receipt's signing kid", doc.entries.some((e) => e.kid === receipt.issuer_signature.kid));

// 3. the document's own signature
say("\n## 3. document signature");
const ds = doc.issuer_signature;
const [dh, dp, dj] = ds.jws.split(".");
const dHeader = JSON.parse(b64u(dh).toString("utf8"));
const dPayload = JSON.parse(b64u(dp).toString("utf8"));
say(`  header ${JSON.stringify(dHeader)}`);
say(`  signed payload = ${JSON.stringify(dPayload)}`);
const key = createPublicKey({ key: ds.issuer_jwk, format: "jwk" });
const okSig = cryptoVerify("sha256", Buffer.from(`${dh}.${dp}`, "utf8"),
  { key, dsaEncoding: "ieee-p1363" }, b64u(dj));
check("document JWS verifies against its own embedded key", okSig);
check("signed payload names head_hash", dPayload.head_hash === doc.head_hash, String(dPayload.head_hash));
check("signed payload names entry_count", String(dPayload.entry_count) === String(doc.entries.length),
  `${dPayload.entry_count} vs ${doc.entries.length}`);
check("signed payload names version and seq (the sealed-snapshot fields)",
  String(dPayload.version) === String(doc.version) && String(dPayload.seq) === String(doc.seq),
  `${dPayload.version}/${dPayload.seq}`);

// 4. key identity across the three places it appears
say("\n## 4. key identity");
const jwks = JSON.parse(readFileSync(path.join(HERE, "chit", "jwks.json"), "utf8"));
const jk = (jwks.keys || jwks)[0];
const entryJwk = doc.entries[0].jwk;
const same = (a, b) => a && b && a.x === b.x && a.y === b.y && a.crv === b.crv && a.kty === b.kty;
check("JWKS key == receipt-embedded key", same(jk, receipt.issuer_signature.issuer_jwk));
check("JWKS key == history entry key", same(jk, entryJwk));
say(`  kid in all three: ${jk.kid}`);
say(`  custody note (from the history entry): ${String(doc.entries[0].custody).slice(0, 140)}…`);

say(`\n## result: ${failures === 0 ? "every check passed" : failures + " check(s) FAILED"}`);
process.exit(failures === 0 ? 0 : 1);
