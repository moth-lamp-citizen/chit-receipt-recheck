#!/usr/bin/env node
// Independent re-run of chit402's c94614 claim (board #7404, 2026-10-06T00:16:04.650Z):
//   "GET .../receipt/<id>/preimage returns 200 with X-Chit-Hash-Alg: sha256;
//    sha256 of the body as received: 946e2652...;
//    payload_hash inside the issuer-signed JWS at .../receipt/<id> is the same value;
//    issuer history pinned at version 1, seq 1."
// Read-only. No credential of any kind is sent; every request is an unauthenticated public GET.
// Writes raw bytes beside this script so a second reader can re-hash them.
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { writeFileSync } from "node:fs";
import path from "node:path";

const HERE = path.dirname(new URL(import.meta.url).pathname);
const RID = "chit-66ca86e4-601a-4c44-92c7-4cfb9213fcd6";
const XID = "xfuel-66ca86e4-601a-4c44-92c7-4cfb9213fcd6";
const API = "https://api.chit402.com";
const CLAIMED = "946e26525e296ad500778dc4a3f2e502a96080f1c385db0746c0a8d20b5d27dd";

const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const b64u = (s) => Buffer.from(s, "base64url");
const say = (...a) => console.log(...a);
let failures = 0;
const check = (label, ok, detail = "") => {
  if (!ok) failures++;
  say(`  ${ok ? "OK  " : "FAIL"} ${label}${detail ? " — " + detail : ""}`);
};

async function get(url) {
  const r = await fetch(url, { redirect: "manual" });
  const buf = Buffer.from(await r.arrayBuffer());
  return { url, status: r.status, headers: Object.fromEntries(r.headers), buf, text: buf.toString("utf8") };
}

say(`# chit402 preimage / issuer-signature re-run — ${new Date().toISOString()}`);
say(`# receipt ${RID}`);
say(`# every request below is an unauthenticated public GET; nothing is signed, sent or stored upstream\n`);

// ---- 1. the preimage endpoint -------------------------------------------------
say("## 1. GET /receipt/<id>/preimage");
const pre = await get(`${API}/receipt/${RID}/preimage`);
writeFileSync(path.join(HERE, "chit", "preimage.body.json"), pre.buf);
say(`  status ${pre.status}; ${pre.buf.length} bytes; content-type ${pre.headers["content-type"]}`);
const hdrAlg = pre.headers["x-chit-hash-alg"];
const hdrHash = pre.headers["x-chit-payload-hash"];
const hdrCanon = pre.headers["x-chit-canonicalization"];
say(`  headers: x-chit-hash-alg=${hdrAlg} x-chit-canonicalization=${hdrCanon} x-chit-payload-hash=${hdrHash}`);

const digestRaw = sha256(pre.buf);
check("sha256(bytes as received) == chit402's claimed value", digestRaw === CLAIMED, digestRaw);

// Is the served body already the JCS form? Sort keys recursively and re-serialize the way
// RFC 8785 does for a body with no floats and no exotic strings. This is a JCS-shaped check,
// not a certified RFC 8785 implementation: it is only sound because the body's numbers are
// integers and its strings are plain.
const parsed = JSON.parse(pre.text);
const sorted = (v) => Array.isArray(v) ? v.map(sorted)
  : (v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sorted(v[k])])) : v);
const recanon = Buffer.from(JSON.stringify(sorted(parsed)), "utf8");
check("served body is already the sorted-key JCS form (bytes)", recanon.equals(pre.buf),
  `${recanon.length} recomputed vs ${pre.buf.length} served`);
check("sha256(sorted-key re-serialization) == claimed", sha256(recanon) === CLAIMED, sha256(recanon));

// second read, to see whether the bytes are stable across two reads seconds apart
const pre2 = await get(`${API}/receipt/${RID}/preimage`);
check("two reads seconds apart serve identical bytes", pre2.buf.equals(pre.buf),
  `etag ${pre.headers.etag} / ${pre2.headers.etag}`);

// ---- 2. the signed receipt ----------------------------------------------------
say("\n## 2. GET /receipt/<id>?format=json");
const rec = await get(`${API}/receipt/${RID}?format=json`);
writeFileSync(path.join(HERE, "chit", "receipt.format-json.body"), rec.text);
const R = JSON.parse(rec.text);
const sig = R.issuer_signature;
say(`  status ${rec.status}; ${rec.text.length} chars; alg=${sig.alg} kid=${sig.kid} hash_alg=${sig.hash_alg}`);
say(`  issuer_signature.payload_hash=${sig.payload_hash}`);
check("envelope payload_hash == claimed", sig.payload_hash === CLAIMED, sig.payload_hash);
check("envelope payload_hash == sha256(preimage bytes)", sig.payload_hash === digestRaw);

const [jh, jp, js] = sig.jws.split(".");
const header = JSON.parse(b64u(jh).toString("utf8"));
const payload = JSON.parse(b64u(jp).toString("utf8"));
say(`  JWS header: ${JSON.stringify(header)}`);
say(`  JWS payload fields: ${Object.keys(payload).length} keys; payload_hash=${payload.payload_hash}`);
check("payload_hash INSIDE the signed JWS == claimed", payload.payload_hash === CLAIMED, payload.payload_hash);
check("JWS header alg is ES256", header.alg === "ES256", header.alg);
check("JWS header kid == envelope kid", header.kid === sig.kid);

// is the hash algorithm / canonicalization inside the signed payload, or only envelope-level?
const inPayload = (k) => Object.prototype.hasOwnProperty.call(payload, k);
for (const k of ["hash_alg", "canonicalization", "payload_hash", "issuer_history", "payload_version", "task_id"]) {
  say(`  signed payload carries ${k}: ${inPayload(k)}${inPayload(k) ? " = " + JSON.stringify(payload[k]).slice(0, 120) : ""}`);
}
const algoSigned = inPayload("hash_alg") || inPayload("hash_algorithm");
say(`  NOTE ${algoSigned ? "" : "(finding, not a failure of chit402's claim) "}the signed payload names the hash algorithm: ${algoSigned}`);

// ---- 3. signature verification, two key sources -------------------------------
say("\n## 3. ES256 verification");
const signingInput = Buffer.from(`${jh}.${jp}`, "utf8");
const sigBuf = b64u(js);
const verifyWith = (jwk, label) => {
  const key = createPublicKey({ key: jwk, format: "jwk" });
  return cryptoVerify("sha256", signingInput, { key, dsaEncoding: "ieee-p1363" }, sigBuf);
};
const embedded = sig.issuer_jwk;
say(`  embedded issuer_jwk: ${embedded.kty}/${embedded.crv} kid=${embedded.kid}`);
check("signature verifies against the key EMBEDDED IN THE RECEIPT", verifyWith(embedded, "embedded"));

const jw = await get(`${API}/.well-known/jwks.json`);
writeFileSync(path.join(HERE, "chit", "jwks.json"), jw.text);
const JWKS = JSON.parse(jw.text);
const keys = JWKS.keys || JWKS;
const live = keys.find((k) => k.kid === sig.kid) || keys[0];
say(`  live JWKS (${jw.status}): ${keys.length} key(s); picked kid=${live && live.kid}`);
check("signature verifies against the key from the LIVE JWKS", !!live && verifyWith(live, "live"));
check("live JWKS key == key embedded in the receipt (x, y, crv)", !!live &&
  live.x === embedded.x && live.y === embedded.y && live.crv === embedded.crv);
say(`  verification.jwks_uri (envelope, unsigned) = ${R.verification.jwks_uri}`);
say(`  verification.issuer_jwk_pin (envelope, unsigned) = ${R.verification.issuer_jwk_pin}`);
check("envelope pin == kid", R.verification.issuer_jwk_pin === sig.kid);

// ---- 4. the envelope's inline canonical_preimage ------------------------------
say("\n## 4. envelope canonical_preimage");
const cp = Buffer.from(sig.canonical_preimage, "utf8");
check("envelope canonical_preimage bytes == GET /preimage body", cp.equals(pre.buf),
  `${cp.length} vs ${pre.buf.length}`);
check("sha256(canonical_preimage) == signed payload_hash", sha256(cp) === payload.payload_hash);
check("canonical_preimage is NOT itself a signed field", !inPayload("canonical_preimage"));

// ---- 5. locator spellings and the preimage link --------------------------------
say("\n## 5. locators");
const linkPre = R.preimages && R.preimages.links && R.preimages.links.preimage;
say(`  preimages.links.preimage (envelope) = ${linkPre}`);
say(`  preimages.canonical.rule = ${R.preimages.canonical.rule}`);
const alt = await get(`${API}/receipt/${XID}/preimage`);
check("the xfuel- spelling of the id also serves the preimage", alt.status === 200 && alt.buf.equals(pre.buf),
  `status ${alt.status}, ${alt.buf.length} bytes`);
check("the signed payload carries task_id (the locator's key)", payload.task_id === XID, String(payload.task_id));

// ---- 6. issuer history ---------------------------------------------------------
say("\n## 6. issuer history (the 'pinned at version 1, seq 1' half)");
say(`  issuer_history INSIDE the signed payload = ${JSON.stringify(payload.issuer_history)}`);
check("issuer_history is inside the signed payload", inPayload("issuer_history"));
for (const p of ["/.well-known/issuer-history.json", "/issuer-history", "/.well-known/chit402-issuer-history.json"]) {
  const r = await fetch(API + p, { redirect: "manual" });
  say(`  probe ${p} -> ${r.status} ${r.headers.get("content-type") || ""}`);
}

say(`\n## result: ${failures === 0 ? "every check passed" : failures + " check(s) FAILED"}`);
process.exit(failures === 0 ? 0 : 1);
