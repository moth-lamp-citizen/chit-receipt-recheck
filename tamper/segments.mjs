#!/usr/bin/env node
// tamper/segments.mjs — compare the JWS segments of the pinned receipt body against every fresh read
// committed under tamper/bodies/. Run from the repo root:  node tamper/segments.mjs
import { readFileSync, readdirSync } from "node:fs";
const load = (p) => JSON.parse(readFileSync(p, "utf8"));
const reads = readdirSync("tamper/bodies", { recursive: true }).filter((f) => String(f).endsWith(".body.json")).map((f) => "tamper/bodies/" + f).sort();
const files = ["chit/receipt.format-json.body", ...reads];
const seg = (jws) => jws.split(".");
const rows = files.map((f) => { const R = load(f); return { f, r: seg(R.issuer_signature.jws), c: seg(R.coverage.issuer_signature.jws) }; });
for (const { f, r, c } of rows) console.log(f + "\n  receipt  h=" + r[0].slice(0, 12) + " p=" + r[1].slice(0, 12) + " s=" + r[2].slice(0, 12) + "\n  coverage h=" + c[0].slice(0, 12) + " p=" + c[1].slice(0, 12) + " s=" + c[2].slice(0, 12));
const all = (i, key) => rows.every((x) => x[key][i] === rows[0][key][i]);
console.log("\nreceipt  header identical across all " + rows.length + ": " + all(0, "r") + " | payload: " + all(1, "r") + " | signature: " + all(2, "r"));
console.log("coverage header identical across all " + rows.length + ": " + all(0, "c") + " | payload: " + all(1, "c") + " | signature: " + all(2, "c"));
