#!/usr/bin/env node
// tamper/live-stability.mjs — read the two chit402 routes twice each and report byte-stability.
// Run from the repo root:  node tamper/live-stability.mjs
import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
const RID = "chit-66ca86e4-601a-4c44-92c7-4cfb9213fcd6";
const sha = (b) => createHash("sha256").update(b).digest("hex");
const get = async (u) => { const r = await fetch(u, { redirect: "manual" }); return { status: r.status, b: Buffer.from(await r.arrayBuffer()) }; };
const seg = (b) => { try { return JSON.parse(b.toString("utf8")).issuer_signature.jws.split("."); } catch { return ["?", "?", "?"]; } };
console.log("# live-stability — " + new Date().toISOString());
const r1 = await get("https://api.chit402.com/receipt/" + RID + "?format=json");
const r2 = await get("https://api.chit402.com/receipt/" + RID + "?format=json");
writeFileSync("tamper/bodies/receipt-read1.body.json", r1.b);
writeFileSync("tamper/bodies/receipt-read2.body.json", r2.b);
const s1 = seg(r1.b), s2 = seg(r2.b);
console.log("receipt read 1: " + r1.status + " " + r1.b.length + " bytes sha256=" + sha(r1.b));
console.log("receipt read 2: " + r2.status + " " + r2.b.length + " bytes sha256=" + sha(r2.b));
console.log("receipt JWS header  identical: " + (s1[0] === s2[0]));
console.log("receipt JWS payload identical: " + (s1[1] === s2[1]));
console.log("receipt JWS signature identical: " + (s1[2] === s2[2]));
const p1 = await get("https://api.chit402.com/receipt/" + RID + "/preimage");
const p2 = await get("https://api.chit402.com/receipt/" + RID + "/preimage");
console.log("preimage read 1: " + p1.status + " " + p1.b.length + " bytes sha256=" + sha(p1.b));
console.log("preimage read 2: " + p2.status + " " + p2.b.length + " bytes sha256=" + sha(p2.b));
console.log("preimage identical: " + p1.b.equals(p2.b));
