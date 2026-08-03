"use strict";

const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
const fs = require("node:fs");

Object.defineProperty(globalThis, "crypto", { value: webcrypto });
const verifier = require("../docs/verify-evidence/verify-evidence.js");

async function main() {
  const path = process.argv[2];
  assert(path, "evidence ZIP path is required");
  const raw = new Uint8Array(fs.readFileSync(path));
  const members = verifier.parseZip(raw);
  assert.deepEqual([...members.keys()], ["accountability.evidence", "accountability.evidence.sha256", "VERIFYING.txt"]);
  const bundle = members.get("accountability.evidence");
  const receipt = new TextDecoder().decode(members.get("accountability.evidence.sha256"));
  assert.equal(receipt, `${await verifier.sha256(bundle)}  accountability.evidence\n`);
  const checks = [];
  const manifest = await verifier.verifyBundle(bundle, (label) => checks.push(label));
  assert.equal(manifest.record_count, 1);
  assert.equal(manifest.instance_id, "11111111-1111-4111-8111-111111111111");
  assert.equal(checks.length, 3);

  const tampered = raw.slice();
  const marker = Buffer.from(receipt, "utf8");
  const offset = Buffer.from(tampered).indexOf(marker);
  assert(offset > 0);
  tampered[offset] ^= 1;
  assert.throws(() => verifier.parseZip(tampered), /CRC check/);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
