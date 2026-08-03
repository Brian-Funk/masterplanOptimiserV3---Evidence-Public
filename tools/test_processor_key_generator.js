"use strict";

const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
Object.defineProperty(globalThis, "crypto", { value: webcrypto });
globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");

const generator = require("../docs/processor-key/processor-key.js");

async function main() {
  const passphrase = "synthetic processor passphrase";
  const result = await generator.generateProcessorKey({ passphrase, displayLabel: "Synthetic workstation" });
  assert.equal(result.privatePackage.format, "mp-opt-processor-private-key-v1");
  assert.equal(result.publicPackage.format, "mp-opt-processor-public-key-v1");
  assert.match(result.publicPackage.entity_id, /^prc-[0-9a-f]{16}$/);
  assert.match(result.publicPackage.key_id, /^ek-[0-9a-f]{16}$/);
  assert.equal(await generator.verifyProcessorKey(result.privatePackage, passphrase), true);
  await assert.rejects(generator.verifyProcessorKey(result.privatePackage, "wrong passphrase value"), /wrong or the encrypted key package was changed/);
  const tampered = structuredClone(result.privatePackage);
  tampered.public_package.display_label = "Changed";
  await assert.rejects(generator.verifyProcessorKey(tampered, passphrase), /wrong or the encrypted key package was changed/);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
