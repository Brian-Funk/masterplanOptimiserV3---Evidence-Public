"use strict";

const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
Object.defineProperty(globalThis, "crypto", { value: webcrypto });
globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");

const custody = require("../docs/controller-key/controller-key.js");

async function main() {
  const passphrase = "synthetic controller passphrase";
  const generated = await custody.generateControllerKey({ controllerId: "ctl-synthetic0001", passphrase });
  assert.equal(generated.privatePackage.format, "mp-opt-controller-private-key-v1");
  assert.equal(generated.publicPackage.format, "mp-opt-controller-public-key-v1");
  assert.match(generated.publicPackage.key_id, /^ek-[0-9a-f]{16}$/);
  assert.equal((await custody.loadControllerKey(generated.privatePackage, passphrase)).publicPackage.key_id, generated.publicPackage.key_id);
  await assert.rejects(custody.loadControllerKey(generated.privatePackage, "wrong passphrase value"), /wrong or the encrypted key package was changed/);

  const tampered = structuredClone(generated.privatePackage);
  tampered.public_package.entity_id = "ctl-substitute01";
  await assert.rejects(custody.loadControllerKey(tampered, passphrase), /wrong or the encrypted key package was changed/);

  const exactAction = {
    format: "mp-opt-trust-action-v1", action: "register",
    instance_id: "00000000-0000-4000-8000-000000000001", entity_id: generated.publicPackage.entity_id,
    key_id: generated.publicPackage.key_id, role: "controller", algorithm: "Ed25519",
    public_key_sha256: generated.publicPackage.public_key_sha256,
    trust_scope: "controller_governance_authority", governance_authorisation: "root_passkey_per_publication",
    supersedes_key_id: null, reason: null,
  };
  const actionSha256 = Buffer.from(await crypto.subtle.digest("SHA-256", Buffer.from(`${custody.canonicalJson(exactAction)}\n`))).toString("hex");
  const document = {
    format: "mp-opt-controller-trust-registration-v2", challenge_id: "synthetic-challenge", action: "register",
    instance_id: "00000000-0000-4000-8000-000000000001", entity_id: generated.publicPackage.entity_id,
    key_id: generated.publicPackage.key_id, role: "controller", algorithm: "Ed25519",
    public_key_sha256: generated.publicPackage.public_key_sha256,
    trust_scope: "controller_governance_authority", governance_authorisation: "root_passkey_per_publication",
    supersedes_key_id: null, reason: null,
    action_sha256: actionSha256, nonce: "synthetic", created_at: "2030-01-01T00:00:00Z", expires_at: "2030-01-01T00:10:00Z",
  };
  const signed = await custody.signControllerDocument(generated.privatePackage, passphrase, document);
  assert.equal(signed.document, document);
  assert.equal(signed.proof.key_id, generated.publicPackage.key_id);
  assert.equal(signed.proof.namespace, "mp-opt-role-trust-v1");
  assert.ok(Buffer.from(signed.proof.signature, "base64").length === 64);
  const ssh = Buffer.from(generated.publicPackage.public_key.split(" ")[1], "base64");
  const publicKey = await crypto.subtle.importKey("raw", ssh.subarray(19), { name: "Ed25519" }, false, ["verify"]);
  const payload = Buffer.concat([Buffer.from("mp-opt-role-trust-v1\0"), Buffer.from(`${custody.canonicalJson(document)}\n`)]);
  assert.equal(await crypto.subtle.verify({ name: "Ed25519" }, publicKey, Buffer.from(signed.proof.signature, "base64"), payload), true);

  const processorDocument = { ...document, role: "processor" };
  await assert.rejects(custody.signControllerDocument(generated.privatePackage, passphrase, processorDocument), /not a controller action/);
  const deletionDocument = { ...document, format: "mp-opt-desktop-deletion-receipt-v2" };
  await assert.rejects(custody.signControllerDocument(generated.privatePackage, passphrase, deletionDocument), /cannot sign that document type/);
  const substituted = { ...document, key_id: "ek-0000000000000000" };
  await assert.rejects(custody.signControllerDocument(generated.privatePackage, passphrase, substituted), /different controller key/);
  const changedAction = { ...document, action_sha256: "a".repeat(64) };
  await assert.rejects(custody.signControllerDocument(generated.privatePackage, passphrase, changedAction), /action digest is invalid/);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
