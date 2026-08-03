"use strict";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const ITERATIONS = 600000;

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function canonicalBytes(value) { return textEncoder.encode(`${canonicalJson(value)}\n`); }
function bytesToBase64(value) {
  let binary = ""; for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function base64ToBytes(value) {
  const binary = atob(value); const result = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) result[index] = binary.charCodeAt(index);
  return result;
}
function uint32(value) { return new Uint8Array([(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255]); }
function concat(...values) {
  const result = new Uint8Array(values.reduce((total, value) => total + value.length, 0));
  let offset = 0; for (const value of values) { result.set(value, offset); offset += value.length; }
  return result;
}
function sshField(value) { return concat(uint32(value.length), value); }
function openSshPublic(raw) {
  const algorithm = textEncoder.encode("ssh-ed25519");
  return `ssh-ed25519 ${bytesToBase64(concat(sshField(algorithm), sshField(raw)))}`;
}
async function sha256Hex(value) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", value))].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
function randomEntityId() {
  const raw = crypto.getRandomValues(new Uint8Array(8));
  return `prc-${[...raw].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}
function timestamp() { return new Date().toISOString().replace(/\.\d{3}Z$/, "Z"); }

async function deriveKey(passphrase, salt) {
  const material = await crypto.subtle.importKey("raw", textEncoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", iterations: ITERATIONS, salt }, material,
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
}

async function generateProcessorKey({ passphrase, displayLabel = null, supersedesKeyId = null } = {}) {
  if (typeof passphrase !== "string" || passphrase.length < 16) throw new Error("Use a passphrase of at least 16 characters.");
  if (supersedesKeyId && !/^ek-[0-9a-f]{16}$/.test(supersedesKeyId)) throw new Error("The superseded key ID is invalid.");
  let pair;
  try { pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]); }
  catch (error) { throw new Error("This browser cannot generate Ed25519 keys. Use a current Firefox or Chromium browser.", { cause: error }); }
  const rawPublic = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const publicKey = openSshPublic(rawPublic);
  const fingerprint = await sha256Hex(textEncoder.encode(publicKey));
  const keyId = `ek-${fingerprint.slice(0, 16)}`;
  const publicPackage = {
    format: "mp-opt-processor-public-key-v1", instance_id: null,
    entity_id: randomEntityId(), key_id: keyId, role: "processor", algorithm: "Ed25519",
    public_key: publicKey, public_key_sha256: fingerprint,
    supersedes_key_id: supersedesKeyId, rotation_reason: supersedesKeyId ? "routine" : null,
    display_label: displayLabel || null, created_at: timestamp(), signature_namespace: "mp-opt-role-trust-v1",
  };
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptionKey = await deriveKey(passphrase, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: canonicalBytes(publicPackage), tagLength: 128 },
    encryptionKey, pkcs8,
  );
  pkcs8.fill(0);
  const privatePackage = {
    format: "mp-opt-processor-private-key-v1", public_package: publicPackage,
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations: ITERATIONS, salt: bytesToBase64(salt) },
    cipher: { name: "AES-GCM", iv: bytesToBase64(iv), tag_length: 128 },
    ciphertext: bytesToBase64(ciphertext),
  };
  await verifyProcessorKey(privatePackage, passphrase);
  return { privatePackage, publicPackage };
}

async function verifyProcessorKey(keyPackage, passphrase) {
  if (keyPackage?.format !== "mp-opt-processor-private-key-v1") throw new Error("The encrypted key format is invalid.");
  const salt = base64ToBytes(keyPackage.kdf.salt); const iv = base64ToBytes(keyPackage.cipher.iv);
  const key = await deriveKey(passphrase, salt);
  let pkcs8;
  try {
    pkcs8 = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: canonicalBytes(keyPackage.public_package), tagLength: 128 },
      key, base64ToBytes(keyPackage.ciphertext),
    ));
  } catch (error) { throw new Error("The passphrase is wrong or the encrypted key package was changed.", { cause: error }); }
  const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  const publicKey = openSshPublic(base64ToBytes(jwk.x.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(jwk.x.length / 4) * 4, "=")));
  pkcs8.fill(0);
  if (publicKey !== keyPackage.public_package.public_key) throw new Error("The encrypted private key does not match the public package.");
  return true;
}

function downloadJson(name, value) {
  const url = URL.createObjectURL(new Blob([`${JSON.stringify(value, null, 2)}\n`], { type: "application/json" }));
  const link = document.createElement("a"); link.href = url; link.download = name; link.click(); URL.revokeObjectURL(url);
}

if (typeof document !== "undefined") {
  let generated = null;
  const button = document.getElementById("generate-button");
  button.addEventListener("click", async () => {
    const passphrase = document.getElementById("passphrase").value;
    const repeated = document.getElementById("passphrase-repeat").value;
    const panel = document.getElementById("result");
    button.disabled = true; panel.className = "verification-result pending";
    try {
      if (passphrase !== repeated) throw new Error("The passphrases do not match.");
      generated = await generateProcessorKey({
        passphrase,
        displayLabel: document.getElementById("display-label").value.trim() || null,
        supersedesKeyId: document.getElementById("supersedes-key").value.trim() || null,
      });
      document.getElementById("passphrase").value = ""; document.getElementById("passphrase-repeat").value = "";
      document.getElementById("result-title").textContent = "Key generated and recovery-tested";
      document.getElementById("result-summary").textContent = "Download both files now. Import the encrypted private package into Desktop; share only the public package.";
      document.getElementById("result-entity").textContent = generated.publicPackage.entity_id;
      document.getElementById("result-key").textContent = generated.publicPackage.key_id;
      document.getElementById("result-fingerprint").textContent = generated.publicPackage.public_key_sha256;
      document.getElementById("result-details").hidden = false; document.getElementById("downloads").hidden = false;
      panel.className = "verification-result valid";
    } catch (error) {
      generated = null; document.getElementById("result-title").textContent = "Key generation failed";
      document.getElementById("result-summary").textContent = error instanceof Error ? error.message : "The key could not be generated.";
      document.getElementById("result-details").hidden = true; document.getElementById("downloads").hidden = true;
      panel.className = "verification-result invalid";
    } finally { button.disabled = false; }
  });
  document.getElementById("private-download").addEventListener("click", () => generated && downloadJson(`${generated.publicPackage.key_id}.processor-key.json`, generated.privatePackage));
  document.getElementById("public-download").addEventListener("click", () => generated && downloadJson(`${generated.publicPackage.key_id}.processor-public.json`, generated.publicPackage));
}

if (typeof module !== "undefined") module.exports = { canonicalJson, generateProcessorKey, verifyProcessorKey };
