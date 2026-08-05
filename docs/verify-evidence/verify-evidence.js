"use strict";

const MAX_ZIP_BYTES = 258 * 1024 * 1024;
const ZIP_NAMES = ["accountability.evidence", "accountability.evidence.sha256", "VERIFYING.txt"];
const BUNDLE_ROOT = new Set(["bundle.json", "bundle.sha256", "VERIFYING.md"]);
const BUNDLE_FORMAT = "mp-opt-portable-evidence-bundle-v1";
const LOCAL_BUNDLE_FORMAT = "mp-opt-evidence-bundle-v1";
const RECORD_FORMAT = "mp-opt-evidence-record-v1";
const SSH_NAMESPACE = "mp-opt-evidence-v1";
const UUID_NAMESPACE = "8c36ce0a-ec6a-4b9b-981e-dfb7f891da70";
const LOCAL_UUID_NAMESPACE = "aa0c67fb-6a9c-4cf3-b712-c4cde822e7be";
const LIMIT_TEXT = "A valid signature proves that the identified key signed the exact statement shown. It does not prove physical deletion, absence of copies outside controlled systems, physical-world truth, or legal compliance.";
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const asciiDecoder = new TextDecoder("ascii", { fatal: true });
const textEncoder = new TextEncoder();

function fail(message) { throw new Error(message); }
function hex(bytes) { return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join(""); }
function concat(...parts) {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}
function equal(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}
async function digest(name, raw) { return new Uint8Array(await crypto.subtle.digest(name, raw)); }
async function sha256(raw) { return hex(await digest("SHA-256", raw)); }
function u32be(value) { return new Uint8Array([(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255]); }
function sshString(raw) { return concat(u32be(raw.length), raw); }
function readSshString(raw, state) {
  if (state.offset + 4 > raw.length) fail("An SSH signature field is truncated.");
  const length = new DataView(raw.buffer, raw.byteOffset + state.offset, 4).getUint32(0, false);
  state.offset += 4;
  if (state.offset + length > raw.length) fail("An SSH signature field exceeds its container.");
  const value = raw.slice(state.offset, state.offset + length);
  state.offset += length;
  return value;
}

function parsePublicKey(value) {
  const parts = value.trim().split(/\s+/);
  if (parts.length < 2 || parts[0] !== "ssh-ed25519") fail("Only OpenSSH Ed25519 evidence keys are supported.");
  const blob = Uint8Array.from(atob(parts[1]), (character) => character.charCodeAt(0));
  const state = { offset: 0 };
  const algorithm = asciiDecoder.decode(readSshString(blob, state));
  const key = readSshString(blob, state);
  if (algorithm !== "ssh-ed25519" || key.length !== 32 || state.offset !== blob.length) fail("The OpenSSH public key is malformed.");
  return { canonical: `ssh-ed25519 ${parts[1]}`, blob, key };
}
async function keyId(publicKey) { return `ek-${(await sha256(textEncoder.encode(publicKey.canonical))).slice(0, 16)}`; }
function parseArmoredSignature(value) {
  const match = value.trim().match(/^-----BEGIN SSH SIGNATURE-----\n([A-Za-z0-9+/=\n]+)\n-----END SSH SIGNATURE-----$/);
  if (!match) fail("An OpenSSH signature is not correctly armoured.");
  return Uint8Array.from(atob(match[1].replace(/\n/g, "")), (character) => character.charCodeAt(0));
}
async function verifySshSignature(message, signatureText, publicText) {
  const publicKey = parsePublicKey(publicText);
  const raw = parseArmoredSignature(signatureText);
  const magic = textEncoder.encode("SSHSIG");
  if (!equal(raw.slice(0, 6), magic)) fail("An OpenSSH signature has the wrong magic value.");
  if (new DataView(raw.buffer, raw.byteOffset, raw.byteLength).getUint32(6, false) !== 1) fail("An OpenSSH signature uses an unsupported version.");
  const state = { offset: 10 };
  const embeddedKey = readSshString(raw, state);
  const namespace = asciiDecoder.decode(readSshString(raw, state));
  const reserved = readSshString(raw, state);
  const hashAlgorithm = asciiDecoder.decode(readSshString(raw, state));
  const signatureBlob = readSshString(raw, state);
  if (state.offset !== raw.length || namespace !== SSH_NAMESPACE || reserved.length !== 0 || !["sha256", "sha512"].includes(hashAlgorithm)) fail("An OpenSSH signature has unsupported parameters.");
  if (!equal(embeddedKey, publicKey.blob)) fail("An OpenSSH signature is bound to another public key.");
  const signatureState = { offset: 0 };
  if (asciiDecoder.decode(readSshString(signatureBlob, signatureState)) !== "ssh-ed25519") fail("An evidence signature is not Ed25519.");
  const signature = readSshString(signatureBlob, signatureState);
  if (signature.length !== 64 || signatureState.offset !== signatureBlob.length) fail("An Ed25519 signature is malformed.");
  const messageDigest = await digest(hashAlgorithm === "sha256" ? "SHA-256" : "SHA-512", message);
  const signed = concat(magic, sshString(textEncoder.encode(namespace)), sshString(reserved), sshString(textEncoder.encode(hashAlgorithm)), sshString(messageDigest));
  let imported;
  try {
    imported = await crypto.subtle.importKey("raw", publicKey.key, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    fail("This browser cannot verify Ed25519 signatures. Use a current Firefox, Chromium, or the offline Python verifier.");
  }
  if (!await crypto.subtle.verify({ name: "Ed25519" }, imported, signature, signed)) fail("An evidence signature is invalid.");
  return publicKey;
}

async function verifyDesktopEvidenceArtifact(raw, payload, expectedDigest) {
  if (await sha256(raw) !== expectedDigest) fail("A Desktop evidence artifact digest does not match its signed ledger reference.");
  const packageValue = parseCanonicalJson(raw, "Desktop evidence artifact");
  exactKeys(packageValue, ["format", "namespace", "document", "proof", "public_key"], "A Desktop evidence artifact");
  if (packageValue.format !== "mp-opt-signed-desktop-evidence-v1" || packageValue.namespace !== "mp-opt-desktop-evidence-v1") fail("A Desktop evidence artifact has an unsupported format.");
  const documentValue = packageValue.document; const proof = packageValue.proof;
  if (typeof documentValue !== "object" || documentValue === null || Array.isArray(documentValue) || typeof proof !== "object" || proof === null || Array.isArray(proof)) fail("A Desktop evidence artifact document or proof is invalid.");
  exactKeys(proof, ["format", "key_id", "namespace", "signature"], "A Desktop evidence proof");
  const publicKey = parsePublicKey(packageValue.public_key);
  const expectedKeyId = await keyId(publicKey);
  let signature;
  try { signature = Uint8Array.from(atob(proof.signature), (character) => character.charCodeAt(0)); }
  catch { fail("A Desktop evidence signature is not valid base64."); }
  if (proof.format !== "mp-opt-ed25519-signature-v1" || proof.namespace !== "mp-opt-desktop-evidence-v1" || proof.key_id !== expectedKeyId || signature.length !== 64) fail("A Desktop evidence signature identity is invalid.");
  let imported;
  try { imported = await crypto.subtle.importKey("raw", publicKey.key, { name: "Ed25519" }, false, ["verify"]); }
  catch { fail("This browser cannot verify Desktop Ed25519 evidence."); }
  const documentRaw = textEncoder.encode(`${canonicalJson(documentValue)}\n`);
  const signingInput = concat(textEncoder.encode("mp-opt-desktop-evidence-v1\0"), documentRaw);
  if (!await crypto.subtle.verify({ name: "Ed25519" }, imported, signature, signingInput)) fail("A Desktop evidence signature is invalid.");
  const expectedDocument = payload.document_sha256 ?? payload.report_sha256 ?? payload.copy_resolution_sha256;
  const expectedKey = payload.key_id ?? payload.processor_key_id;
  const expectedFingerprint = payload.public_key_sha256 ?? payload.completed_public_key_sha256;
  if (
    expectedDocument !== await sha256(documentRaw)
    || payload.signature_sha256 !== await sha256(textEncoder.encode(`${canonicalJson(proof)}\n`))
    || expectedKey !== proof.key_id
    || expectedFingerprint !== await sha256(textEncoder.encode(publicKey.canonical))
    || documentValue.key_id !== proof.key_id
    || documentValue.public_key_sha256 !== expectedFingerprint
  ) fail("A Desktop evidence artifact does not match its signed ledger record.");
}

function crc32(raw) {
  let crc = 0xffffffff;
  for (const byte of raw) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function parseZip(raw) {
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  let eocd = -1;
  for (let offset = raw.length - 22; offset >= Math.max(0, raw.length - 65557); offset -= 1) {
    if (view.getUint32(offset, true) === 0x06054b50) { eocd = offset; break; }
  }
  if (eocd < 0 || view.getUint16(eocd + 20, true) !== 0 || eocd + 22 !== raw.length) fail("The ZIP end record is invalid.");
  if (view.getUint16(eocd + 4, true) !== 0 || view.getUint16(eocd + 6, true) !== 0) fail("Multi-disk ZIP files are not accepted.");
  const entries = view.getUint16(eocd + 10, true);
  const centralSize = view.getUint32(eocd + 12, true);
  const centralOffset = view.getUint32(eocd + 16, true);
  if (entries !== 3 || view.getUint16(eocd + 8, true) !== entries || centralOffset + centralSize !== eocd) fail("The ZIP must contain exactly three central-directory entries.");
  const result = new Map();
  let offset = centralOffset;
  for (let index = 0; index < entries; index += 1) {
    if (view.getUint32(offset, true) !== 0x02014b50) fail("The ZIP central directory is malformed.");
    const flags = view.getUint16(offset + 8, true);
    const method = view.getUint16(offset + 10, true);
    const crc = view.getUint32(offset + 16, true);
    const compressed = view.getUint32(offset + 20, true);
    const size = view.getUint32(offset + 24, true);
    const nameLength = view.getUint16(offset + 28, true);
    const extraLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    const localOffset = view.getUint32(offset + 42, true);
    const name = asciiDecoder.decode(raw.slice(offset + 46, offset + 46 + nameLength));
    if (name !== ZIP_NAMES[index] || flags !== 0 || method !== 0 || compressed !== size || extraLength !== 0 || commentLength !== 0) fail("The ZIP is not in the canonical stored format.");
    if (view.getUint32(localOffset, true) !== 0x04034b50) fail("A ZIP local header is missing.");
    const localNameLength = view.getUint16(localOffset + 26, true);
    const localExtraLength = view.getUint16(localOffset + 28, true);
    const localName = asciiDecoder.decode(raw.slice(localOffset + 30, localOffset + 30 + localNameLength));
    if (localName !== name || localExtraLength !== 0 || view.getUint16(localOffset + 6, true) !== flags || view.getUint16(localOffset + 8, true) !== method) fail("A ZIP local header disagrees with its directory entry.");
    const start = localOffset + 30 + localNameLength;
    const value = raw.slice(start, start + size);
    if (value.length !== size || crc32(value) !== crc) fail(`The ZIP member ${name} failed its CRC check.`);
    result.set(name, value);
    offset += 46 + nameLength + extraLength + commentLength;
  }
  if (offset !== eocd) fail("The ZIP central directory has trailing or missing data.");
  return result;
}

function parseOctal(raw, label) {
  const value = asciiDecoder.decode(raw).replace(/\0.*$/, "").trim();
  if (!/^[0-7]+$/.test(value)) fail(`The tar ${label} is invalid.`);
  return Number.parseInt(value, 8);
}
function safePath(name) { return name.length > 0 && !name.startsWith("/") && !name.includes("\\") && !name.split("/").includes("..") && !name.includes("//"); }
function parseTar(raw) {
  const result = new Map();
  let offset = 0;
  let longName = null;
  while (offset + 512 <= raw.length) {
    const header = raw.slice(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      if (!raw.slice(offset).every((byte) => byte === 0)) fail("The evidence tar has data after its end marker.");
      return result;
    }
    let checksum = 0;
    for (let index = 0; index < 512; index += 1) checksum += index >= 148 && index < 156 ? 32 : header[index];
    if (checksum !== parseOctal(header.slice(148, 156), "checksum")) fail("The evidence tar header checksum is invalid.");
    const size = parseOctal(header.slice(124, 136), "size");
    const type = header[156];
    let name = asciiDecoder.decode(header.slice(0, 100)).replace(/\0.*$/, "");
    const dataStart = offset + 512;
    const data = raw.slice(dataStart, dataStart + size);
    if (data.length !== size) fail("The evidence tar is truncated.");
    offset = dataStart + Math.ceil(size / 512) * 512;
    if (type === 76) { longName = asciiDecoder.decode(data).replace(/\0.*$/, ""); continue; }
    if (longName !== null) { name = longName; longName = null; }
    if (![0, 48].includes(type) || parseOctal(header.slice(100, 108), "mode") !== 0o600 || !safePath(name) || result.has(name)) fail("The evidence tar contains an unsafe or duplicate member.");
    result.set(name, data);
  }
  fail("The evidence tar has no valid end marker.");
}

function ensureJsonValues(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return;
  if (typeof value === "number") { if (!Number.isSafeInteger(value)) fail("Evidence JSON contains a non-integer or unsafe number."); return; }
  if (Array.isArray(value)) { for (const item of value) ensureJsonValues(item); return; }
  if (typeof value === "object") { for (const item of Object.values(value)) ensureJsonValues(item); return; }
  fail("Evidence JSON contains an unsupported value.");
}
function canonicalJson(value) {
  ensureJsonValues(value);
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}
function parseCanonicalJson(raw, label) {
  const text = textDecoder.decode(raw);
  if (text.includes("\r") || !text.endsWith("\n")) fail(`${label} is not canonical LF-terminated JSON.`);
  let value;
  try { value = JSON.parse(text); } catch { fail(`${label} is not valid JSON.`); }
  if (typeof value !== "object" || value === null || Array.isArray(value) || `${canonicalJson(value)}\n` !== text) fail(`${label} is not canonical JSON.`);
  return value;
}
function exactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} has an unexpected schema.`);
}
function canonicalUuid(value) { return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value); }
function uuidBytes(value) { return Uint8Array.from(value.replaceAll("-", "").match(/../g), (pair) => Number.parseInt(pair, 16)); }
function formatUuid(raw) { const value = hex(raw); return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`; }
async function uuidV5(namespace, name) {
  const value = (await digest("SHA-1", concat(uuidBytes(namespace), textEncoder.encode(name)))).slice(0, 16);
  value[6] = (value[6] & 0x0f) | 0x50; value[8] = (value[8] & 0x3f) | 0x80;
  return formatUuid(value);
}

async function verifyLocalBundle(tar, manifestRaw, manifest, addCheck) {
  exactKeys(manifest, ["format", "bundle_id", "created_at", "instance_id", "chain_id", "chain_head_sha256", "record_count", "files"], "The local bundle manifest");
  if (!canonicalUuid(manifest.bundle_id) || !canonicalUuid(manifest.instance_id) || !canonicalUuid(manifest.chain_id) || !Array.isArray(manifest.files) || manifest.files.length === 0) fail("The local bundle manifest identity or schema is invalid.");
  const payload = new Map(); const declared = new Set();
  for (const row of manifest.files) {
    exactKeys(row, ["path", "sha256", "size"], "A local bundle file row");
    if (typeof row.path !== "string" || !safePath(row.path) || !["ledger", "public", "anchors", "artifacts"].includes(row.path.split("/", 1)[0]) || declared.has(row.path)) fail("A local bundle file path is unsafe or duplicated.");
    const raw = tar.get(`evidence/${row.path}`);
    if (!raw || raw.length !== row.size || await sha256(raw) !== row.sha256) fail(`The declared evidence file ${row.path} does not match its digest.`);
    payload.set(row.path, raw); declared.add(row.path);
  }
  const carried = [...tar.keys()].filter((name) => name !== "bundle.json").map((name) => name.replace(/^evidence\//, ""));
  if (carried.length !== declared.size || carried.some((name) => !declared.has(name))) fail("The local bundle contains undeclared evidence files.");
  addCheck(`Canonical local bundle manifest and all ${declared.size} declared files`);
  const publicRaw = payload.get("public/instance_signing_key.pub");
  if (!publicRaw) fail("The local bundle has no instance verification key.");
  const publicKey = parsePublicKey(asciiDecoder.decode(publicRaw));
  const expectedKeyId = await keyId(publicKey);
  const recordPattern = /^ledger\/([0-9]{12})_([0-9a-f-]{36})\.json$/;
  const records = [...payload.entries()].filter(([name]) => recordPattern.test(name)).sort(([left], [right]) => left.localeCompare(right));
  if (records.length === 0 || records.length !== manifest.record_count) fail("The local signed record count does not match its manifest.");
  let previous = "GENESIS"; let head = null; const artifactReferences = new Map();
  for (let index = 0; index < records.length; index += 1) {
    const [name, raw] = records[index]; const match = name.match(recordPattern); const record = parseCanonicalJson(raw, `record ${index + 1}`);
    exactKeys(record, ["format", "instance_id", "chain_id", "sequence", "record_id", "record_type", "created_at", "signer", "previous_record_sha256", "management_audit_tail_sha256", "payload"], `Record ${index + 1}`);
    if (record.format !== RECORD_FORMAT || record.sequence !== index + 1 || !canonicalUuid(record.record_id) || match[1] !== String(index + 1).padStart(12, "0") || match[2] !== record.record_id || record.instance_id !== manifest.instance_id || record.chain_id !== manifest.chain_id || record.previous_record_sha256 !== previous || record.signer?.key_id !== expectedKeyId || record.signer?.role !== "instance") fail(`Record ${index + 1} breaks the local signed chain.`);
    const signature = payload.get(`${name}.sig`);
    if (!signature) fail(`Record ${index + 1} has no signature.`);
    await verifySshSignature(raw, asciiDecoder.decode(signature), publicKey.canonical);
    if (record.payload.evidence_package_sha256 !== undefined) {
      const digestValue = record.payload.evidence_package_sha256;
      if (typeof digestValue !== "string" || !/^[0-9a-f]{64}$/.test(digestValue) || artifactReferences.has(digestValue)) fail("A Desktop evidence artifact reference is invalid or duplicated.");
      artifactReferences.set(digestValue, record.payload);
    }
    head = await sha256(raw); previous = head;
  }
  if (head !== manifest.chain_head_sha256) fail("The local signed-chain head does not match its manifest.");
  addCheck(`All ${records.length} local record signatures and chain links`);
  const artifactPaths = [...payload.keys()].filter((name) => name.startsWith("artifacts/"));
  if (artifactPaths.length !== artifactReferences.size) fail("Desktop evidence artifacts do not exactly match the signed ledger.");
  for (const [digestValue, recordPayload] of artifactReferences) {
    const artifactRaw = payload.get(`artifacts/${digestValue}.json`);
    if (!artifactRaw) fail("A signed Desktop evidence artifact is missing.");
    await verifyDesktopEvidenceArtifact(artifactRaw, recordPayload, digestValue);
  }
  if (artifactReferences.size > 0) addCheck(`All ${artifactReferences.size} Desktop processor signatures and ledger bindings`);
  const rowsDigest = await sha256(textEncoder.encode(`${canonicalJson({ files: manifest.files })}\n`));
  const identity = [manifest.instance_id, manifest.chain_id, manifest.chain_head_sha256, rowsDigest].join("|");
  if (await uuidV5(LOCAL_UUID_NAMESPACE, identity) !== manifest.bundle_id) fail("The deterministic local bundle identity does not match its contents.");
  addCheck("Deterministic local bundle identity and exact chain-head binding");
  return manifest;
}

async function verifyBundle(bundleRaw, addCheck) {
  const tar = parseTar(bundleRaw);
  if (!tar.has("bundle.json")) fail("The canonical bundle is missing bundle.json.");
  const manifestRaw = tar.get("bundle.json");
  const manifest = parseCanonicalJson(manifestRaw, "bundle.json");
  if (manifest.format === LOCAL_BUNDLE_FORMAT) {
    for (const name of tar.keys()) if (name !== "bundle.json" && !name.startsWith("evidence/")) fail(`The local bundle contains unexpected member ${name}.`);
    return verifyLocalBundle(tar, manifestRaw, manifest, addCheck);
  }
  for (const required of BUNDLE_ROOT) if (!tar.has(required)) fail(`The canonical bundle is missing ${required}.`);
  for (const name of tar.keys()) if (!BUNDLE_ROOT.has(name) && !name.startsWith("payload/")) fail(`The canonical bundle contains unexpected member ${name}.`);
  exactKeys(manifest, ["format", "bundle_id", "created_at", "controller_id", "instance_id", "chain_id", "chain_head_sha256", "record_count", "instance_key_id", "processor_ids", "verification_limits", "files"], "The bundle manifest");
  if (manifest.format !== BUNDLE_FORMAT || manifest.verification_limits !== LIMIT_TEXT || !canonicalUuid(manifest.bundle_id) || !canonicalUuid(manifest.instance_id) || !canonicalUuid(manifest.chain_id)) fail("The bundle manifest identity or format is invalid.");
  if (textDecoder.decode(tar.get("bundle.sha256")) !== `${await sha256(manifestRaw)}  bundle.json\n`) fail("The bundle manifest checksum does not match.");
  addCheck("Canonical bundle manifest and checksum");
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) fail("The bundle file manifest is empty.");
  const payload = new Map(); const declared = new Set();
  for (const row of manifest.files) {
    exactKeys(row, ["path", "sha256", "size"], "A bundle file row");
    if (typeof row.path !== "string" || !safePath(row.path) || declared.has(row.path)) fail("A bundle file path is unsafe or duplicated.");
    const raw = tar.get(`payload/${row.path}`);
    if (!raw || raw.length !== row.size || await sha256(raw) !== row.sha256) fail(`The declared payload ${row.path} does not match its digest.`);
    payload.set(row.path, raw); declared.add(row.path);
  }
  const carried = [...tar.keys()].filter((name) => name.startsWith("payload/")).map((name) => name.slice(8));
  if (carried.length !== declared.size || carried.some((name) => !declared.has(name))) fail("The bundle contains undeclared payload files.");
  addCheck(`All ${declared.size} declared payload files`);

  const prefix = `evidence/instances/${manifest.instance_id}`;
  const required = ["evidence/trust/controller.json", "evidence/trust/controller.json.sig", "evidence/trust/controller.pub", `${prefix}/trust/instance.json`, `${prefix}/trust/instance.json.sig`, `${prefix}/trust/instance.pub`];
  if (!required.every((name) => payload.has(name))) fail("The bundle trust material is incomplete.");
  const controllerRaw = payload.get(required[0]); const controller = parseCanonicalJson(controllerRaw, "controller.json");
  const controllerSig = asciiDecoder.decode(payload.get(required[1])); const controllerPub = parsePublicKey(asciiDecoder.decode(payload.get(required[2])));
  exactKeys(controller, ["format", "controller_id", "display_name", "jurisdiction", "signing_key_id", "signing_public_key", "revoked_key_ids", "status", "signed_at"], "The controller trust declaration");
  if (controller.format !== "mp-opt-controller-trust-v1" || !/^ctl-[a-z0-9]{16}$/.test(controller.controller_id) || parsePublicKey(controller.signing_public_key).canonical !== controllerPub.canonical || controller.signing_key_id !== await keyId(controllerPub) || controller.controller_id !== manifest.controller_id || controller.status !== "active" || !Array.isArray(controller.revoked_key_ids) || controller.revoked_key_ids.includes(controller.signing_key_id)) fail("The controller trust declaration is inconsistent.");
  await verifySshSignature(controllerRaw, controllerSig, controllerPub.canonical);
  const instanceRaw = payload.get(required[3]); const instance = parseCanonicalJson(instanceRaw, "instance.json");
  const instanceSig = asciiDecoder.decode(payload.get(required[4])); const instancePub = parsePublicKey(asciiDecoder.decode(payload.get(required[5])));
  exactKeys(instance, ["format", "instance_id", "controller_id", "signing_key_id", "signing_public_key", "processor_ids", "status", "signed_at"], "The instance trust declaration");
  if (instance.format !== "mp-opt-instance-trust-v1" || parsePublicKey(instance.signing_public_key).canonical !== instancePub.canonical || instance.signing_key_id !== await keyId(instancePub) || instance.signing_key_id !== manifest.instance_key_id || instance.instance_id !== manifest.instance_id || instance.controller_id !== manifest.controller_id || instance.status !== "active" || controller.revoked_key_ids.includes(instance.signing_key_id)) fail("The instance trust declaration is inconsistent.");
  await verifySshSignature(instanceRaw, instanceSig, controllerPub.canonical);
  if (!Array.isArray(instance.processor_ids) || canonicalJson(instance.processor_ids) !== canonicalJson(manifest.processor_ids)) fail("The processor trust list does not match the bundle manifest.");
  for (const processorId of instance.processor_ids) {
    const raw = payload.get(`evidence/trust/processors/${processorId}.json`); const signature = payload.get(`evidence/trust/processors/${processorId}.json.sig`);
    if (!raw || !signature) fail(`Processor trust declaration ${processorId} is missing.`);
    const processor = parseCanonicalJson(raw, `${processorId}.json`);
    exactKeys(processor, ["format", "processor_id", "controller_id", "display_name", "service_categories", "countries", "transfer_basis", "active_from", "active_until", "status", "signed_at"], `Processor trust declaration ${processorId}`);
    if (processor.format !== "mp-opt-processor-trust-v1" || !/^proc-[a-z0-9]{16}$/.test(processorId) || processor.processor_id !== processorId || processor.controller_id !== manifest.controller_id || processor.status !== "active") fail(`Processor trust declaration ${processorId} is inconsistent.`);
    await verifySshSignature(raw, asciiDecoder.decode(signature), controllerPub.canonical);
  }
  addCheck("Controller, instance, and processor trust signatures");

  const escapedPrefix = prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const recordPattern = new RegExp(`^${escapedPrefix}/ledger/([0-9]{12})_([0-9a-f-]{36})\\.json$`);
  const records = [...payload.entries()].filter(([name]) => recordPattern.test(name)).sort(([left], [right]) => left.localeCompare(right));
  if (records.length === 0 || records.length !== manifest.record_count) fail("The signed record count does not match the bundle manifest.");
  let previous = "GENESIS"; let head = null;
  for (let index = 0; index < records.length; index += 1) {
    const [name, raw] = records[index]; const match = name.match(recordPattern); const record = parseCanonicalJson(raw, `record ${index + 1}`);
    exactKeys(record, ["format", "instance_id", "chain_id", "sequence", "record_id", "record_type", "created_at", "signer", "previous_record_sha256", "management_audit_tail_sha256", "payload"], `Record ${index + 1}`);
    if (record.format !== RECORD_FORMAT || record.sequence !== index + 1 || !canonicalUuid(record.record_id) || match[1] !== String(index + 1).padStart(12, "0") || match[2] !== record.record_id || record.instance_id !== manifest.instance_id || record.chain_id !== manifest.chain_id || record.previous_record_sha256 !== previous || record.signer?.key_id !== manifest.instance_key_id || record.signer?.role !== "instance" || Object.keys(record.signer || {}).sort().join(",") !== "key_id,role" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(record.created_at) || typeof record.payload !== "object" || record.payload === null || Array.isArray(record.payload)) fail(`Record ${index + 1} breaks the declared signed chain.`);
    const signature = payload.get(`${name}.sig`);
    if (!signature) fail(`Record ${index + 1} has no signature.`);
    await verifySshSignature(raw, asciiDecoder.decode(signature), instancePub.canonical);
    head = await sha256(raw); previous = head;
  }
  if (head !== manifest.chain_head_sha256) fail("The verified signed-chain head does not match the bundle manifest.");
  addCheck(`All ${records.length} record signatures and chain links`);
  const rowsDigest = await sha256(textEncoder.encode(`${canonicalJson({ files: manifest.files })}\n`));
  const identity = [manifest.controller_id, manifest.instance_id, manifest.chain_head_sha256, rowsDigest].join("|");
  if (await uuidV5(UUID_NAMESPACE, identity) !== manifest.bundle_id) fail("The deterministic bundle identity does not match its contents.");
  addCheck("Deterministic bundle identity and exact chain-head binding");
  return manifest;
}

function addDetail(container, term, value) {
  const dt = document.createElement("dt"); dt.textContent = term;
  const dd = document.createElement("dd"); dd.textContent = value;
  container.append(dt, dd);
}
if (typeof document !== "undefined") {
  const input = document.getElementById("evidence-file");
  const button = document.getElementById("verify-button");
  const result = document.getElementById("result");
  input.addEventListener("change", () => { button.disabled = !input.files?.length; result.hidden = true; });
  button.addEventListener("click", async () => {
  const file = input.files?.[0]; if (!file) return;
  result.hidden = false; result.setAttribute("aria-busy", "true"); button.disabled = true;
  const title = document.getElementById("result-title"); const summary = document.getElementById("result-summary");
  const details = document.getElementById("result-details"); const checks = document.getElementById("result-checks");
  title.textContent = "Verifying…"; summary.textContent = "Reading and checking the selected file locally."; details.replaceChildren(); checks.replaceChildren(); result.className = "verification-result pending";
  const addCheck = (label) => { const item = document.createElement("li"); item.textContent = label; checks.append(item); };
  try {
    if (file.size <= 0 || file.size > MAX_ZIP_BYTES) fail("The selected ZIP is empty or exceeds the 258 MiB safety limit.");
    const zipRaw = new Uint8Array(await file.arrayBuffer()); const zip = parseZip(zipRaw); addCheck("Canonical three-file ZIP structure and CRC values");
    const bundleRaw = zip.get("accountability.evidence"); const bundleHash = await sha256(bundleRaw);
    if (textDecoder.decode(zip.get("accountability.evidence.sha256")) !== `${bundleHash}  accountability.evidence\n`) fail("The accountability.evidence checksum receipt does not match.");
    addCheck("Accountability bundle SHA-256 receipt");
    const manifest = await verifyBundle(bundleRaw, addCheck);
    title.textContent = "Evidence is valid"; summary.textContent = "The package passed its local integrity, trust-signature, and signed-chain checks.";
    addDetail(details, "Bundle ID", manifest.bundle_id); addDetail(details, "Controller ID", manifest.controller_id); addDetail(details, "Instance ID", manifest.instance_id);
    addDetail(details, "Records", String(manifest.record_count)); addDetail(details, "Chain head SHA-256", manifest.chain_head_sha256); addDetail(details, "Bundle SHA-256", bundleHash); addDetail(details, "ZIP SHA-256", await sha256(zipRaw));
    result.className = "verification-result valid";
  } catch (error) {
    title.textContent = "Evidence is not valid"; summary.textContent = error instanceof Error ? error.message : "The selected package could not be verified."; result.className = "verification-result invalid";
  } finally { result.setAttribute("aria-busy", "false"); button.disabled = false; }
  });
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { parseZip, verifyBundle, sha256 };
}
