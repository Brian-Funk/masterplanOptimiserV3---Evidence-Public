#!/usr/bin/env python3
"""Generate signed synthetic evidence and exercise the browser verifier."""

from __future__ import annotations

from pathlib import Path
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import evidence_git  # noqa: E402
import evidence_manifest  # noqa: E402
import portable_bundle  # noqa: E402


INSTANCE_ID = "11111111-1111-4111-8111-111111111111"
CHAIN_ID = "22222222-2222-4222-8222-222222222222"
CONTROLLER_ID = "ctl-controller000001"
LOCAL_BUNDLE_NAMESPACE = uuid.UUID("aa0c67fb-6a9c-4cf3-b712-c4cde822e7be")


def keypair(directory: Path, name: str) -> tuple[Path, Path]:
    private = directory / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private)], check=True)
    return private, private.with_suffix(".pub")


def signed(path: Path, value: dict, private: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(evidence_git.canonical_json(value))
    evidence_manifest.sign_file(path, private)


def desktop_proof(document: dict) -> tuple[dict, str, str]:
    script = """
const { createHash, generateKeyPairSync, sign } = require('node:crypto');
const document = JSON.parse(Buffer.from(process.argv[1], 'base64').toString('utf8'));
const canonical = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
};
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const der = publicKey.export({ type: 'spki', format: 'der' });
const raw = der.subarray(der.length - 32);
const algorithm = Buffer.from('ssh-ed25519');
const length = (value) => { const result = Buffer.alloc(4); result.writeUInt32BE(value.length); return result; };
const blob = Buffer.concat([length(algorithm), algorithm, length(raw), raw]);
const publicText = `ssh-ed25519 ${blob.toString('base64')}`;
const fingerprint = createHash('sha256').update(publicText, 'ascii').digest('hex');
document.key_id = `ek-${fingerprint.slice(0, 16)}`;
document.public_key_sha256 = fingerprint;
const message = Buffer.concat([Buffer.from('mp-opt-desktop-evidence-v1\\0', 'ascii'), Buffer.from(`${canonical(document)}\\n`, 'utf8')]);
process.stdout.write(JSON.stringify({
  document,
  publicKey: publicText,
  signature: sign(null, message, privateKey).toString('base64')
}));
"""
    result = subprocess.run(
        ["node", "-e", script, base64.b64encode(json.dumps(document).encode()).decode("ascii")],
        check=True, capture_output=True, text=True,
    )
    material = json.loads(result.stdout)
    return material["document"], material["publicKey"], material["signature"]


def fixture(directory: Path) -> Path:
    repository = directory / "repository"
    (repository / "trust" / "processors").mkdir(parents=True)
    (repository / "instances").mkdir()
    controller_private, controller_public = keypair(directory, "controller")
    instance_private, instance_public = keypair(directory, "instance")
    controller_key = evidence_manifest.canonical_public_key(controller_public.read_text(encoding="ascii"))
    instance_key = evidence_manifest.canonical_public_key(instance_public.read_text(encoding="ascii"))
    controller = {
        "format": evidence_git.CONTROLLER_FORMAT,
        "controller_id": CONTROLLER_ID,
        "display_name": "Synthetic Controller",
        "jurisdiction": "CH",
        "signing_key_id": evidence_manifest.key_id(controller_key),
        "signing_public_key": controller_key,
        "revoked_key_ids": [],
        "status": "active",
        "signed_at": "2026-01-01T00:00:00Z",
    }
    (repository / "trust" / "controller.pub").write_text(controller_key + "\n", encoding="ascii")
    signed(repository / "trust" / "controller.json", controller, controller_private)
    instance_root = repository / "instances" / INSTANCE_ID
    (instance_root / "trust").mkdir(parents=True)
    (instance_root / "trust" / "instance.pub").write_text(instance_key + "\n", encoding="ascii")
    signed(
        instance_root / "trust" / "instance.json",
        {
            "format": evidence_git.INSTANCE_FORMAT,
            "instance_id": INSTANCE_ID,
            "controller_id": CONTROLLER_ID,
            "signing_key_id": evidence_manifest.key_id(instance_key),
            "signing_public_key": instance_key,
            "processor_ids": [],
            "status": "active",
            "signed_at": "2026-01-01T00:00:00Z",
        },
        controller_private,
    )
    evidence_manifest.append_record(
        instance_root / "ledger",
        instance_id=INSTANCE_ID,
        chain_id=CHAIN_ID,
        record_type="instance.initialised",
        payload={"status": "initialised"},
        private_key=instance_private,
        public_key=instance_root / "trust" / "instance.pub",
        created_at="2026-01-01T00:00:00Z",
        record_id="33333333-3333-4333-8333-333333333333",
    )
    document = {
        "format": "mp-opt-desktop-policy-acknowledgement-v1",
        "instance_id": INSTANCE_ID,
        "event_ref": "44444444-4444-4444-8444-444444444444",
        "entity_id": "prc-synthetic0001",
        "role": "processor",
        "algorithm": "Ed25519",
        "policy_version": 1,
        "policy_sha256": "a" * 64,
        "acknowledged_at": "2026-01-01T00:01:00Z",
    }
    document, processor_public, signature = desktop_proof(document)
    processor_key_id = evidence_manifest.key_id(processor_public)
    fingerprint = hashlib.sha256(processor_public.encode("ascii")).hexdigest()
    assert document["key_id"] == processor_key_id
    assert document["public_key_sha256"] == fingerprint
    document_raw = evidence_git.canonical_json(document)
    proof = {
        "format": "mp-opt-ed25519-signature-v1",
        "key_id": processor_key_id,
        "namespace": "mp-opt-desktop-evidence-v1",
        "signature": signature,
    }
    package = {
        "format": "mp-opt-signed-desktop-evidence-v1",
        "namespace": "mp-opt-desktop-evidence-v1",
        "document": document,
        "proof": proof,
        "public_key": processor_public,
    }
    package_raw = evidence_git.canonical_json(package)
    package_sha256 = hashlib.sha256(package_raw).hexdigest()
    evidence_manifest.append_record(
        instance_root / "ledger",
        instance_id=INSTANCE_ID,
        chain_id=CHAIN_ID,
        record_type="desktop.policy_acknowledged",
        payload={
            "event_ref": document["event_ref"],
            "entity_id": document["entity_id"],
            "key_id": processor_key_id,
            "policy_version": 1,
            "policy_sha256": document["policy_sha256"],
            "document_sha256": hashlib.sha256(document_raw).hexdigest(),
            "signature_sha256": hashlib.sha256(evidence_git.canonical_json(proof)).hexdigest(),
            "evidence_package_sha256": package_sha256,
            "public_key_sha256": fingerprint,
            "status": "verified",
        },
        private_key=instance_private,
        public_key=instance_root / "trust" / "instance.pub",
        created_at="2026-01-01T00:01:00Z",
        record_id="55555555-5555-4555-8555-555555555555",
    )
    artifacts = {package_sha256: package_raw}

    def append_deletion_artifact(
        *, document: dict, record_type: str, digest_field: str,
        created_at: str, record_id: str,
    ) -> None:
        signed_document, public_key, desktop_signature = desktop_proof(document)
        key_id = evidence_manifest.key_id(public_key)
        public_fingerprint = hashlib.sha256(public_key.encode("ascii")).hexdigest()
        signed_proof = {
            "format": "mp-opt-ed25519-signature-v1",
            "key_id": key_id,
            "namespace": "mp-opt-desktop-evidence-v1",
            "signature": desktop_signature,
        }
        signed_package = {
            "format": "mp-opt-signed-desktop-evidence-v1",
            "namespace": "mp-opt-desktop-evidence-v1",
            "document": signed_document,
            "proof": signed_proof,
            "public_key": public_key,
        }
        signed_package_raw = evidence_git.canonical_json(signed_package)
        signed_package_sha256 = hashlib.sha256(signed_package_raw).hexdigest()
        domain_document_raw = evidence_git.canonical_json(signed_document).rstrip(b"\n")
        payload = {
            "case_id": "66666666-6666-4666-8666-666666666666",
            "work_order_id": signed_document["work_order_id"],
            "event_ref": signed_document["event_ref"],
            "processor_entity_id": signed_document["entity_id"],
            "processor_key_id": key_id,
            digest_field: hashlib.sha256(domain_document_raw).hexdigest(),
            "signature_sha256": hashlib.sha256(
                evidence_git.canonical_json(signed_proof)
            ).hexdigest(),
            "evidence_package_sha256": signed_package_sha256,
            "completed_public_key_sha256": public_fingerprint,
            "status": "verified",
        }
        evidence_manifest.append_record(
            instance_root / "ledger",
            instance_id=INSTANCE_ID,
            chain_id=CHAIN_ID,
            record_type=record_type,
            payload=payload,
            private_key=instance_private,
            public_key=instance_root / "trust" / "instance.pub",
            created_at=created_at,
            record_id=record_id,
        )
        artifacts[signed_package_sha256] = signed_package_raw

    shared_deletion = {
        "instance_id": INSTANCE_ID,
        "event_ref": "44444444-4444-4444-8444-444444444444",
        "entity_id": "prc-synthetic0001",
        "role": "processor",
        "algorithm": "Ed25519",
        "work_order_id": "77777777-7777-4777-8777-777777777777",
        "completed_at": "2026-01-01T00:02:00Z",
    }
    append_deletion_artifact(
        document={
            **shared_deletion,
            "format": "mp-opt-desktop-deletion-receipt-v2",
            "subject_ref": "88888888-8888-4888-8888-888888888888",
            "operation": "delete_subject",
            "outcome": "deleted",
            "deleted_counts": {"availability": 1},
            "outstanding_actions": [],
        },
        record_type="deletion.desktop_report_received",
        digest_field="report_sha256",
        created_at="2026-01-01T00:02:00Z",
        record_id="99999999-9999-4999-8999-999999999999",
    )
    append_deletion_artifact(
        document={
            **shared_deletion,
            "format": "mp-opt-desktop-copy-resolution-v1",
            "disposition": "no_known_local_copies",
            "software_inventory_complete": True,
            "operator_confirmation": "LOCAL COPIES RESOLVED",
        },
        record_type="deletion.desktop_copy_resolution",
        digest_field="copy_resolution_sha256",
        created_at="2026-01-01T00:03:00Z",
        record_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    )
    for name in ("requests", "purges", "attestations", "backups", "anchors", "summaries"):
        (instance_root / name).mkdir()
    home = directory / "local-evidence"
    shutil.copytree(instance_root / "ledger", home / "ledger")
    (home / "public").mkdir()
    shutil.copyfile(instance_root / "trust" / "instance.pub", home / "public" / "instance_signing_key.pub")
    (home / "anchors").mkdir()
    (home / "artifacts").mkdir()
    for artifact_sha256, artifact_raw in artifacts.items():
        (home / "artifacts" / f"{artifact_sha256}.json").write_bytes(artifact_raw)
    payload = {
        path.relative_to(home).as_posix(): path.read_bytes()
        for root_name in ("anchors", "artifacts", "ledger", "public")
        for path in sorted((home / root_name).rglob("*"))
        if path.is_file()
    }
    rows = [
        {"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
        for path, raw in sorted(payload.items())
    ]
    chain = evidence_manifest.verify_chain(home / "ledger", home / "public" / "instance_signing_key.pub")
    identity = "|".join((
        chain["instance_id"], chain["chain_id"], chain["head_sha256"],
        hashlib.sha256(evidence_git.canonical_json({"files": rows})).hexdigest(),
    ))
    latest = evidence_manifest.load_json_bytes(sorted((home / "ledger").glob("[0-9]" * 12 + "_*.json"))[-1].read_bytes())
    document = {
        "format": "mp-opt-evidence-bundle-v1",
        "bundle_id": str(uuid.uuid5(LOCAL_BUNDLE_NAMESPACE, identity)),
        "created_at": latest["created_at"],
        "instance_id": chain["instance_id"],
        "chain_id": chain["chain_id"],
        "chain_head_sha256": chain["head_sha256"],
        "record_count": chain["records"],
        "files": rows,
    }
    bundle = directory / "accountability.evidence"
    with tarfile.open(bundle, "w", format=tarfile.GNU_FORMAT) as archive:
        portable_bundle._add_bytes(archive, "bundle.json", evidence_git.canonical_json(document))
        for path, raw in sorted(payload.items()):
            portable_bundle._add_bytes(archive, f"evidence/{path}", raw)
    bundle_raw = bundle.read_bytes()
    bundle_sha256 = hashlib.sha256(bundle_raw).hexdigest()
    export_zip = directory / "accountability-evidence.zip"
    with zipfile.ZipFile(export_zip, "w", allowZip64=False) as archive:
        archive.writestr(portable_bundle._zip_info("accountability.evidence"), bundle_raw)
        archive.writestr(portable_bundle._zip_info("accountability.evidence.sha256"), f"{bundle_sha256}  accountability.evidence\n".encode("ascii"))
        archive.writestr(portable_bundle._zip_info("VERIFYING.txt"), b"Synthetic local verifier fixture\n")
    return export_zip


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="mp-opt-browser-verifier-test.") as directory_name:
        export_zip = fixture(Path(directory_name))
        subprocess.run(["node", str(ROOT / "tools" / "test_browser_verifier.js"), str(export_zip)], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
