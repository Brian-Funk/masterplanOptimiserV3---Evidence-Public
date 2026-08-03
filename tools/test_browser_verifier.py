#!/usr/bin/env python3
"""Generate signed synthetic evidence and exercise the browser verifier."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import evidence_git  # noqa: E402
import evidence_manifest  # noqa: E402
import portable_bundle  # noqa: E402


INSTANCE_ID = "11111111-1111-4111-8111-111111111111"
CHAIN_ID = "22222222-2222-4222-8222-222222222222"
CONTROLLER_ID = "ctl-controller000001"


def keypair(directory: Path, name: str) -> tuple[Path, Path]:
    private = directory / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private)], check=True)
    return private, private.with_suffix(".pub")


def signed(path: Path, value: dict, private: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(evidence_git.canonical_json(value))
    evidence_manifest.sign_file(path, private)


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
    for name in ("requests", "purges", "attestations", "backups", "anchors", "summaries"):
        (instance_root / name).mkdir()
    bundle = directory / "accountability.evidence"
    export_zip = directory / "accountability-evidence.zip"
    portable_bundle.create_bundle(repository, INSTANCE_ID, bundle)
    portable_bundle.create_evidence_zip(bundle, export_zip)
    return export_zip


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="mp-opt-browser-verifier-test.") as directory_name:
        export_zip = fixture(Path(directory_name))
        subprocess.run(["node", str(ROOT / "tools" / "test_browser_verifier.js"), str(export_zip)], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
