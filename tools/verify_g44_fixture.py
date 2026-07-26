#!/usr/bin/env python3
"""Verify G44 JSON evidence without importing or invoking the fixture lab."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packs" / "web3" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "protocol" / "src"))

from faultloom_web3.verifier import G44VerificationError, verify_g44_evidence  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--trusted-provenance-public-key", type=Path, required=True)
    parser.add_argument("--verification-time", required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
        loaded_key = serialization.load_pem_public_key(
            args.trusted_provenance_public_key.read_bytes()
        )
        if not isinstance(loaded_key, Ed25519PublicKey):
            raise G44VerificationError("trusted provenance key must be Ed25519 PEM")
        public_key_bytes = loaded_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        verification_time = datetime.strptime(
            args.verification_time, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        report = verify_g44_evidence(
            evidence,
            trusted_provenance_public_key=public_key_bytes,
            verification_time=verification_time,
        ).document()
    except (OSError, ValueError, TypeError) as exc:
        report = {"passed": False, "error": str(exc)}
        exit_code = 1
    else:
        exit_code = 0
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is None:
        sys.stdout.write(rendered)
    else:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding="utf-8")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
