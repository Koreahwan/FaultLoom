from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Final

from faultloom_protocol import EvidenceRef

NOW: Final = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
RUN_ID: Final = "run.patch-variant-lab"


def evidence(label: str) -> EvidenceRef:
    return EvidenceRef(
        schema_version="0.1.0",
        evidence_id=f"evidence.{label}",
        run_id=RUN_ID,
        cas_digest=digest(label),
        observation_ids=(f"observation.{label}",),
        created_at=NOW,
    )


def digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"
