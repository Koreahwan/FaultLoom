from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOTS = (
    ROOT / "packages" / "protocol" / "src",
    ROOT / "packages" / "sdk" / "src",
    ROOT / "packages" / "runtime" / "src",
)


def test_offline_automation_imports_do_not_require_fcntl() -> None:
    source_roots = repr([str(path) for path in SOURCE_ROOTS])
    script = f"""
import hashlib
import sys
sys.path[:0] = {source_roots}
sys.modules["fcntl"] = None

import faultloom.automation as automation
import faultloom.automation.coordinator as coordinator
import faultloom.automation_cli as automation_cli
import faultloom.cli as cli
import faultloom.hypothesis as hypothesis
from faultloom.automation.models import (
    AutomationLimits,
    ReasoningEvidence,
    ReasoningScopeSummary,
    ReasoningTurnRequest,
)
from faultloom.automation.provider_prompt import build_reasoning_chat_payload
from faultloom.provider import GenerationConfig, provider_sha256_digest
from faultloom.tool_planner import PlanningBudget
from faultloom_protocol.models import ActionClass

context = ReasoningTurnRequest(
    run_id="run.windows-safe",
    evidence=(
        ReasoningEvidence(
            evidence_id="evidence.windows-safe",
            cas_digest=provider_sha256_digest("cas"),
            redaction_digest=provider_sha256_digest("redaction"),
            media_type="text/plain",
            content="redacted owned observation",
            content_digest="sha256:" + hashlib.sha256(b"redacted owned observation").hexdigest(),
            redacted=True,
            untrusted=True,
        ),
    ),
    authority_grant_digest=provider_sha256_digest("authority"),
    scope=ReasoningScopeSummary(
        target_ids=("target.windows-safe",),
        pack_ids=("pack.web",),
        adapter_ids=("adapter.http",),
        allowed_action_classes=(ActionClass.OBSERVE,),
        allowed_action_families=("http.request",),
    ),
    remaining_budget=PlanningBudget(
        rate_slots=1,
        duration_seconds=1,
        bytes=1,
        concurrency=1,
        actions=1,
        cost_microunits=1,
    ),
    limits=AutomationLimits(),
    output_schema_digest=provider_sha256_digest("model-turn"),
)
payload = build_reasoning_chat_payload(
    context,
    generation=GenerationConfig(
        max_output_tokens=1,
        temperature_milli=0,
        top_p_milli=1000,
        seed=0,
        response_format="json",
    ),
)

assert automation.AuthorizedAutomationCoordinator is coordinator.AuthorizedAutomationCoordinator
assert coordinator.HypothesisSeed is hypothesis.HypothesisSeed
assert automation_cli.AutomationCompileError.__name__ == "AutomationCompileError"
assert payload.messages[0].role == "system"
assert "faultloom.state" not in sys.modules
assert "faultloom._provider.adapter" not in sys.modules
assert "faultloom._provider.anchored_journal" not in sys.modules
assert "faultloom.automation.execution_bridge" not in sys.modules
assert "faultloom.automation.persistence" not in sys.modules
assert "faultloom.hypothesis.journal" not in sys.modules
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="durable state APIs require POSIX fcntl")
def test_posix_public_exports_remain_accessible() -> None:
    import faultloom.automation as automation
    import faultloom.hypothesis as hypothesis
    import faultloom.provider as provider

    for name in automation.__all__:
        assert getattr(automation, name) is not None
    for name in hypothesis.__all__:
        assert getattr(hypothesis, name) is not None
    for name in provider.__all__:
        assert getattr(provider, name) is not None
    assert (
        automation.AutomationLimits().max_response_bytes
        == provider.OPENAI_COMPATIBLE_MAX_TOOL_ARGUMENT_BYTES
    )
