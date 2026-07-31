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
import sys
sys.path[:0] = {source_roots}
sys.modules["fcntl"] = None

import faultloom.automation as automation
import faultloom.automation.coordinator as coordinator
import faultloom.automation_cli as automation_cli
import faultloom.hypothesis as hypothesis

assert automation.AuthorizedAutomationCoordinator is coordinator.AuthorizedAutomationCoordinator
assert coordinator.HypothesisSeed is hypothesis.HypothesisSeed
assert automation_cli.AutomationCompileError.__name__ == "AutomationCompileError"
assert "faultloom.state" not in sys.modules
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
    from faultloom.provider import OPENAI_COMPATIBLE_MAX_TOOL_ARGUMENT_BYTES

    for name in automation.__all__:
        assert getattr(automation, name) is not None
    for name in hypothesis.__all__:
        assert getattr(hypothesis, name) is not None
    assert automation.AutomationLimits().max_response_bytes == OPENAI_COMPATIBLE_MAX_TOOL_ARGUMENT_BYTES
