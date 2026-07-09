from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_example(name: str) -> str:
    result = subprocess.run(
        [sys.executable, str(ROOT / "examples" / name)],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def test_quickstart_runs():
    output = run_example("quickstart.py")

    assert "authorize_subcall: Decision(allowed=True" in output
    assert "authorize_tool_call: Decision(allowed=True" in output


def test_authority_escape_demo_runs_and_denies_expansion():
    output = run_example("demo_authority_escape.py")

    assert "Naive ungoverned delegation allowed? True" in output
    assert "GovernanceRuntime decision: Decision(allowed=False" in output
    assert "TOOL_AUTHORITY_EXPANDED" in output
