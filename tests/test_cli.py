"""Every CLI command runs offline and the gate passes."""

import pytest

from socassure.cli import main, table

COMMANDS = [
    "suites", "bench", "bench --suite otrf --window all", "compare", "otrf", "evasion", "claim --k 87 --n 100 --claimed 87",
    "fmea", "chaos --experiment containment_probes", "residency", "residency --deployment proposed --all", "iac", "validate",
    "drift", "challenger", "scorecard --product azure-ai-soc",
]  # fmt: skip


@pytest.mark.parametrize("args", COMMANDS)
def test_command_runs(args, capsys):
    assert main(args.split()) == 0
    assert capsys.readouterr().out.strip()


def test_gate_passes(capsys):
    assert main(["gate"]) == 0
    assert "gate passed" in capsys.readouterr().out


def test_audit_replay_writes_three_reports(tmp_path, capsys):
    assert main(["audit-replay", "--out", str(tmp_path)]) == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == ["audit-decisions.csv", "audit-report.html", "audit-report.md"]


def test_export_writes_jsonl(tmp_path, capsys):
    out = tmp_path / "d.jsonl"
    assert main(["export", "--out", str(out)]) == 0
    assert out.read_text().count("\n") > 50


def test_table_aligns_columns():
    t = table([[1, "a"], [22, "bb"]], ["n", "s"])
    assert t.splitlines()[1] == "--  --"
