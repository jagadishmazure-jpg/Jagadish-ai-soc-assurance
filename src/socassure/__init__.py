"""Vendor-neutral assurance for AI-assisted security operations centres.

The harness treats any AI SOC as a system under test behind an adapter (socassure.adapters), feeds it
seeded scenarios whose ground truth it keeps to itself (socassure.scenarios), and scores what comes
back with confidence intervals (socassure.benchmark). Around that sit the failure-mode catalogue and
fault-injection experiments, data-residency checks, model risk artefacts, a decision-audit replay tool
and a product evaluation scorecard."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config"
DATA = ROOT / "data"
OUT = ROOT / "out"

__all__ = ["CONFIG", "DATA", "OUT", "ROOT"]
