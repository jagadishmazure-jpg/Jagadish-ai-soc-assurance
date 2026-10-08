"""Download a few OTRF Security-Datasets recordings at a pinned commit, verify them and keep a small sample.

OTRF Security-Datasets (https://github.com/OTRF/Security-Datasets) is MIT licensed. Each dataset is a
recording of one attack technique run in a lab, as Windows event and Sysmon logs. This script keeps only
the Sysmon process-creation events (event ID 1) and a handful of their fields, so the vendored sample in
data/otrf/ is a few kilobytes. Host and user names are dropped; the replay assigns fictional ones.

    python scripts/vendor_otrf.py            # download into .cache/otrf, verify SHA-256, rewrite data/otrf/
    python scripts/vendor_otrf.py --check    # re-derive the sample and fail if data/otrf/ differs

Needs network access, so CI does not run it; the tests check the vendored sample's structure instead."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache" / "otrf"
DATA = ROOT / "data" / "otrf"
KEEP = ("Image", "ParentImage", "CommandLine")


def manifest() -> dict:
    return yaml.safe_load((DATA / "datasets.yaml").read_text())


def fetch(url: str, sha256: str) -> bytes:
    CACHE.mkdir(parents=True, exist_ok=True)
    f = CACHE / url.rsplit("/", 1)[1]
    if not f.exists():
        with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 - fixed https URL at a pinned commit
            f.write_bytes(r.read())
    blob = f.read_bytes()
    got = hashlib.sha256(blob).hexdigest()
    if got != sha256:
        raise SystemExit(f"{f.name}: sha256 {got} does not match the manifest ({sha256})")
    return blob


def sysmon_process_events(blob: bytes) -> list[dict]:
    rows = []
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for name in z.namelist():
            if not name.endswith(".json"):
                continue
            for line in z.read(name).decode("utf-8", "replace").splitlines():
                if not line.strip():
                    continue
                r = json.loads(line)
                if r.get("EventID") == 1 and "Sysmon" in str(r.get("Channel", "")):
                    rows.append(r)
    return rows


def _ts(r: dict) -> datetime:
    return datetime.strptime(r["UtcTime"][:19], "%Y-%m-%d %H:%M:%S")


def sample() -> list[dict]:
    m = manifest()
    out = []
    for ds in m["datasets"]:
        url = f"{m['source']['raw_base']}/{m['source']['commit']}/{ds['path']}"
        rows = sorted(sysmon_process_events(fetch(url, ds["sha256"])), key=lambda r: (_ts(r), r.get("ProcessId", 0)))
        t0 = _ts(rows[0])
        for i, r in enumerate(rows):
            sha = next((h.split("=", 1)[1] for h in str(r.get("Hashes", "")).split(",") if h.startswith("SHA256=")), "")
            out.append({"dataset": ds["id"], "seq": i + 1, "offset_s": int((_ts(r) - t0).total_seconds()), **{k: r.get(k, "") for k in KEEP}, "SHA256": sha})
    return out


def render(rows: list[dict]) -> str:
    return "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)


def main(argv: list[str]) -> int:
    text = render(sample())
    target = DATA / "process-events.jsonl"
    if "--check" in argv:
        ok = target.read_text() == text
        print(f"{target.name}: {'matches' if ok else 'DIFFERS from'} the pinned upstream recordings")
        return 0 if ok else 1
    target.write_text(text)
    print(f"wrote {target.relative_to(ROOT)}: {text.count(chr(10))} process events from {len(manifest()['datasets'])} datasets")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
