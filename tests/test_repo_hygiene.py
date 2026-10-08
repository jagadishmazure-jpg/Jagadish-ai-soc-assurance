"""Repository hygiene: complete docs, current outputs, no dates, no real identifiers, no copied whitepaper."""

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", ".pytest_cache", ".ruff_cache", "__pycache__", ".terraform", ".sut", ".cache", "out", "evidence"}
MD = sorted(p for p in ROOT.rglob("*.md") if not SKIP_PARTS & set(p.relative_to(ROOT).parts))
SECTIONS = [
    "Purpose", "Architecture", "How it works", "Key files", "Code excerpts", "Configuration", "Commands",
    "Real output", "Tests and gates", "Guardrails", "Security and governance", "Observability",
    "Failure modes", "Mapping to Azure services", "Limitations", "Interview talking points",
]  # fmt: skip
COMPONENT_DOCS = sorted(p for p in (ROOT / "docs/components").glob("*.md") if p.name != "README.md")
SERVICES = ("Microsoft Sentinel", "Defender XDR", "Foundry", "Entra ID", "Azure Policy", "Azure Monitor")
MONTHS = r"\b(January|February|March|April|June|July|August|September|October|November|December)\b"
SUFFIXES = {".md", ".py", ".json", ".yml", ".yaml", ".tf", ".bicep", ".hcl", ".sh", ".toml", ".jsonl", ".tfvars"}
TEXT_FILES = [p for p in ROOT.rglob("*") if p.is_file() and not SKIP_PARTS & set(p.relative_to(ROOT).parts) and p.suffix in SUFFIXES]
# The OTRF recordings contain the public COM class id of the comsvcs MiniDump technique.
PUBLIC_GUIDS = {"3e5fc7f9-9a51-4367-9063-a120244fbec7"}
GUIDE_LINK = "https://www.conifers.ai/blog/ai-powered-soc/"
GAPS = ("Independent benchmarks", "Failure modes", "Data residency", "Model risk", "Decision audit", "Product comparison")


def flat(path: Path) -> str:
    return " ".join(path.read_text().split())


def folders():
    yield from sorted({p.parent for p in ROOT.rglob("*") if p.is_file() and not SKIP_PARTS & set(p.relative_to(ROOT).parts)})


@pytest.mark.parametrize("folder", [f for f in folders() if f != ROOT / ".github"], ids=lambda p: str(p.relative_to(ROOT)) or ".")
def test_every_folder_has_a_readme_with_a_file_table(folder):
    readme = folder / "README.md"
    assert readme.exists(), f"{folder} has no README.md"
    if folder != ROOT:
        assert "| File | What it does |" in readme.read_text()


def test_folder_readmes_list_every_child():
    for readme in MD:
        if readme.name != "README.md" or readme.parent == ROOT:
            continue
        text = readme.read_text()
        for child in readme.parent.iterdir():
            if child.name in {"README.md", "__pycache__", ".terraform", ".terraform.lock.hcl"}:
                continue
            name = child.name + ("/" if child.is_dir() else "")
            assert f"`{name}`" in text, f"{readme.relative_to(ROOT)} does not list {name}"


def test_no_dates_in_markdown():
    for p in MD:
        t = re.sub(r"https?://\S+", "", p.read_text())
        t = re.sub(r"@\d{4}-\d{2}-\d{2}(-preview)?", "", t)
        assert not re.search(r"\b\d{4}-\d{2}-\d{2}\b", t), f"ISO date in {p}"
        assert not re.search(r"(?<![\w$,.])20[1-3]\d(?![\w,.%])", t), f"year in {p}"
        assert not re.search(MONTHS, t), f"month name in {p}"
        assert "Date:" not in t, f"Date line in {p}"


def test_no_todos_or_placeholders():
    for p in MD:
        t = p.read_text()
        for word in ("TODO", "TBD", "FIXME", "lorem ipsum", "coming soon", "being written"):
            assert word not in t, f"{word} in {p}"


def test_full_doc_set_exists():
    names = {p.stem for p in COMPONENT_DOCS}
    assert names == {"benchmark", "failure-modes", "data-residency", "model-risk", "decision-audit", "product-scorecard"}
    for top in ("architecture", "gaps", "threat-model", "vendor-claims", "adopt-this", "interview-guide", "limitations"):
        assert (ROOT / "docs" / f"{top}.md").exists(), top
    for agent in ("triage", "investigation", "response"):
        assert (ROOT / "docs/model-risk" / f"{agent}.md").exists(), agent


@pytest.mark.parametrize("doc", COMPONENT_DOCS, ids=lambda p: p.name)
def test_component_doc_has_all_sections_in_order(doc):
    t = doc.read_text()
    pos = [t.find(f"## {i}. {s}") for i, s in enumerate(SECTIONS, 1)]
    assert all(x >= 0 for x in pos), [s for s, x in zip(SECTIONS, pos, strict=True) if x < 0]
    assert pos == sorted(pos)
    assert "```mermaid" in t and "<!-- output:" in t and "<!-- code:" in t
    for svc in SERVICES:
        assert svc in t, f"{doc.name} does not map to {svc}"


@pytest.mark.parametrize("agent", ["triage", "investigation", "response"])
def test_model_risk_pack_per_agent(agent):
    t = (ROOT / "docs/model-risk" / f"{agent}.md").read_text()
    for part in ("## Model card", "## Risk card", "## Validation report", "NIST AI RMF", "EU AI Act", "ISO/IEC 42001", "SR 11-7"):
        assert part in t, part
    assert f"<!-- output: validate --agent {agent} -->" in t
    assert "https://github.com/jagadishmazure-jpg/Jagadish-agentic-ai-model-risk" in t


def test_doc_links_resolve():
    for p in MD:
        for target in re.findall(r"\]\(([^)#\s]+\.md)(?:#[^)]*)?\)", p.read_text()):
            if target.startswith("http"):
                continue
            assert (p.parent / target).resolve().exists(), f"{p.relative_to(ROOT)} links to missing {target}"


def test_doc_outputs_and_excerpts_are_current():
    r = subprocess.run([sys.executable, "scripts/render_docs.py", "--check"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_no_secrets_or_real_identifiers():
    guid = re.compile(r"\b(?!00000000-)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
    bad = [re.compile(p, re.I) for p in (r"AccountKey=", r"-----BEGIN", r"client_secret\s*=", r"@gmail\.com", r"SharedAccessSignature=")]
    for p in TEXT_FILES:
        if p.name == "test_repo_hygiene.py":
            continue
        t = p.read_text(errors="ignore")
        found = {m.group(0).lower() for m in guid.finditer(t)}
        assert found <= PUBLIC_GUIDS, f"GUID-like identifier in {p}: {sorted(found - PUBLIC_GUIDS)}"
        for b in bad:
            assert not b.search(t), f"{b.pattern} in {p}"


def test_flood_uses_documentation_addresses():
    src = (ROOT / "src/socassure/scenarios.py").read_text()
    assert re.findall(r'f"(\d+\.\d+\.\d+\.)\{', src) == ["198.51.100."]


def test_whitepaper_is_never_committed_and_only_linked():
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    assert not [f for f in tracked if f.lower().endswith(".pdf") or f.endswith("sec.txt")]
    assert "*.pdf" in (ROOT / ".gitignore").read_text()
    gaps = flat(ROOT / "docs/gaps.md")
    assert "Conifers" in gaps and GUIDE_LINK in gaps and "not quoted" in gaps


def test_readme_maps_every_gap_to_a_section():
    t = flat(ROOT / "README.md")
    for g in GAPS:
        assert g in t, g
    assert GUIDE_LINK in t


def test_organisations_are_fictional():
    readme = flat(ROOT / "README.md")
    assert "fictional" in readme
    for org in ("Brightwater Logistics", "Orchid Valley Clinics", "Pinecrest Credit Union"):
        assert org in readme


def test_readme_never_claims_deployment():
    t = flat(ROOT / "README.md").lower()
    assert "never been deployed" in t
    assert "running in production" not in t and "live in production" not in t


def test_microsoft_statements_link_to_microsoft_docs():
    t = (ROOT / "docs/residency/deployment-types.md").read_text()
    assert "https://learn.microsoft.com/" in t and "unverified" in t.lower()


def test_changelog_has_only_unreleased():
    versions = re.findall(r"^## (.+)$", (ROOT / "CHANGELOG.md").read_text(), re.M)
    assert versions == ["Unreleased"]


def test_adrs_without_date_lines():
    adrs = sorted((ROOT / "docs/adr").glob("0*.md"))
    assert len(adrs) >= 6
    for a in adrs:
        t = a.read_text()
        assert "**Status:**" in t and "Date" not in t


def test_root_files_exist():
    for f in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", "LICENSE"):
        assert (ROOT / f).exists(), f


def test_security_policy_has_a_fallback_contact():
    t = (ROOT / "SECURITY.md").read_text()
    assert "Report a vulnerability" in t and "Security contact request" in t


def test_readme_has_recruiter_section_and_honest_test_count():
    t = (ROOT / "README.md").read_text()
    assert "## At a glance (for recruiters)" in t
    m = re.search(r"\*\*(\d+) automated tests\*\*", t)
    collected = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q"], cwd=ROOT, capture_output=True, text=True).stdout
    n = int(re.search(r"(\d+) tests? collected", collected).group(1))
    assert m and int(m.group(1)) == n, f"README says {m.group(1) if m else None}, pytest collects {n}"
