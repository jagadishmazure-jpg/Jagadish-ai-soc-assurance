"""The doc renderer: output blocks and code excerpts."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("render_docs", ROOT / "scripts/render_docs.py")
rd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rd)


def test_output_block_is_filled_from_the_cli():
    out = rd.render("<!-- output: claim --k 87 --n 100 --claimed 87 -->\nstale\n<!-- /output -->\n")
    assert "Wilson interval" in out and "stale" not in out


def test_python_excerpt_is_the_current_function():
    lang, body = rd.excerpt("src/socassure/stats.py::wilson")
    assert lang == "python" and body.startswith("def wilson")


def test_constant_excerpt():
    _, body = rd.excerpt("src/socassure/benchmark.py::METRICS")
    assert body.startswith("METRICS")


def test_hcl_block_excerpt_balances_braces():
    lang, body = rd.excerpt('infra/terraform/main.tf::resource "azurerm_subscription_policy_assignment" "residency"')
    assert lang == "hcl" and body.count("{") == body.count("}")


def test_bicep_block_excerpt():
    lang, body = rd.excerpt("infra/bicep/main.bicep::resource assignment")
    assert lang == "bicep" and body.rstrip().endswith("}")


def test_unknown_name_fails():
    with pytest.raises(SystemExit):
        rd.excerpt("src/socassure/stats.py::nope")


def test_rendered_docs_never_include_the_sut_checkout():
    assert all(".sut" not in p.parts for p in rd.md_files())
