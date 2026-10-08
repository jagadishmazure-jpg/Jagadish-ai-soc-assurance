# Architecture

The assurance layer sits beside an AI SOC, never inside it. It drives the system under test (SUT) through
an adapter, owns the ground truth, and turns runs into evidence: benchmark estimates, fault-experiment
observations, residency checks, validation reports, an audit report and a scorecard.

```mermaid
flowchart TB
  subgraph Inputs
    SC[scenario suites<br/>synthetic seeds 101-110<br/>adversarial: injection, evasion, flood, drift<br/>OTRF public recordings]
    OR[oracle: simulated analysts<br/>honest, rubber-stamp, poisoned]
    CFG[config: benchmark, adversarial,<br/>failure modes, model risk,<br/>residency, scorecard]
  end
  subgraph Adapters
    A1[azure-ai-soc<br/>pinned commit, fault patches]
    A2[azure-ai-soc-static<br/>feedback loop off]
    A3[always-escalate]
    A4[severity-rules]
    A5[recorded JSONL<br/>any product's export]
    A6[third-party stub<br/>documented contract]
  end
  SC --> A1 & A2 & A3 & A4 & A5
  OR <--> A1
  A1 & A2 & A3 & A4 & A5 --> DEC[neutral decisions + audit records]
  DEC --> BEN[benchmark<br/>cluster bootstrap]
  DEC --> FM[failure-mode experiments]
  DEC --> AUD[audit replay]
  BEN & FM & AUD --> MR[model-risk validation,<br/>drift, challenger]
  CFG --> RES[residency checks]
  RES --> IAC[Azure Policy<br/>Terraform + Bicep]
  BEN & FM & AUD & RES & MR --> SCO[scorecard with caps]
  BEN & FM & AUD & RES & MR & SCO --> GATE[socassure gate in CI]
  GATE --> DOCS[docs rendered from real runs]
```

## Layers

| Layer | Code | Contract |
| --- | --- | --- |
| Scenarios | `src/socassure/scenarios.py`, `model.py` | neutral `Scenario`: tables, labels, stories; the harness keeps the labels |
| Oracle | `src/socassure/oracle.py` | answers review, approval and QA questions from ground truth, with a chosen behaviour |
| Adapters | `src/socassure/adapters/` | `run(scenario, oracle, faults) -> SutResult`; unsupported faults raise |
| Evidence | `benchmark.py`, `failures.py`, `audit_replay.py`, `residency.py`, `modelrisk.py`, `scorecard.py`, `claims.py` | pure functions over runs and configuration |
| Interface | `cli.py`, `scripts/render_docs.py` | every number in the docs is a CLI output checked in CI |
| Enforcement | `infra/terraform`, `infra/bicep` | Azure Policy initiative per customer subscription |

## Decisions

The main design choices are recorded as ADRs in [adr/](adr/README.md): the adapter boundary, the oracle
owning truth, clustered intervals, criteria judged on the conservative bound, failing closed on unknown
residency, and never scoring a real product.

## What runs where

Everything runs offline on one machine: Python 3.13, the SUT installed from its pinned commit, no network
except to fetch the SUT and (optionally) re-vendor OTRF data. Nothing is deployed. The deploy workflow
exists for an adopter and is gated off.
