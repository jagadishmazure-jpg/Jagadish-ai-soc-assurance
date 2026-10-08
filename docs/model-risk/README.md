# Model risk packs

One pack per agent of the system under test: a model card, a risk card and a validation report whose
numbers are rendered from `socassure validate`. The method is described in
[components/model-risk.md](../components/model-risk.md).

| File | What it does |
| --- | --- |
| `triage.md` | triage agent: closes incidents; not validated for production (fails on public recordings) |
| `investigation.md` | investigation agent: evidence and narrative; guardrails hold under simulated failures |
| `response.md` | response agent: containment proposals; validated only with careful approvers (FM-11) |
| `framework-mapping.md` | NIST AI RMF, EU AI Act, ISO/IEC 42001 and SR 11-7, paraphrased, with links |
