# Interview guide

Talking points for Staff-level agentic AI, forward-deployed engineering and AI FinOps conversations, each
tied to a file and a number from a real run.

## The one-minute version

"Vendors of AI SOC products publish one number from data they chose. I built a vendor-neutral assurance
layer that drives any AI SOC through an adapter, scores it against ground truth it cannot see, injects
twelve failure modes, checks every data flow against residency policy and enforces it with Azure Policy,
validates each agent like a model risk team would, replays its audit trail independently, and scores it
with caps from its own failures. My own AI SOC scored under half, and the reasons are specific."

## Agentic AI (Staff)

* **Decision rights per agent.** Triage closes, investigation informs, response contains; each is
  validated separately with different criteria ([model-risk](model-risk/README.md)).
* **Code owns the verdict.** With guardrails off, the gullible model obeyed injected text in its
  summaries and the validator rejected every one of them; no attack was auto-closed, because the model
  never decides the verdict (FM-01).
* **Learning is an attack surface and a liability.** The feedback loop saves about 740 analyst minutes
  per 100 incidents against the same agent without learning, and it is also why a public Empire launcher
  recording was auto-closed: the learned prior for encoded PowerShell came from benign admin scripts.
* **Human-in-the-loop is not a control by itself.** Rubber-stamp approvers let 6 wrong containments
  through per run (FM-11), mostly before the system had learned the tenant.

## Forward-deployed engineering

* **Adapters and exports.** A customer can be assessed with zero integration by exporting decisions as
  JSONL; deeper integration adds fault injection.
* **Residency is a deployment question.** The SUT cannot be placed in Canada as written, and its model
  deployment type is unpinned. The fix is in configuration and policy, not a rewrite.
* **Evidence a customer's auditor accepts.** HTML, Markdown and CSV reports from the audit replay, and
  docs whose numbers CI re-renders from real runs.

## AI FinOps

* **Cost per alert with an interval.** About eight cents per thousand alerts on the mock's token counts at
  illustrative prices; the method matters more than the number. Prices are inputs in configuration.
* **Analyst minutes are the real cost.** The AI SOC saves about 1,470 analyst minutes per 100 incidents
  against always-escalate; severity-rules saves more by closing attacks. Cost metrics without the
  dangerous-error count are misleading.
* **Data zone versus geography deployments.** Global types are cheapest and most available; residency can
  force Standard deployments with less capacity. The policy makes that trade explicit per customer.

## Questions to expect

| Question | Short answer | Where |
| --- | --- | --- |
| Why bootstrap by tenant-run? | incidents within a tenant are correlated; resampling incidents would understate uncertainty | `stats.py`, benchmark doc |
| Why not trust 100% on synthetic data? | it is the generator the SUT was built on; 2 of 9 on public recordings | `socassure otrf` |
| How do you know the adapter is faithful? | it reproduces the SUT's published holdout numbers exactly | `tests/test_adapters.py` |
| What would you fix first in the SUT? | approval fatigue controls, record model output in the audit, a degraded mode, residency-ready IaC | failure-modes and audit docs |
| How would you evaluate a real vendor? | decision export on your data, criteria fixed in advance, evidence-capped scorecard | [adopt-this.md](adopt-this.md) |
