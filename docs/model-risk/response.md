# Response agent: model card, risk card, validation report

System under test: azure-ai-soc, pinned in `config/sut.yaml`. Framework alignment: NIST AI RMF, EU AI Act,
ISO/IEC 42001 and SR 11-7, mapped in [framework-mapping.md](framework-mapping.md); the general method is in
[Jagadish-agentic-ai-model-risk](https://github.com/jagadishmazure-jpg/Jagadish-agentic-ai-model-risk).

## Model card

| Field | Value |
| --- | --- |
| Purpose | Propose containment from a fixed catalogue (disable account, revoke sessions, isolate host, block indicator) for malicious incidents |
| Model type | Rule-based planner and policy checks; no language model in the decision |
| Decision rights | Proposes; named customer approvers approve a plan digest within a time-to-live; high-impact actions need two approvers; the executor records requests only (dry-run) |
| Risk tier | High (acts on customer identities and hosts once approved) |
| Out of scope | Live execution (not implemented); actions outside the catalogue; break-glass accounts |
| Owner (proposed) | SOC lead with the customer's security owner; second-line validation by model risk |

## Risk card

| Risk | Who is harmed | Likelihood signal | Control | Evidence |
| --- | --- | --- | --- | --- |
| Wrong containment with careful approvers | customer users | executions on non-attacks | malicious verdict required; human approval | 0 on synthetic runs |
| **Wrong containment with rubber-stamp approvers** | customer users | approval rate and latency per approver | none effective in the SUT today | **FM-11 finding: 6 to 8 per run** |
| Cross-tenant or break-glass action | another customer | probe failures | tenant and catalogue checks | 11 of 11 probes as expected |
| Stale or altered plan executed | customer | digest mismatch | digest-bound approvals | probe "plan changed after approval" refused |
| Attack not contained | customer | stories contained | plan for every malicious verdict | 100% [95.9, 100] synthetic stories contained (dry-run) |

## Validation report

<!-- output: validate --agent response -->
```text
criteria judged on the conservative end of the 95% interval (lower bound for >=, upper bound for <=)
agent     criterion                  suite      estimate [95% CI]    threshold  bound used  result
--------  -------------------------  ---------  -------------------  ---------  ----------  ------
response  wrong_containment          synthetic  0.0 [0.0, 0.0]       <= 0       0.0         pass
response  containment_probes_failed  synthetic  0.0 [0.0, 0.0]       <= 0       0.0         pass
response  attack_stories_contained   synthetic  100.0 [95.9, 100.0]  >= 90      95.9        pass
```
<!-- /output -->

**Conclusion.** Every criterion passes with honest approvers, and every unsafe containment attempt is
refused. The validation is conditional on approvers reading what they approve: the approval-fatigue
experiment (FM-11) shows wrong containment going through when they do not, concentrated in the first two
weeks of a tenant. Required before production: show contradicting evidence in the approval request,
require a reason, sample approvals for QA, and raise the containment bar for tenants with little review
history. Live execution remains out of scope.
