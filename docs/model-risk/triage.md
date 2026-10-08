# Triage agent: model card, risk card, validation report

System under test: azure-ai-soc, pinned in `config/sut.yaml`. Framework alignment: NIST AI RMF, EU AI Act,
ISO/IEC 42001 and SR 11-7, mapped in [framework-mapping.md](framework-mapping.md); the general method is in
[Jagadish-agentic-ai-model-risk](https://github.com/jagadishmazure-jpg/Jagadish-agentic-ai-model-risk).

## Model card

| Field | Value |
| --- | --- |
| Purpose | Score each incident's probability of being malicious; choose tier 1 (auto-close candidate), 2 or 3 |
| Model type | Deterministic logistic score: rule priors, threat-intel match, behaviour analytics, tactic count, severity, injection flag, tenant context, case notes; per-detector priors and thresholds learned from analyst reviews |
| Decision rights | May close a non-malicious incident above a learned confidence threshold; may never close a malicious verdict |
| Risk tier | High (acts without a human) |
| Training data | The tenant's own reviewed incidents in the first 14 days; frozen for the holdout window |
| Intended use | Reduce analyst load on repetitive benign alerts in a managed SOC with per-customer tuning |
| Out of scope | Detection (it scores what rules raise); attack types without a rule or product alert; tenants with no review history |
| Owner (proposed) | SOC lead; second-line validation by model risk |

## Risk card

| Risk | Who is harmed | Likelihood signal | Control | Evidence |
| --- | --- | --- | --- | --- |
| Attack auto-closed | the customer (dwell time) | attacks auto-closed rate | code never closes a malicious verdict; QA sample | synthetic 0; **OTRF 1 of 2 detected** |
| Overfitting to the generator | the customer | out-of-sample recall | independent data in validation | **OTRF detection 2 of 9** |
| Poisoned learning | the customer | label flips on attack detectors | replay gate on threshold promotion | FM-02 safe |
| Drift | analysts (noise), customer (misses) | PSI over 0.25 | monitor and re-validation | FM-03, PSI 6.4 on the drifted set |
| Over-trust in calibration | analysts | ECE | calibration reported per run | ECE under 2% on synthetic |

## Validation report

Criteria are judged on the conservative end of the 95% interval.

<!-- output: validate --agent triage -->
```text
criteria judged on the conservative end of the 95% interval (lower bound for >=, upper bound for <=)
agent   criterion            suite      estimate [95% CI]     threshold  bound used  result
------  -------------------  ---------  --------------------  ---------  ----------  ------
triage  malicious_recall     synthetic  100.0 [100.0, 100.0]  >= 95      100.0       pass
triage  attacks_auto_closed  synthetic  0.0 [0.0, 0.0]        <= 1       0.0         pass
triage  binary_accuracy      synthetic  100.0 [100.0, 100.0]  >= 90      100.0       pass
triage  ece                  synthetic  1.8 [1.8, 1.9]        <= 10      1.9         pass
triage  detection_recall     otrf       22.2 [6.3, 54.7]      >= 50      6.3         FAIL
triage  attacks_auto_closed  otrf       50.0 [9.5, 90.5]      <= 1       90.5        FAIL
```
<!-- /output -->

**Conclusion.** The agent meets every criterion on the generator's own scenarios and fails both criteria
on public attack recordings it did not choose. It is **not validated for production use** under these
criteria. Before re-validation: add detections for the missed techniques (the agent can only triage what
is detected), fix the cause of the Empire launcher auto-close (the audit replay shows the score was the learned
encoded-PowerShell prior alone, 0.225, learned down from benign administration scripts in the training
window, with no other signal firing), and repeat with more recordings so the interval narrows.

Monitoring after any approval: PSI per tenant per week (watch 0.10, drift 0.25), override rate, QA
disagreement, and the attacks-auto-closed count from QA samples.
