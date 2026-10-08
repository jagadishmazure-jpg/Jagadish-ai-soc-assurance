# Framework mapping

How the model-risk practices in this repository line up with four frameworks. Each entry is a paraphrase
in this repository's own words of what the framework expects, followed by where this repository does it.
This is engineering mapping, not legal advice; whether a given AI SOC falls in scope of any regulation is
for the adopter's counsel. The broader mapping, with machine-readable controls, is in
[Jagadish-agentic-ai-model-risk](https://github.com/jagadishmazure-jpg/Jagadish-agentic-ai-model-risk).

## NIST AI RMF

Reference: [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework).

| Function | What it asks for (paraphrased) | Here |
| --- | --- | --- |
| Govern | accountable roles, policies and an inventory of AI systems | `config/model-risk.yaml` inventory with decision rights and tiers; gate in CI |
| Map | understand context, intended use and impacts before measuring | model cards (purpose, decision rights, out-of-scope uses) |
| Measure | test with appropriate methods, track trustworthiness characteristics | benchmark with intervals, OTRF, fault experiments |
| Manage | prioritise and treat risks, monitor after deployment | FMEA ranking, drift monitor, challenger, findings in risk cards |

## EU AI Act

Reference: [the EU regulation on artificial intelligence on EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689).
This repository does not decide whether an AI SOC is a high-risk system under the Act. The practices below
are the themes the Act sets for high-risk systems, which are good practice either way.

| Theme (paraphrased) | Here |
| --- | --- |
| risk management across the lifecycle | FMEA with experiments; risk cards |
| data and data governance | scenario provenance, OTRF licence and hashes, seeds recorded |
| technical documentation | model cards and component docs with real output |
| record-keeping (logs) | hash-chained audit and the independent replay |
| transparency to those who deploy it | limitations sections; scorecard caps |
| human oversight | digest-bound approvals; FM-11 tests whether oversight is real |
| accuracy, robustness and cybersecurity | benchmark intervals, adversarial suites, injection and tampering experiments |

## ISO/IEC 42001

Reference: [ISO/IEC 42001 AI management systems](https://www.iso.org/standard/81230.html).

| Theme (paraphrased) | Here |
| --- | --- |
| AI risk assessment and treatment | FMEA, RPN ranking, mitigations |
| AI system impact assessment | risk cards per agent (who is affected when it is wrong) |
| lifecycle and change management | pinned SUT commit, re-rendered reports, gate |
| monitoring and measurement | drift monitor, validation criteria |
| internal audit | decision-audit replay with rules and an auditor report |

## SR 11-7

Reference: [SR 11-7 Supervisory Guidance on Model Risk Management](https://www.federalreserve.gov/boarddocs/srletters/2011/sr1107.htm)
(Federal Reserve). Written for banks; used here as a well-tested template for model validation.

| Element (paraphrased) | Here |
| --- | --- |
| sound development and documented limitations | model cards; limitations in every component |
| independent validation: conceptual soundness | validation reports reason about each agent's design |
| ongoing monitoring | drift monitor; override and QA rates |
| outcomes analysis | benchmark against ground truth; OTRF out-of-sample test |
| effective challenge | challenger comparison; rules baseline |
| governance: inventory, roles, policies | inventory with owners and tiers; gate |
