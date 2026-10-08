# Threat model

Two systems are in scope: the AI SOC being assured, and the assurance layer itself. The first is covered
by the failure-mode catalogue; this page lists the threats in STRIDE terms and where each is tested, then
the threats to the assurance results.

## Threats to the AI SOC (tested here)

| STRIDE | Threat | Test | Result |
| --- | --- | --- | --- |
| Spoofing | an agent or another tenant's user approves containment | FM-06 probes | refused |
| Tampering | attacker text in alerts steers the model (prompt injection) | FM-01 | safe: verdict owned by code |
| Tampering | poisoned analyst labels in the learning window | FM-02 | safe on these scenarios |
| Tampering | audit records edited, removed, re-ordered, relabelled | FM-12 | detected, except tail truncation |
| Repudiation | no record of what the model told the analyst | audit rule AUD-09 | gap on every escalated incident |
| Information disclosure | one customer's data in another's prompts or records | FM-09 canary | not found |
| Information disclosure | processing outside the customer's country | residency checks | shipped layout fails for the Canadian tenant |
| Denial of service | alert flood, model or tool outage | FM-07, FM-04, FM-05 | no attack closed; no degraded mode |
| Elevation of privilege | rubber-stamped containment on benign incidents | FM-11 | **finding** |
| Elevation of privilege | containment outside the catalogue, live mode, break-glass | FM-06 probes | refused |

## Threats to the assurance results

| Threat | Effect | Mitigation |
| --- | --- | --- |
| Adapter does not behave like the SUT | every number wrong | fidelity test reproduces the SUT's published numbers |
| Ground truth leaks to the SUT | inflated results | labels never passed to adapters; only the oracle reads them |
| Cherry-picked seeds | inflated results | seeds fixed in configuration; SUT development seed excluded |
| Numbers edited by hand in docs | false claims | rendered from the CLI; CI fails on drift |
| Expected findings silently "fixed" | lost findings | gate fails if FMEA observation and expectation differ |
| Third-party data licence or integrity | legal or data error | OTRF pinned to a commit, hashed, licence shipped |
| Supply chain of the harness | compromised results | SHA-pinned actions, Dependabot, CodeQL, gitleaks, SBOM |
| Vendor whitepaper text copied | copyright | not committed, credited by link only; overlap check before publishing |
