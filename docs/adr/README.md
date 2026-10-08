# Architecture decision records

| File | What it does |
| --- | --- |
| `0001-adapter-boundary.md` | systems are driven only through an adapter; the harness never imports a vendor's internals elsewhere |
| `0002-oracle-owns-ground-truth.md` | labels stay in the harness; humans are simulated by an oracle with explicit behaviours |
| `0003-clustered-intervals.md` | tenant-run cluster bootstrap and paired differences; Wilson for small counts |
| `0004-conservative-bound-criteria.md` | acceptance criteria are judged on the conservative end of the interval |
| `0005-fail-closed-residency.md` | unknown processing location is a failure; policy refuses Global deployment types |
| `0006-no-scores-for-real-products.md` | real products are listed with public links and never scored by this repository |
| `0007-expected-findings-in-the-gate.md` | the gate checks observations against documented expectations in both directions |
