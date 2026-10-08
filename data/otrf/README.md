# otrf

Process-creation events from nine OTRF Security-Datasets recordings, replayed into the scenario tenants as independent attack data. Pinned to a commit and hashed; rebuild with `python scripts/vendor_otrf.py`.

| File | What it does |
| --- | --- |
| `LICENSE-OTRF` | the MIT licence of the source project |
| `datasets.yaml` | source, commit, and per dataset: id, technique, archive path, sha256, expected SUT rule |
| `process-events.jsonl` | the extracted Sysmon event 1 rows (image, parent, command line, hash) |
