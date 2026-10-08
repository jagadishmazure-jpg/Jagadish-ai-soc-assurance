# scripts

Helper scripts.

| File | What it does |
| --- | --- |
| `fetch_sut.sh` | clone the system under test at the pinned commit and install it |
| `vendor_otrf.py` | download the OTRF archives, verify hashes, write the extract (`--check` verifies only) |
| `render_docs.py` | fill `<!-- output -->` and `<!-- code -->` blocks from real runs; `--check` fails on drift |
| `overlap_check.py` | report any eight-word run shared with reference documents (used before publishing) |
