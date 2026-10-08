# adapters

Adapters: the only code that knows how a particular system works.

| File | What it does |
| --- | --- |
| `__init__.py` | adapter registry (`get(name)`) |
| `base.py` | the adapter protocol and the fault catalogue |
| `azure_ai_soc.py` | the portfolio SUT: pipeline mirror, fault patches, containment probes, alert sources |
| `baselines.py` | always-escalate and severity-rules, on the SUT's own detections |
| `recorded.py` | score any product's exported decisions (JSONL); export from any run |
| `third_party.py` | stub documenting the contract for a vendor adapter |
