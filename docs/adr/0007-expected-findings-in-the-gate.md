# 0007 Expected findings in the gate

**Status:** Accepted

**Context.** A gate that only checks "all safe" would either fail forever on a known finding or tempt
someone to weaken the experiment.

**Decision.** `config/failure-modes.yaml` records the expected outcome of each experiment, including
findings. The gate fails when an observation differs from its expectation in either direction.

**Consequences.** A fixed finding forces a reviewed update to the FMEA; a regression cannot hide; known
findings stay documented.
