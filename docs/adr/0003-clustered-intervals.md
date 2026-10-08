# 0003 Clustered intervals

**Status:** Accepted

**Context.** Incidents in one tenant of one run share learned state and attack stories; they are not
independent. Resampling incidents would give intervals that are too narrow.

**Decision.** Resample tenant-runs (30 for ten seeds and three tenants) with 2000 draws and a fixed seed.
Compare systems with paired differences on the same draws. Use Wilson intervals where there are too few
units to bootstrap (nine OTRF recordings).

**Consequences.** Intervals are honest but sometimes degenerate (for example 0.0 [0.0, 0.0]) when no unit
has an event; counts are always printed beside rates so a reader sees the denominator.
