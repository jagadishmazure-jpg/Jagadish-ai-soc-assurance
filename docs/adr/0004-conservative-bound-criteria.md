# 0004 Criteria judged on the conservative bound

**Status:** Accepted

**Context.** A point estimate from a small sample can clear a threshold by luck.

**Decision.** Each acceptance criterion is judged on the lower bound of its 95% interval for "at least"
criteria and the upper bound for "at most" criteria.

**Consequences.** Small evidence fails strict criteria: nine OTRF recordings cannot pass a 50% recall bar
unless nearly all are detected. That is intended; more data, not a lower bar, is the fix.
