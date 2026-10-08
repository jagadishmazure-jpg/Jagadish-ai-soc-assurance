# 0002 The oracle owns ground truth

**Status:** Accepted

**Context.** An AI SOC asks humans questions (review, approval, QA) and learns from the answers. If the
answers came from the SUT's own simulation, analyst behaviour would be part of the system being measured.

**Decision.** Labels stay in the harness. A simulated analyst (the oracle) answers every human question
from ground truth, with an explicit behaviour: honest, rubber-stamp or poisoned. Adapters receive answers,
never labels.

**Consequences.** Analyst behaviour becomes a controlled variable, which is what makes FM-02 (poisoning)
and FM-11 (approval fatigue) testable. Review minutes are configured, so time metrics are simulations.
