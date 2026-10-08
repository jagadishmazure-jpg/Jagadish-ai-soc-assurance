# 0001 Adapter boundary

**Status:** Accepted

**Context.** The assurance layer must work for any AI SOC, but its first system under test is a Python
package it can import. Importing internals everywhere would tie every metric to one product.

**Decision.** Only modules under `src/socassure/adapters/` know how a system works. Everything else sees a
neutral `Scenario` in and a `SutResult` of `Decision`s and audit records out. Faults are declared per
adapter; an unsupported fault raises instead of being ignored.

**Consequences.** A second product needs one adapter or a decision export, nothing else. The azure-ai-soc
adapter mirrors the SUT's pipeline, so it must be proved faithful; a test reproduces the SUT's published
numbers.
