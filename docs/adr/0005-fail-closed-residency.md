# 0005 Fail closed on residency

**Status:** Accepted

**Context.** A model deployment with no declared deployment type could be Global, which may process
prompts in any region. An unknown region could be anywhere.

**Decision.** The checker reports `unknown` for anything it cannot place and counts it as a failure. The
Terraform variable and the Bicep template refuse Global and Developer deployment types, so a parameter file
cannot weaken the policy. Policy effect defaults to `Deny`.

**Consequences.** The shipped SUT fails residency for every tenant on the model flow, which is correct:
nobody can say where its prompts would be processed.
