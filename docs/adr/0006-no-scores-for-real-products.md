# 0006 No scores for real products

**Status:** Accepted

**Context.** A comparison table with numbers for named vendors invites invented or second-hand scores.

**Decision.** Real products appear in `config/scorecard/products/` with a general description, a link to
their public documentation and every score empty, marked "to be filled from your own POC". A test and the
gate fail if any real product file contains a score.

**Consequences.** The scorecard is a method plus one honest worked example, not a ranking.
