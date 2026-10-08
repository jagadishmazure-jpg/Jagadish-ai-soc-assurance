"""Template adapter for a commercial AI SOC product. Deliberately not implemented.

To benchmark a product on your own data, implement `run` in four steps and keep everything else in the
harness unchanged:

1. Replay: write each tenant's tables from the scenario into a test workspace the product reads (for a
   Microsoft Sentinel-based product, the Logs Ingestion API into custom tables, or a dedicated test
   workspace per tenant). Never replay into production.
2. Wait and collect: poll the product's incident API until it has processed the replay window, and map
   each of its incidents to the scenario's event ids (via entity and time matching if it does not keep ids).
3. Humans: route the product's review and approval requests to `oracle.answer(...)`, or run the
   benchmark in "observe only" mode and score the product's automatic dispositions alone.
4. Return a `SutResult` whose `Decision`s carry the product's own verdict, confidence (if exposed),
   disposition, timestamps and token or credit usage (if exposed). Leave unknown fields at their
   defaults and say so in `SutResult.notes`.

If the product only exports results, use the `recorded` adapter instead: it scores a JSONL export."""

from __future__ import annotations

from socassure.model import Scenario, SutResult
from socassure.oracle import Oracle


class ThirdPartyStub:
    name = "third-party"
    description = "template for a commercial product (not implemented; see module docstring)"
    supported_faults: frozenset[str] = frozenset()

    def __init__(self, product: str = "your-product") -> None:
        self.product = product

    def run(self, scenario: Scenario, oracle: Oracle, faults: frozenset[str] = frozenset()) -> SutResult:
        raise NotImplementedError(
            f"{self.product}: replay the scenario into a test workspace, collect the product's incidents and map them to "
            "Decision records (steps in socassure/adapters/third_party.py). No product is benchmarked by this repository."
        )
