# Limitations

What this repository does not show, in one place.

* **Nothing is deployed.** The Azure Policy stacks are tested with mocked Terraform plans and `bicep build`;
  the deploy workflow is gated off. No subscription has these assignments.
* **One real system under test.** Only the portfolio azure-ai-soc has an adapter. It is itself an offline
  reference implementation with a deterministic mock model, so "real model" behaviour is not measured.
* **Synthetic data dominates.** Ten seeds of the SUT's own generator are new samples of the same design,
  not new attacker behaviour. The independent evidence is nine OTRF process-creation recordings, which is
  small (hence wide Wilson intervals) and covers one table.
* **Simulated people.** Review minutes, approval latency and analyst verdicts come from the oracle.
  Analyst minutes and time to respond are models, not measurements.
* **Judgement ratings.** FMEA severity, occurrence and detection, scorecard weights and model-risk
  thresholds are the author's proposals.
* **Residency is modelled, not observed.** The checker trusts the deployment description; region lists
  are a subset; Microsoft service behaviour is linked and some points are marked unverified.
* **Real products are not scored.** Their rows are templates with public links; nothing about them is
  measured or asserted.
* **Prices are illustrative.** Token prices in `config/benchmark.yaml` are inputs for cost per alert, not
  quotes.
