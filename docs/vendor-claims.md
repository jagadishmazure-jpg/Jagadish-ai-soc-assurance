# Judging a vendor's claims

A headline such as "87% of alerts resolved autonomously" is one number. Before it can inform a decision
it needs a definition, a denominator, an interval, a baseline and the count of the dangerous error. This
page turns that into a procedure, with the commands that help.

## 1. Put an interval on it

<!-- output: claim --k 87 --n 100 --claimed 87 -->
```text
claimed 87%; observed 87/100 = 87.0% (95% Wilson interval 79.0-92.2%): consistent with the observation
items needed for a +/-10 point margin at 87%: 44
items needed for a +/-5 point margin at 87%: 174
items needed for a +/-2 point margin at 87%: 1087
ask the vendor:
  - definition: What exactly is counted: alerts, incidents, verdicts, or analyst agreement? Which classes?
  - denominator: How many items, over what period, from how many customers? Was any data excluded?
  - ground truth: Who labelled the truth, independently of the system, and how were disagreements settled?
  - selection: Who chose the data? Was it from customers who agreed to a case study?
  - baseline: Compared with what: the same team without the product, a rules baseline, or nothing?
  - errors: How many attacks were auto-closed or missed? Accuracy alone hides the dangerous error.
  - interval: What is the confidence interval, and how was it computed?
  - reproduction: Can we run the same measurement on our data during a POC, with exportable decisions?
  - drift: How is the figure monitored after go-live, and what happens when it drops?
```
<!-- /output -->

If the vendor cannot give the denominator, the claim cannot be checked. If they can, the Wilson interval
shows how much the number could move by chance alone. A two-point margin needs over a thousand items.

## 2. Ask for the dangerous error, not only accuracy

Accuracy and "alerts handled" hide the error that matters: attacks closed without a human. In this
repository's benchmark the severity-rules baseline saves more analyst time than the AI SOC, and closes
one attack in five. Ask for attacks auto-closed, with its denominator, alongside any automation rate.

## 3. Ask what it was compared with

"Reduced triage time by X" means nothing without a baseline. Two baselines anyone can run are in
`src/socassure/adapters/baselines.py`: escalate everything, and auto-close everything that is not High
severity. If a product does not beat both on your data with an interval that excludes zero, the claim
does not transfer.

## 4. Run it on data the vendor did not choose

The system under test here is near-perfect on its own generator's data and detects 2 of 9 public attack
recordings. A POC on the vendor's demo tenant measures the demo. Use the recorded adapter: export the
product's incident decisions from your own tenant for a period and score them against your analysts'
labels (`src/socassure/adapters/recorded.py` documents the format).

## 5. The questions

<!-- output: claim --k 0 --n 0 --claimed 87 -->
```text
claimed 87%; observed 0/0: no data: the claim cannot be checked
items needed for a +/-10 point margin at 87%: 44
items needed for a +/-5 point margin at 87%: 174
items needed for a +/-2 point margin at 87%: 1087
ask the vendor:
  - definition: What exactly is counted: alerts, incidents, verdicts, or analyst agreement? Which classes?
  - denominator: How many items, over what period, from how many customers? Was any data excluded?
  - ground truth: Who labelled the truth, independently of the system, and how were disagreements settled?
  - selection: Who chose the data? Was it from customers who agreed to a case study?
  - baseline: Compared with what: the same team without the product, a rules baseline, or nothing?
  - errors: How many attacks were auto-closed or missed? Accuracy alone hides the dangerous error.
  - interval: What is the confidence interval, and how was it computed?
  - reproduction: Can we run the same measurement on our data during a POC, with exportable decisions?
  - drift: How is the figure monitored after go-live, and what happens when it drops?
```
<!-- /output -->

## 6. Record the answer in the scorecard

A claim with no evidence scores at most 1 on the evidence ladder in
[components/product-scorecard.md](components/product-scorecard.md); documentation 2; a demonstration 3;
your own measurement with an interval 4 or 5.
