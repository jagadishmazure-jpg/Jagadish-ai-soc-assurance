# Security policy

## Scope

This repository contains offline assurance code, configuration, a small extract of public attack
recordings (OTRF Security-Datasets, MIT licence) and Azure Policy templates. It holds no credentials,
subscription or tenant identifiers, model keys or customer data, and its tests enforce that. The only GUID
outside `00000000-` mocks is a public COM class id inside the OTRF recordings, allow-listed by a test.

## Reporting a vulnerability

1. Open a private security advisory on GitHub (Security tab, "Report a vulnerability"). Include the file,
   the problem and how to reproduce it.
2. If that button is not shown, open an issue titled `Security contact request` with no technical details,
   and I will reply with a private channel.

I aim to acknowledge a report within 5 working days. This is a personal portfolio maintained by one person,
so there is no formal SLA or bug bounty.

## Design choices that matter for security

- **Read-only assurance.** The harness never changes the system under test's code; faults are patches
  scoped to one run, and the SUT's containment executor is dry-run only.
- **No secrets anywhere.** The gated deploy workflow logs in to Azure with OIDC federated credentials; no
  client secret exists.
- **Residency enforced as policy.** The Terraform variable and the Bicep template refuse Global model
  deployment types; the initiative defaults to `Deny`.
- **Third-party data is pinned and hashed.** The OTRF extract records the source commit and a SHA-256 per
  archive; the vendoring script verifies before writing.
- **Copyrighted material is never committed.** The vendor whitepaper that motivated this repository is
  credited by link only; `*.pdf` is ignored and a test checks no PDF is tracked.
- **Supply chain:** SHA-pinned actions, Dependabot (pip, GitHub Actions, Terraform), CodeQL for Python and
  workflows, gitleaks over full history, an SPDX SBOM, pinned Python dependencies, checkov (no skips) and
  tflint on Terraform.
- **Deployment gated off** until `DEPLOY_ENABLED` is set; each tenant's environment needs reviewers.

See [docs/threat-model.md](docs/threat-model.md).

## Supported versions

Only the `main` branch is maintained.
