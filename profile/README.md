# ipso

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ipsofacto-io/ipso/badge)](https://scorecard.dev/viewer/?uri=github.com/ipsofacto-io/ipso)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15758/badge)](https://www.bestpractices.dev/en/projects/15758)

**A registry of binding engineering decisions, enforced on pull requests, in CI, on infrastructure plans, and before AI coding agents edit code.**

> Status: pre-alpha. The open EDR 1.1 specification, CLI, GitHub Action, agent plugins, examples, and source-available control plane are actively developed ahead of the 1.0 release.

## Why ipso

Architecture and infrastructure decisions usually end up buried in ADRs, pull request threads, and chat logs. Nothing enforces them, and nobody can prove which rules were in force when a change shipped.

AI coding agents now write a growing share of production changes, yet rules files only guide them probabilistically. ipso closes that gap by turning binding decisions into deterministic, auditable checks.

## How it works

1. **Record decisions as code:** Write explicit, owned, scoped, and time-bounded Engineering Decision Records (EDRs) in Markdown.
2. **Compile into checks you already run:** Compile EDR checks for OPA/Conftest, Semgrep, dependency-cruiser, ArchUnit, import-linter, ESLint, Checkov, Kyverno, Gatekeeper, and security scanners.
3. **Enforce everywhere:** Run checks on pull requests, in CI, on `terraform plan` (plus Pulumi, CloudFormation, CDK, and Bicep), and locally before an AI coding agent writes to a file.
4. **Keep humans in charge:** LLMs can propose decisions and draft checks, humans approve them, and only deterministic checks block changes.

## Repositories

| Repository | Description | License |
| --- | --- | --- |
| [edr-spec](https://github.com/ipsofacto-io/edr-spec) | Open specification, JSON Schema, and conformance suite for the Engineering Decision Record (EDR) format | CC-BY-4.0 / Apache-2.0 |
| [ipso](https://github.com/ipsofacto-io/ipso) | CLI, check compilers, AI agent hooks, rules generator, and local MCP server | Apache-2.0 |
| [ipso-action](https://github.com/ipsofacto-io/ipso-action) | GitHub Action that runs ipso checks in CI and uploads SARIF and evidence | Apache-2.0 |
| [agent-plugins](https://github.com/ipsofacto-io/agent-plugins) | Plugins and hook configs for Claude Code, Codex, Copilot, Cursor, and Kiro | Apache-2.0 |
| [examples](https://github.com/ipsofacto-io/examples) | End-to-end sample repositories across Terraform, Atlantis, Kubernetes, IaC tools, and CI platforms | Apache-2.0 |
| [ipso-server](https://github.com/ipsofacto-io/ipso-server) | Source-available control plane with bitemporal registry, API, web app, and remote MCP | FSL-1.1-ALv2 |
| [terraform-provider-ipso](https://github.com/ipsofacto-io/terraform-provider-ipso) | Terraform and OpenTofu provider for managing decisions, scopes, and waivers as code | MPL-2.0 |

## Get involved

- **Questions and ideas:** [GitHub Discussions](https://github.com/ipsofacto-io/ipso/discussions)
- **Contributing:** [CONTRIBUTING.md](https://github.com/ipsofacto-io/.github/blob/main/CONTRIBUTING.md)
- **Security reports:** [SECURITY.md](https://github.com/ipsofacto-io/.github/blob/main/SECURITY.md)
