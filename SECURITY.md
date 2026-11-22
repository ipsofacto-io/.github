# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability reporting: open the **Security** tab of the affected repository and choose **Report a vulnerability**, or go to `https://github.com/ipsofacto-io/<repository>/security/advisories/new`. If you are unsure which repository is affected, or the affected repository is private (for example `ipso-ee`), report it in [ipso](https://github.com/ipsofacto-io/ipso/security/advisories/new).

Do not open public issues, discussions or pull requests for security problems.

Where you can, include the affected repository and version or commit, a description of the issue and its impact, steps to reproduce or a proof of concept, and any known mitigation.

Reports stay private to the maintainers. We do not copy a reporter's name or email address into public pages, issue trackers or regulator filings. GitHub builds the draft advisory from your report, so before publication we rewrite it to carry the impact and the fix, and not your proof of concept or personal details, unless you agree otherwise.

## What to expect

- We acknowledge reports within 5 business days.
- We keep you informed while we investigate and fix the issue.
- We agree a disclosure date with you, as described below.
- Fixes are published as GitHub security advisories, with a CVE where applicable.
- We credit you in the advisory through GitHub's credits field if you accept the credit. Without your acceptance we do not name you.

## Coordinated vulnerability disclosure

This is our coordinated vulnerability disclosure (CVD) policy. The disclosure window is 90 days, counted from the day we receive the report.

- **Fix first.** We aim to ship a fix and publish the advisory before day 90. The advisory is published when the fix is released.
- **Day 90.** If no fix has shipped by day 90, we publish the advisory with the mitigations we know, unless we agreed a later date with you in the private advisory. We agree a later date only while a fix is in progress.
- **Your side.** Keep the details private until the advisory is published or the disclosure date passes. The disclosure date is day 90, or the later date we agreed with you.
- **Actively exploited issues.** If an issue is being exploited in the wild, either side may publish earlier after telling the other.
- **Third-party components.** When the flaw is in a component we use, we also report it to the maintainers of that component, and we may agree a different date with them.
- **What we publish.** The advisory names the repository, the affected version, the impact and the update. It does not name you unless you accepted credit.
- **No bug bounty.** We do not pay for reports yet.

## Testing in good faith

We do not run a hosted service for this software, so test only against copies you run yourself. Do not access, change or keep data that is not yours. Do not degrade the services of third parties, such as GitHub or package registries, and do not use social engineering or physical attacks against people. If you reach data that is not yours, stop and report what you did. We will not take legal action against research that follows this policy.

## Machine-readable contact

The same contact is published as an RFC 9116 [security.txt](https://github.com/ipsofacto-io/.github/blob/main/.well-known/security.txt) in `ipsofacto-io/.github`. It is served at `https://ipsoplatform.io/.well-known/security.txt` once the site is live. Until then that file is the source. The file is not signed. Rely on the HTTPS address and the `Canonical` field.

## Support period and security updates

Pre-GA releases (`0.x`, and source-available builds that have no release tag) are supported on a best-effort basis, on the latest minor release of each product that publishes a GitHub Release. Today that is `ipso`. The repositories `ipso-server` and `ipso-ee` (the enterprise server in that repository is `ipso-server-ee`, and the agent is `ipso-agent`) join this rule when they publish a release. A repository with no GitHub Release is not a supported product line under this paragraph. The reporting rules above still apply to every repository. These builds are supplied free of charge and are not placed on the market in the course of a commercial activity (Regulation (EU) 2024/2847, Article 3(22) and Recital 18). No EU declaration of conformity and no CE marking is claimed for them.

From commercial general availability (`1.0.0`), each designated major or long-term support line of in-scope ipso software has a 5-year (60-month) security support period, counted from the day that line is first placed on the EU market. In-scope software is the `ipso` CLI, compilers, local MCP server, hooks, plugins, and OCI policy bundles, the CI and portal wrappers, the `ipso-server` Helm chart, Compose bundle, and air-gapped bundle, the enterprise server `ipso-server-ee` in the `ipso-ee` repository, and `ipso-agent`. The end of each period is a month and a year (`YYYY-MM`). That date is published in this file, and on the public site once its domain is live, and it is shown before purchase. Security fixes for a line ship on the latest minor release of that line for the whole 60 months. A later minor release replaces the earlier ones. An N-2 upgrade test in CI is not a promise to keep three minor releases in support at once. Security updates are free of charge, are separable from feature updates where that is technically feasible, are published with a GitHub security advisory and a CycloneDX SBOM, and are kept with the technical file for at least 10 years, or for the support period if that is longer. `ipso-server-ee` and `ipso-agent` have no public release yet. Their SBOMs will be on the private release at the first general-availability tag, not on a public URL before that.

ipso binaries, hooks, plugins, container images, and the BYOC agent do not install updates by themselves over the network. An unpinned self-update would break reproducible CI, air-gapped installs, and workloads pinned by digest. An operator installs an update by bumping a pinned version or an `@sha256:` digest, or by following a GitHub security advisory. There is no default that installs updates automatically, so there is no switch that turns that default off (Annex II, point 8(e), of Regulation (EU) 2024/2847).

## Verifying releases and accessing SBOMs

From v0.2.0 onward, CLI releases are signed by `ipsofacto-io/.github`. Download the archive and `checksums.txt` from the GitHub Release, then run the commands below. A `.zip` archive uses the same flags as the `.tar.gz`.

```sh
gh attestation verify ipso_<version>_<os>_<arch>.tar.gz \
  --repo ipsofacto-io/ipso \
  --signer-workflow ipsofacto-io/.github/.github/workflows/release-cli.yml \
  --source-ref refs/tags/v<version>
gh attestation verify checksums.txt \
  --repo ipsofacto-io/ipso \
  --signer-workflow ipsofacto-io/.github/.github/workflows/release-cli.yml \
  --source-ref refs/tags/v<version>
gh attestation verify "oci://ghcr.io/ipsofacto-io/ipso@sha256:<digest>" \
  --repo ipsofacto-io/ipso \
  --signer-workflow ipsofacto-io/.github/.github/workflows/release-cli.yml \
  --source-ref refs/tags/v<version>
gh attestation verify "oci://ghcr.io/ipsofacto-io/ipso@sha256:<digest>" \
  --repo ipsofacto-io/ipso \
  --signer-workflow ipsofacto-io/.github/.github/workflows/release-cli.yml \
  --source-ref refs/tags/v<version> \
  --predicate-type https://cyclonedx.org/bom
```

The same releases also verify with cosign. Pulling the image requires access to `ghcr.io/ipsofacto-io/ipso`.

```sh
cosign verify \
  --certificate-identity-regexp '^https://github.com/ipsofacto-io/\.github/\.github/workflows/release-cli\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ghcr.io/ipsofacto-io/ipso@sha256:<digest>"
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ipsofacto-io/\.github/\.github/workflows/release-cli\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

v0.1.1 is the first CLI release built by that isolated workflow. Its assets on the GitHub Release still use the previous file prefix (`ergo_0.1.1_*`). Verify `checksums.txt` with the bundle on that release. Do not reuse the v0.2.0 signer workflow or the regexp above.

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ergoprobat/\.github/\.github/workflows/release-cli\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

`gh attestation verify` of those v0.1.1 assets against `ipsofacto-io/ipso` does not find a provenance attestation. The image named in `ergo_0.1.1_image.cdx.json` is `ghcr.io/ergoprobat/ergo`. Pulling it is not a public command. The previous organization stays empty so nobody else can mint that identity. v0.1.0 is signed with cosign and has a CycloneDX SBOM. It is not SLSA Build Level 3, because it was built before this workflow.

Every CLI release publishes CycloneDX JSON SBOMs from Syft: v0.1.1 uses `ergo_0.1.1_sbom.cdx.json` and `ergo_0.1.1_image.cdx.json`, and from v0.2.0 the names are `ipso_<version>_sbom.cdx.json` and `ipso_<version>_image.cdx.json`. The air-gapped server bundle `ipso-airgap.tar` carries a CycloneDX SBOM for each image and a CycloneDX attestation. Verify that tar offline as described in `docs/install.md` of [ipso-server](https://github.com/ipsofacto-io/ipso-server).

The signed EU declaration of conformity and the software CE marking will be published on the public site, at the path `compliance/eu-doc`, when a commercial release is placed on the market. Until that publication, these repositories do not claim conformity and do not show a CE mark.
