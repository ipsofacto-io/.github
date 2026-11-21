# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability reporting: open the **Security** tab of the affected repository and choose **Report a vulnerability**, or go to `https://github.com/ipsofacto-io/<repository>/security/advisories/new`. If you are unsure which repository is affected, report it in [ipso](https://github.com/ipsofacto-io/ipso/security/advisories/new).

Do not open public issues, discussions or pull requests for security problems.

Where you can, include the affected repository and version or commit, a description of the issue and its impact, steps to reproduce or a proof of concept, and any known mitigation.

## What to expect

- We acknowledge reports within 5 business days.
- We keep you informed while we investigate and fix the issue, agree on a disclosure date with you, and credit you in the advisory unless you prefer otherwise.
- Fixes are published as GitHub security advisories, with a CVE where applicable.

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

Each CLI release from v0.2.0 also publishes machine-readable CycloneDX JSON SBOMs produced by Syft. On the GitHub Release, `ipso_<version>_sbom.cdx.json` is the module SBOM and `ipso_<version>_image.cdx.json` is the image SBOM. v0.1.1 publishes `ergo_0.1.1_sbom.cdx.json` and `ergo_0.1.1_image.cdx.json`. The air-gapped server bundle `ipso-airgap.tar` carries a CycloneDX SBOM for each image and a CycloneDX attestation. Verify that tar offline as described in `docs/install.md` of [ipso-server](https://github.com/ipsofacto-io/ipso-server).

The signed EU declaration of conformity and the software CE marking will be published on the public site, at the path `compliance/eu-doc`, when a commercial release is placed on the market. Until that publication, these repositories do not claim conformity and do not show a CE mark.
