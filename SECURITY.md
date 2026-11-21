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

Pre-GA releases (`0.x`, and source-available builds that have no release tag) are supported on a best-effort basis, on the latest minor release published on that repository's GitHub Releases page. They are supplied free of charge and are not placed on the market in the course of a commercial activity (Regulation (EU) 2024/2847, Article 3(22) and Recital 18). No EU declaration of conformity and no CE marking is claimed for them.

From commercial general availability (`1.0.0`), each designated major or long-term support line of in-scope ipso software has a 5-year (60-month) security support period, counted from the day that line is first placed on the EU market. In-scope software is the `ipso` CLI, compilers, hooks, plugins, and CI or portal wrappers, the `ipso-server` Helm chart, Compose bundle, and air-gapped bundle, `ipso-server-ee`, and `ipso-agent`. The end of each period is a month and a year (`YYYY-MM`). That date is published in this file, and on `ipsoplatform.io` once that domain is live, and it is shown before purchase. Inside an active major line, minor releases follow an N-2 window and upgrade forward inside that line's 60-month window. Security updates are free of charge, are separable from feature updates where that is technically feasible, are published with a GitHub security advisory and a CycloneDX SBOM, and are kept with the technical file for at least 10 years, or for the support period if that is longer.

ipso binaries, hooks, plugins, container images, and the BYOC agent do not install updates by themselves over the network. An unpinned self-update would break reproducible CI, air-gapped installs, and workloads pinned by digest. An operator installs an update by bumping a pinned version or an `@sha256:` digest, or by following a GitHub security advisory. There is no default that installs updates automatically, so there is no switch that turns that default off (Annex II, point 8(e), of Regulation (EU) 2024/2847).

## Verifying releases and accessing SBOMs

From v0.2.0 onward, CLI releases are signed by `ipsofacto-io/.github`. Verify against:

- Signer workflow identity: `https://github.com/ipsofacto-io/.github/.github/workflows/release-cli.yml`
- Image: `ghcr.io/ipsofacto-io/ipso`

Releases up to v0.1.1 were published under a previous organization and product name. Their cosign signatures and attestations still use that previous signer identity. Read the identity from the release attestation itself (`gh attestation verify` / cosign) rather than from this file. The previous organization stays empty so nobody else can mint that identity. v0.1.0 is signed and has an SBOM. It is not SLSA Build Level 3, because it was built before this workflow.

Each CLI release from v0.2.0 also publishes machine-readable CycloneDX JSON SBOMs produced by Syft. On the GitHub Release, `ipso_<version>_sbom.cdx.json` is the module SBOM and `ipso_<version>_image.cdx.json` is the image SBOM. The air-gapped server bundle `ipso-airgap.tar` carries a CycloneDX SBOM for each image and a CycloneDX attestation. Verify that tar offline as described in `docs/install.md` of [ipso-server](https://github.com/ipsofacto-io/ipso-server).

The signed EU declaration of conformity and the software CE marking will be published at `https://ipsoplatform.io/compliance/eu-doc` when a commercial release is placed on the market. Until that publication, these repositories do not claim conformity and do not show a CE mark.
