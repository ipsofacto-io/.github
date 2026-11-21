# ipsofacto-io/.github

Organization profile and default community health files for the [ipsofacto-io](https://github.com/ipsofacto-io) repositories.

| Path | Purpose |
| --- | --- |
| [`profile/README.md`](profile/README.md) | Public organization profile |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution workflow, licenses and contributor terms |
| [`SECURITY.md`](SECURITY.md) | Private vulnerability reporting, the 90-day coordinated disclosure policy, good-faith testing, the security support period, and how to verify a release and its SBOM |
| [`.well-known/security.txt`](.well-known/security.txt) | RFC 9116 security contact file. It is served at `https://ipsoplatform.io/.well-known/security.txt` once the site is live. GitHub does not apply it |
| [`scripts/`](scripts/) | Checker and tests for `security.txt`, run by the `security-txt` workflow on every pull request and weekly, so the file is renewed before it expires |
| [`SUPPORT.md`](SUPPORT.md) | Where to ask for help, including the security support period |
| [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/) | Issue forms: bug, feature, task, decision proposal |
| [`.github/pull_request_template.md`](.github/pull_request_template.md) | Pull request template |

GitHub applies these files to every repository in the organization that does not define its own version.
