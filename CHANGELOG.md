# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Hardened CI: pinned GitHub Actions by commit SHA, least-privilege `permissions`, and `concurrency`.
- `Release` workflow: builds sdist + wheel, generates `SHA256SUMS.txt`, produces a SLSA build-provenance
  attestation, and publishes a GitHub Release on `v*` tags.
- Project hygiene: `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, `dependabot.yml`, this changelog.

## [0.1.0] - 2026-08-10
### Added
- Initial public release of the Renker platform authorization core (Apache-2.0), extracted from
  `renker-core`: identity, capabilities, path scope, deterministic policy, tamper-evident audit, and a
  guarded filesystem executor. Zero runtime dependencies. Verified black-box inside `RENCORA.exe`.
