# Changelog

All notable changes to the WordPress Security Hardening Guide.

## Unreleased

### Added
- Added a `Series review` issue form so quarterly and pre-release cross-document alignment checks can be tracked explicitly.
- Added a repo-local generated-artifact smoke validator and a dedicated `Validate Artifacts` workflow for PDF, EPUB, and DOCX outputs.
- Added a Playwright-based PDF visual smoke test and dedicated workflow with committed baselines for critical page regions.

### Changed
- Corrected current-version framing to reflect WordPress 6.9.1 as the latest stable release and WordPress 7.0 as scheduled for April 9, 2026.
- Refactored the document-generation pipeline into explicit build, validate, and publish jobs so generated artifacts are validated before the bot commit step runs.
- Updated GitHub Action pins in the PDF visual validation workflow to Node 24-capable major versions to avoid runner deprecation warnings.
- Set a short PDF running header title so the guide subtitle no longer appears in page headers.
- Hardened GitHub release automation and metrics validation by pinning action references to immutable commits.
- Documented the maintainer edit, verification, artifact-generation, release, and cross-document review workflow for this repository and its companion document series.

## 1.1.0 — 2026-03-21

### Changed
- Replaced the ad hoc license file with the canonical Creative Commons BY-SA 4.0 legal text and normalized in-repo license references to `CC-BY-SA-4.0` for GitHub license detection consistency.
- Replaced the hard-coded local verification path in `docs/current-metrics.md` with `git rev-parse --show-toplevel` for path-independent maintenance checks.
- Corrected stale repository metadata in `docs/current-metrics.md` by restoring the full 17-section map and updating the local verification path.
- Updated market-share, version-context, and security-architecture wording in the guide and README to reflect the current WordPress 6.9.4 / planned 7.0 state and current W3Techs figures.
- Tightened high-risk technical guidance around REST API CORS behavior, safe HTTP SSRF protections, and software integrity wording to avoid overstating what WordPress core guarantees.
- Added repository hygiene files (`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, `LICENSE`, `.gitattributes`) and linked them from the README so GitHub community health reflects the repo's intended maintenance model.
- Cited WordPress VIP step-up authentication as an example platform implementation of action-gated reauthentication in §8.2.
- Updated version framing for the WordPress 7.0 release cycle and aligned PHP guidance to the current `8.3+` baseline with `8.4` staging validation.
- Corrected the password-policy recommendation to restore the 15-character baseline and normalized the cross-document classification matrix wording.
- Added centered page numbering to `.github/pandoc/reference.docx` so DOCX-derived PDF output includes footer page numbers through the shared generation pipeline.
- Replaced the repo-local document-generation workflow with a caller to the shared reusable workflow in `ai-assisted-docs`, keeping the primary markdown source and generated artifact names unchanged.

### Added
- `CHANGELOG.md` — this file.
- `docs/current-metrics.md` — architectural fact counts with verification commands.

## 1.0 — 2026-03-08

### Added
- Initial public release: enterprise security architecture and threat mitigation guidance.
- 17 major sections covering threat landscape, core security architecture, OWASP Top 10 (2025), server hardening, application hardening, authentication, monitoring, backup, supply chain, organizational practices, hosting, and AI integration security.
- Cross-Document Control Classification Matrix aligning controls with the Security Benchmark.
- Deprecated and Invalid Constants Guardrail (section 15.5).
- PDF, DOCX, and EPUB formats via Pandoc CI/CD pipeline.
- Editorial review by three frontier LLMs with human editorial approval.
