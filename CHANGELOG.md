# Changelog

All notable changes to the WordPress Security Hardening Guide.

## Unreleased

### Changed
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
