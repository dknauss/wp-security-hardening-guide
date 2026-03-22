# WordPress Security Docs Series Release Summary

Date: March 21, 2026

This coordinated maintenance and release pass aligned the four companion repositories in the WordPress security documentation series on licensing, repository hygiene, release metadata, generated artifacts, and cross-document editorial consistency.

## Releases

| Repository | Release | Notes |
|---|---|---|
| [`wp-security-benchmark`](https://github.com/dknauss/wp-security-benchmark) | [`v1.1.0`](https://github.com/dknauss/wp-security-benchmark/releases/tag/v1.1.0) | License normalization, explicit repo health files, metadata cleanup, regenerated PDF/DOCX/EPUB artifacts, and current-version framing updates. |
| [`wp-security-hardening-guide`](https://github.com/dknauss/wp-security-hardening-guide) | [`v1.1.0`](https://github.com/dknauss/wp-security-hardening-guide/releases/tag/v1.1.0) | Current WordPress/W3Techs/Patchstack fact refresh, metrics cleanup, license normalization, repo hygiene baseline, and regenerated artifacts. |
| [`wp-security-style-guide`](https://github.com/dknauss/wp-security-style-guide) | [`v1.1.0`](https://github.com/dknauss/wp-security-style-guide/releases/tag/v1.1.0) | License normalization, explicit repo health files, consistency updates, and regenerated artifacts. |
| [`wordpress-runbook-template`](https://github.com/dknauss/wordpress-runbook-template) | [`v3.1.0`](https://github.com/dknauss/wordpress-runbook-template/releases/tag/v3.1.0) | License normalization, explicit repo health files, runbook framing cleanup, and regenerated artifacts. |

## Series-Wide Changes

- Standardized all repositories on the canonical `CC-BY-SA-4.0` identifier and GitHub-detectable Creative Commons legal text.
- Established the same explicit repository-health baseline in each repo: `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, and `.gitattributes`.
- Regenerated and published PDF, DOCX, and EPUB artifacts from the updated canonical Markdown sources.
- Normalized contributor and AI-assisted editorial disclosures across the series.
- Aligned version framing so current stable WordPress and planned release-cycle references are distinguished explicitly.

## Operational Follow-Up

- Release automation was updated after this coordinated release so future tags also have a manual `workflow_dispatch` fallback.
- Remaining GitHub metadata alignment work is tracked in-repo through README, changelog, and workflow history rather than a separate project board.
