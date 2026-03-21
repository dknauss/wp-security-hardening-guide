# Contributing

Thanks for helping improve the WordPress Security Hardening Guide.

## Scope

Contributions are welcome for:

- factual corrections
- outdated WordPress or security guidance
- wording and structural improvements
- broken links or repository automation issues

This repository is an advisory guide. It is not the place for environment-specific runbook commands or audit-only benchmark controls unless they are needed to explain the guidance clearly.

## Before You Start

Read these files first:

- `README.md`
- `WordPress-Security-Hardening-Guide.md`
- `docs/current-metrics.md`
- `SECURITY.md`

Related repositories in this document series may also need aligned updates:

- `wp-security-benchmark`
- `wordpress-runbook-template`
- `wp-security-style-guide`

## Reporting Issues

- Use the GitHub issue templates for factual problems, broken automation, or improvement requests.
- Do not use public issues for security-sensitive reports. Follow `SECURITY.md` instead.

When filing a documentation bug, include the affected section, the source you used to verify it, and whether companion repos may also need updates.

## Editing Rules

- Treat `WordPress-Security-Hardening-Guide.md` as the canonical source.
- Keep generated artifacts aligned with the canonical Markdown source, but do not hand-edit binary artifacts unless the change specifically targets the generation pipeline or template files.
- Verify WordPress-specific claims against primary sources such as `developer.wordpress.org`, WordPress core documentation, or WordPress.org project pages.
- Keep terminology aligned with the repository's existing editorial style.
- Update `CHANGELOG.md` for user-visible documentation or workflow changes.

## Metrics Verification

If your change affects headings, tables, placeholders, or other structural counts, update `docs/current-metrics.md` and run:

```bash
bash .github/scripts/verify-metrics.sh docs/current-metrics.md
```

The metrics file is the canonical source of truth for the structural counts used in this repository.

## Generated Documents

This repository tracks generated `.docx`, `.epub`, and `.pdf` artifacts. Regenerate them through the documented GitHub Actions workflow or an equivalent local Pandoc toolchain when required by the change.

If you cannot regenerate artifacts locally, note that in the pull request instead of committing guessed outputs.

## Pull Requests

Pull requests should:

- describe what changed and why
- mention any source verification performed
- note whether metrics, changelog entries, or generated artifacts changed
- call out any cross-document follow-up needed in the benchmark, runbook, or style guide repos

Keep changes focused. Separate editorial cleanup from unrelated repository or workflow changes when practical.
