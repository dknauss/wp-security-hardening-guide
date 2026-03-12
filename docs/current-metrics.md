# Current Metrics (Canonical)

This file is the single source of truth for architectural counts in the WordPress Security Hardening Guide. Check this file before writing any count in prose, and update it when adding or removing sections or structural elements.

Last verified: 2026-03-12

## Architectural Facts

| Fact | Value | Verification command | Last changed |
|---|---:|---|---|
| Document lines | 621 | `wc -l WordPress-Security-Hardening-Guide.md` | v1.0 |
| Major sections (H2) | 17 | `grep -cE '^## ' WordPress-Security-Hardening-Guide.md` | v1.0 |
| Subsections (H3) | 50 | `grep -cE '^### ' WordPress-Security-Hardening-Guide.md` | v1.0 |
| OWASP Top 10 categories covered | 10 | A01–A10:2025 in section 4 | v1.0 |
| Table rows | 7 | `grep -cE '^\| ' WordPress-Security-Hardening-Guide.md` | v1.0 |
| Code fences | 0 | `grep -c '^\`\`\`' WordPress-Security-Hardening-Guide.md` | v1.0 |
| WP-CLI commands | 0 | `grep -cE '^\s*wp ' WordPress-Security-Hardening-Guide.md` | v1.0 |
| `[CUSTOMIZE: ...]` placeholders | 0 | `grep -c '\[CUSTOMIZE:' WordPress-Security-Hardening-Guide.md` | v1.0 |
| Output formats | 4 | Markdown, DOCX, EPUB, PDF | v1.0 |

## Section Map

| Section | Title | Subsections |
|---|---|---:|
| 1 | Overview | 0 |
| 2 | Threat Landscape | 0 |
| 3 | WordPress Core Security Architecture | 4 |
| 4 | OWASP Top 10 Coverage | 10 |
| 5 | Keeping WordPress Up to Date | 1 |
| 6 | Server Hardening | 4 |
| 7 | WordPress Application Hardening | 5 |
| 8 | User Authentication and Session Security | 5 |
| 9 | Security Plugins and Monitoring | 3 |
| 10 | Backup and Recovery | 0 |
| 11 | Supply Chain Security | 4 |
| 12 | Organizational Security Practices | 5 |
| 13 | The Role of the Hosting Provider | 0 |
| 14 | AI Integration Security in WordPress | 3 |
| 15 | Additional Resources | 6 |

## Notes

This document is advisory prose with no code blocks, WP-CLI commands, or customization placeholders. Operational commands belong in the companion [Operations Runbook](https://github.com/dknauss/wordpress-runbook-template). Audit commands belong in the companion [Security Benchmark](https://github.com/dknauss/wp-security-benchmark).

If code blocks or commands are added in future revisions, add verification commands to this table and update the counts.

## Verification Procedure

Run after any structural edit:

```bash
cd /Users/danknauss/Documents/GitHub/wp-security-hardening-guide

echo "=== Document size ==="
wc -l WordPress-Security-Hardening-Guide.md

echo "=== Structure ==="
echo "H2 sections: $(grep -cE '^## ' WordPress-Security-Hardening-Guide.md)"
echo "H3 subsections: $(grep -cE '^### ' WordPress-Security-Hardening-Guide.md)"
echo "Table rows: $(grep -cE '^\| ' WordPress-Security-Hardening-Guide.md)"

echo "=== Code ==="
echo "Code fences: $(grep -c '^```' WordPress-Security-Hardening-Guide.md)"
echo "WP-CLI commands: $(grep -cE '^\s*wp ' WordPress-Security-Hardening-Guide.md)"
echo "CUSTOMIZE placeholders: $(grep -c '\[CUSTOMIZE:' WordPress-Security-Hardening-Guide.md)"
```

## Update Procedure

1. After any edit to `WordPress-Security-Hardening-Guide.md`, run the verification script above.
2. Compare results to this table. Update any changed values.
3. Update `CHANGELOG.md` with the change.
