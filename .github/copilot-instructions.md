# Copilot Instructions

## Project Overview

WordPress Security Hardening Guide — an enterprise architecture and strategy document for securing WordPress deployments. This is a documentation-only repository (Markdown + PDF). No code, no build step, no dependencies.

Licensed CC BY-SA 4.0.

## Repository Structure

- `WordPress-Security-Hardening-Guide.md` — The primary document. Architecture, strategy, and implementation guidance.
- `README.md` — Project overview and contribution guidance.
- `WordPress-Security-Hardening-Guide.pdf` — PDF export of the guide.

## Writing Conventions

- The companion [WordPress Security Benchmark](https://github.com/dknauss/wp-security-benchmark) is the more comprehensive document. Anything covered here should also be in the Benchmark.
- Terminology follows the [WP Security Style Guide](https://github.com/dknauss/wp-security-style-guide) glossary.
- "Dashboard" preferred over "admin panel" or "backend."
- `wp-config.php` always in monospace backticks.
- Acronyms spelled out on first use.
- Security statistics cite Verizon DBIR 2025 and IBM Cost of a Data Breach 2025.
- OWASP Top 10:2025 categories used for vulnerability classification.
- Current WordPress version coverage: 6.9 (February 2026).
- PHP 8.2 security-only support, 8.3+ recommended.

## Key Technical Context

- WordPress uses bcrypt password hashing by default since WP 6.8 (April 2025), with SHA-384 pre-hashing and BLAKE2b for tokens.
- WordPress 7.0 is due April 9, 2026 — version references will need updating.
