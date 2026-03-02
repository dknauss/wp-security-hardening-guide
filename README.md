# WordPress Security Hardening Guide

**Enterprise Best Practices and Threat Mitigation for the Modern WordPress Ecosystem.**

This repository contains a comprehensive guide to WordPress security architecture, processes, and hardening practices. It is designed for developers, system administrators, and security teams tasked with deploying and maintaining WordPress in high-security and enterprise environments.

---

## Document Purpose

This is an **advisory guide** — it answers **"what should I implement and why?"**

It provides the threat landscape context, architectural rationale, and implementation guidance behind security decisions. The target reader is a security-aware developer, architect, or team lead deciding *which* hardening measures to adopt, understanding the tradeoffs, and mapping controls to real-world threats like the OWASP Top 10.

This document is **not** a compliance checklist (use the [Security Benchmark](https://github.com/dknauss/wp-security-benchmark) for audit-ready controls with pass/fail criteria), **not** a step-by-step operations manual (use the [Operations Runbook](https://github.com/dknauss/wordpress-runbook-template) for procedures and code snippets), and **not** a writing reference (use the [Style Guide](https://github.com/dknauss/wp-security-style-guide)).

---

## Overview

WordPress powers over 43% of the internet. While its core security is robust, the vast majority of vulnerabilities (90-99%) originate in third-party plugins and themes, misconfigured environments, or compromised user accounts. This guide provides the technical and organizational frameworks necessary to mitigate these risks.

### Key Focus Areas:
- **Core Security Architecture**: Understanding the WordPress Security Team, release cycles, and automatic patching.
- **OWASP Top 10**: Detailed mapping of how WordPress handles injection, broken access control, and cryptographic failures.
- **Server Hardening**: Prescriptive configurations for Nginx, Apache, PHP, and network-level defenses.
- **User Authentication**: Implementing MFA/2FA, privileged action gating, and session security.
- **Supply Chain Security**: Managing SBOMs and vetting third-party extensions.
- **Generative AI Security**: Navigating the emerging risks of LLM integrations and "Shadow AI."

---

## Related Documents

This guide is one of four complementary documents covering WordPress security from different angles:

| Document | Purpose |
|---|---|
| **[WordPress Security Benchmark](https://github.com/dknauss/wp-security-benchmark)** | Audit checklist — "what to verify." Prescriptive, auditable hardening controls for compliance verification. |
| **[WordPress Operations Runbook](https://github.com/dknauss/wordpress-runbook-template)** | Operational — "how to do it." Step-by-step procedures, code snippets, and incident response playbooks. |
| **[WordPress Security Style Guide](https://github.com/dknauss/wp-security-style-guide)** | Editorial — "how to write about it." Terminology, voice, and formatting conventions for security communication. |

### Additional Resources

- [Hardening WordPress](https://developer.wordpress.org/advanced-administration/security/) — Official WordPress.org Advanced Administration Handbook.
- [Securing WordPress](https://cio.ubc.ca/information-security/policy-standards-resources/M5/gui-securing-wordpress) — Information Security Guidance from the University of British Columbia's Office of the CIO.

---

## Getting Started

To get the most out of this repository:
1. Read the **[Full Security Guide](WordPress-Security-Hardening-Guide.md)**.
2. Cross-reference your current configuration with the **[Security Benchmark](https://github.com/dknauss/wp-security-benchmark)**.
3. Review the **Executive Summary** in Section 2 for the latest threat landscape data from Verizon and IBM.

---

## License and Attribution

This project is licensed under the **[Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/)**.

*Maintained by Dan Knauss.*
