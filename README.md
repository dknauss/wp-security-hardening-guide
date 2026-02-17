# WordPress Security Hardening Guide

**Enterprise Best Practices and Threat Mitigation for the Modern WordPress Ecosystem.**

This repository contains a comprehensive guide to WordPress security architecture, processes, and hardening practices. It is designed for developers, system administrators, and security teams tasked with deploying and maintaining WordPress in high-security and enterprise environments.

---

## 🚀 Overview

WordPress powers over 43% of the internet. While its core security is robust, the vast majority of vulnerabilities (90-99%) originate in third-party plugins and themes, misconfigured environments, or compromised user accounts. This guide provides the technical and organizational frameworks necessary to mitigate these risks.

### Key Focus Areas:
- **Core Security Architecture**: Understanding the WordPress Security Team, release cycles, and automatic patching.
- **OWASP Top 10**: Detailed mapping of how WordPress handles injection, broken access control, and cryptographic failures.
- **Server Hardening**: Prescriptive configurations for Nginx, Apache, PHP, and network-level defenses.
- **User Authentication**: Implementing MFA/2FA, privileged action gating, and session security.
- **Supply Chain Security**: Managing SBOMs and vetting third-party extensions.
- **Generative AI Security**: Navigating the emerging risks of LLM integrations and "Shadow AI."

---

## 📖 Related Documents

This guide is part of a larger ecosystem of security resources:

- 📊 **[WordPress Security Benchmark](https://github.com/dknauss/wp-security-benchmark)**: Auditable hardening controls for compliance and configuration audits.
- ✍️ **[WordPress Security Style Guide](https://github.com/dknauss/wp-security-style-guide)**: Principles and terminology for writing about WordPress security effectively.
- 🛡️ **[WordPress Security Hardening Guide (PDF and Markdown)]**: The full technical document in this repository.

---

## 🛠️ Getting Started

To get the most out of this repository:
1. Read the **[Full Security Guide](file:///Users/danknauss/Documents/GitHub/wp-security-hardening-guide/WordPress-Security-Hardening-Guide.md)**.
2. Cross-reference your current configuration with the **[Security Benchmark](https://github.com/dknauss/wp-security-benchmark)**.
3. Review the **Executive Summary** in Section 2 for the latest threat landscape data from Verizon and IBM.

---

## ⚖️ License and Attribution

This project is licensed under the **[Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/)**.

*Maintained by Dan Knauss. Last updated: February 16, 2026.*
