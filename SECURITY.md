# Security Policy

## Supported Versions

The following versions of Field Watcher are currently being supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 2.1.x   | ✅ Yes             |
| < 2.1   | ❌ No              |

## Reporting a Vulnerability

We take the security of Field Watcher seriously. If you believe you have found a security vulnerability, please report it responsibly.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please follow these steps:
1. Send an email to the maintainer (if provided) or open a private security advisory on GitHub.
2. Provide a detailed description of the vulnerability.
3. Include steps to reproduce the issue (PoC).
4. Mention the potential impact.

We will acknowledge your report within 48 hours and provide a timeline for a fix if the vulnerability is confirmed.

## Security Scope & Principles

### Passive Monitoring
Field Watcher is designed as a **100% passive** tool. It should never transmit packets on the wire during its normal discovery mode. If you find any behavior where the software initiates outgoing network traffic (other than local database operations), please report it as a high-priority bug.

### Privileges
By design, this tool requires `root` or `sudo` privileges to put network interfaces into promiscuous mode. We recommend:
- Running the tool on a dedicated monitoring interface.
- Ensuring the SQLite database is stored in a secure directory with restricted permissions.
- Running the tool inside a restricted environment if possible.

### Data Privacy
Field Watcher captures metadata (IP, MAC, Hostnames) from unencrypted discovery protocols. It does not inspect the encrypted payload of application traffic (HTTPS, SSH, etc.). Users are responsible for ensuring that the use of this tool complies with local privacy laws and network monitoring policies.
