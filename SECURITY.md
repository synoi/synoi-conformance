# Security Policy

## Supported versions

This repository contains conformance test vectors, not a runtime library. There are no versioned releases with security support windows.

## Reporting a vulnerability

**Do not open a GitHub issue for security vulnerabilities.**

If you discover that a conformance test vector is incorrect in a way that could cause implementations to accept invalid or forged objects:

- **Preferred:** Use GitHub's [private vulnerability reporting](../../security/advisories/new) - creates a private draft advisory visible only to maintainers, no email required.
- **Alternative:** Submit the form at [synoi.systems/security](https://synoi.systems/security).

Include:
- Which vector(s) are affected and what property they incorrectly assert
- The correct expected behavior per the spec
- Whether passing implementations would accept invalid objects or reject valid ones as a result

We will acknowledge receipt within 72 hours.

## Disclosure policy

We follow responsible disclosure. We will credit reporters in the release notes unless you prefer anonymity.
