# Security Policy

## Supported Versions

We currently support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of Role Intelligence Service seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to security@roleintelligence.com.

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report more quickly.

## Preferred Languages

We prefer all communications to be in English.

## Policy

Role Intelligence Service follows the principle of [Responsible Disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure).

## What to expect

After you submit a report, we will:

1. Confirm the problem and determine the affected versions.
2. Audit code to find any similar problems.
3. Prepare fixes for all supported versions. These fixes will be released as fast as possible.

## Security Best Practices

When using Role Intelligence Service, we recommend following these security best practices:

1. Always use the latest stable version
2. Keep your API keys and credentials secure
3. Use environment variables for sensitive configuration
4. Regularly audit role assignments and permissions
5. Monitor access logs for suspicious activity
6. Implement proper authentication and authorization
7. Use HTTPS for all API communications
8. Regularly backup your Neo4j database
9. Follow the principle of least privilege
10. Keep all dependencies up to date

## Security Updates

Security updates will be released as patch versions (e.g., 1.0.1, 1.0.2) and will be announced in the release notes. We recommend subscribing to our security announcements mailing list for immediate notification of security updates. 