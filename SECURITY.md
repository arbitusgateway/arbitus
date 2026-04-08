# Security Policy

## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

Arbitus is a security-focused project. We take all security issues seriously and appreciate responsible disclosure.

### How to Report

Report security vulnerabilities via one of these methods:

1. **GitHub Security Advisories** (Preferred)
   - Navigate to [github.com/arbitusgateway/arbitus/security/advisories](https://github.com/arbitusgateway/arbitus/security/advisories)
   - Click "Report a vulnerability"
   - Provide detailed description of the vulnerability

2. **Email** (Once configured)
   - Send to: security@arbitusgateway.dev
   - Include: "SECURITY: Arbitus Vulnerability" in subject line
   - Provide: Affected version, reproduction steps, potential impact

### What to Include

Please provide the following information:

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Affected versions** (if known)
- **Potential impact** and attack scenario
- **Proof of concept** (if available)
- **Suggested fix** (if you have one)

## Security Response Process

### Timeline

| Stage | Target Timeframe |
|-------|------------------|
| **Acknowledgment** | Within 24 hours |
| **Triage** | Within 3 business days |
| **Initial Assessment** | Within 5 business days |
| **Fix Development** | Depends on severity |
| **CVE Assignment** | If applicable, upon confirmation |
| **Advisory Publication** | After fix is released |

### Fix Development Timeline by Severity

| Severity | Target Fix Time |
|----------|-----------------|
| **Critical** (CVSS 9.0-10.0) | 1-3 days |
| **High** (CVSS 7.0-8.9) | 1 week |
| **Medium** (CVSS 4.0-6.9) | 2 weeks |
| **Low** (CVSS 0.1-3.9) | Next release |

### Process

1. **Acknowledgment**: We confirm receipt within 24 hours
2. **Triage**: We assess severity and assign a CVE if applicable
3. **Development**: We develop a fix privately
4. **Review**: Security team reviews the fix
5. **Release**: We release the fix and publish an advisory
6. **Disclosure**: We credit the reporter (if desired) in the advisory

## Supported Versions

Security updates are provided for the following versions:

| Version | Supported | Notes |
| ------- | --------- | ----- |
| 1.x | ✅ | Active development |
| < 1.0 | ⚠️ | Best-effort only |

We recommend always running the latest stable release.

## Security Features

Arbitus includes the following security features:

### Authentication & Authorization

- **Per-agent policies**: API keys, JWT/OIDC, mTLS
- **Tool allowlists/denylists**: Wildcard patterns supported
- **Resource access control**: `allowed_resources`/`denied_resources`
- **Prompt access control**: `allowed_prompts`/`denied_prompts`
- **OPA/Rego policies**: Custom policy evaluation

### Input Validation

- **Payload filtering**: Block or redact sensitive patterns
- **Encoding-aware**: Base64, URL-encoded, Unicode variants
- **Schema validation**: Validate against `inputSchema`
- **Prompt injection detection**: Built-in heuristics

### Rate Limiting

- **Per-agent limits**: Sliding window enforcement
- **Per-tool limits**: Tool-specific rate limits
- **IP-based limits**: Infrastructure-level protection

### Audit & Compliance

- **Immutable audit log**: SQLite with hash-chain integrity
- **Fan-out**: Multiple backends simultaneously
- **CloudEvents 1.0**: SIEM-compatible format
- **OpenLineage**: Lineage tracking

### Supply Chain Security

- **Binary verification**: SHA-256 hash pinning
- **Cosign verification**: Sigstore bundle verification

### Human-in-the-Loop

- **Approval workflow**: Sensitive operations require human approval
- **Shadow mode**: Dry-run risky operations

## Known Security Considerations

### Transport Security

- **HTTP transport**: Use TLS in production
- **mTLS available**: For agent authentication
- **Stdio transport**: Runs locally; less exposure

### Configuration Security

- **Secrets management**: Use `${VAR}` interpolation or Vault/OpenBao
- **Hot reload**: Changes apply without restart; protect config files
- **Admin endpoints**: Require `Authorization: Bearer <admin_token>`

### Upstream Security

- **Circuit breaker**: Protects against upstream failures
- **Timeout enforcement**: Prevents indefinite hangs
- **Response filtering**: Blocks sensitive patterns in upstream responses

## Security Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities.

(None yet - be the first!)

---

## Contact

- **Security Issues**: See reporting instructions above
- **General Questions**: Open a GitHub Discussion
- **Maintainer Contact**: See [MAINTAINERS.md](MAINTAINERS.md)

Thank you for helping keep Arbitus and its users secure!