---
title: B2B SaaS Audit Logs & Compliance
description: How SaaSReady handles security event logging and audit trails. Essential for enterprise compliance and security monitoring in B2B applications.
keywords: [SaaS audit logs, security event logging, compliance B2B SaaS, user activity tracking, audit trail implementation]
---

# Audit Logs & Compliance

Audit logging is a critical requirement for any enterprise-grade B2B SaaS platform. It provides a transparent, immutable record of security-sensitive actions performed by users within an organization.

## What is an Audit Log?

An audit log records "who did what, when, and where." In SaaSReady, these logs are organization-scoped, allowing organization administrators to monitor the activity of their members for security and compliance purposes.

## Key Events Logged

SaaSReady automatically captures logs for a wide range of events:

- **Authentication**: Successful logins, failed login attempts (brute-force detection), logout, and 2FA enablement/disablement.
- **Organization Management**: Updates to organization settings, creating API keys, and modifying feature flags.
- **Membership & Roles**: Sending invitations, accepting invitations, removing members, and updating member roles.
- **Security**: Password changes and password reset requests.

## Data Captured per Log

Each audit log entry contains rich metadata:

- **Actor**: The user ID who performed the action.
- **Action**: A unique string identifying the event (e.g., `user.login.failed`).
- **Target**: The resource affected (if applicable).
- **Metadata**: Contextual information like IP address and User-Agent.
- **Timestamp**: High-precision UTC timestamp.

## Compliance Readiness

For applications targeting Fintech, Healthcare (HIPAA), or Enterprise (SOC2/ISO27001) customers, SaaSReady's audit logs provide the necessary raw data for compliance audits. 

- **Immutability**: Once written, audit logs are intended to be read-only for users (though manageable by system DB admins).
- **Searchability**: Administrators can filter logs by user or date range to investigate suspicious activity.

## Retention Policy

By default, SaaSReady maintains audit logs for 90 days. This is configurable in your environment settings:

```env
# backend/.env
AUDIT_LOG_RETENTION_DAYS=90
```

## Integrating Audit Logs into Your UI

SaaSReady provides a dedicated API endpoint for retrieving logs, making it easy to build a "Security Activity" dashboard directly in your frontend application.

```python
# List audit logs for an organization
logs = client.orgs.get_audit_logs(org_id=org.id)
```
