---
title: Multi-Tenant SaaS Architecture
description: Deep dive into the multi-tenant architecture of SaaSReady. Learn how organizations, users, and isolation work in a B2B SaaS environment.
keywords: [multi-tenant architecture, SaaS multi-tenancy, B2B SaaS design, organization management, tenant isolation]
---

# Multi-Tenant Architecture

SaaSReady is designed from the ground up to support **Multi-Tenancy**, the core architectural pattern for B2B (Business-to-Business) software where a single instance of the application serves multiple groups of users (Organizations).

## Core Concepts: Users vs. Organizations

In a typical B2B application, resources are owned by **Organizations** (also known as Tenants, Workspaces, or Teams), not individual users.

- **User**: A physical person with an email and password. A user can belong to multiple organizations.
- **Organization**: A logical container for resources, data, and members. Each organization has its own unique slug and settings.
- **Membership**: The link between a User and an Organization, which defines the user's **Role** within that specific context.

## Data Isolation

SaaSReady ensures that data remains isolated between organizations. Every resource in the database (API keys, audit logs, feature flags) is associated with an `organization_id`.

### The "Personal Organization" Pattern
By default, when a user registers without an invitation, SaaSReady automatically creates a "Personal Organization" for them. This ensures that the user immediately has a workspace to explore the platform's features as an Owner.

## Invitation Workflow

One of the most complex parts of B2B SaaS is the onboarding flow. SaaSReady handles this out of the box:

1. **Invite**: An Admin/Owner invites a new member via email.
2. **Pending Membership**: A membership record is created with a `PENDING` status.
3. **Acceptance**: The user receives an email with a unique token.
4. **Onboarding**: Upon clicking the link, the user either registers or logs in, and the membership is automatically activated.

## Scaling Multi-Tenancy

For early-stage and mid-market SaaS, SaaSReady uses a **Shared Database, Shared Schema** approach. This offers the best balance between cost-efficiency and maintenance.

- **Efficiency**: All tenants share the same database connections and caches.
- **Logical Isolation**: Every query is filtered by `organization_id` at the repository level.

For enterprise scale, the architecture supports moving toward a **Shared Database, Separate Schema** or even **Separate Database** approach by adjusting the connection routing, though the default setup is optimized for rapid growth and lower infrastructure overhead.
