# Integrations & Adapters

This module provides adapters for major IAM platforms, enabling data synchronization and recommendations.

## Supported Platforms
- Okta
- Azure AD
- AWS IAM
- Google Workspace
- Neo4j

## Purpose
- Fetch and synchronize roles, users, permissions, and access logs.
- Apply recommendations to external IAM systems.

## Common Interface
- `fetch_roles()`
- `fetch_users()`
- `fetch_permissions()`
- `fetch_access_logs()`
- `apply_recommendations(recommendations)`

## Example Usage
```python
okta_adapter.fetch_roles()
azure_adapter.apply_recommendations(recommendations)
```

## Platform-Specific Notes

### Okta
- Uses Okta API tokens for authentication.
- Supports incremental sync.

### Azure AD
- Integrates via Microsoft Graph API.
- Handles user, group, and role objects.

### AWS IAM
- Uses boto3 for access.
- Can fetch policies, roles, and CloudTrail logs.

### Google Workspace
- Integrates via Google Admin SDK.
- Fetches users, groups, and privileges.

### Neo4j
- Connects to graph database for advanced relationship analysis.
- Useful for visualizing and querying complex access structures. 