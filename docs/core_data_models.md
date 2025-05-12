# Core Data Models

This document describes the core data models used in the Role Intelligence Service.

## Role
- **Description:** Represents a collection of permissions assigned to users or groups for access control.
- **Fields:**
  - `id` (UUID): Unique identifier.
  - `name` (str): Human-readable name.
  - `description` (str): Optional description.
  - `permissions` (List[Permission]): List of permissions.
  - `risk_score` (float): Calculated risk score.
- **Example:**
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "name": "Admin",
  "description": "Full access to all resources.",
  "permissions": ["perm-001", "perm-002"],
  "risk_score": 0.85
}
```

## Permission
- **Description:** Represents an action or set of actions that can be performed on a resource.
- **Fields:**
  - `id` (UUID)
  - `name` (str)
  - `resource` (Resource)
  - `action` (str)
- **Example:**
```json
{
  "id": "perm-001",
  "name": "Read Reports",
  "resource": "res-001",
  "action": "read"
}
```

## User
- **Description:** Represents an individual or service account in the system.
- **Fields:**
  - `id` (UUID)
  - `username` (str)
  - `email` (str)
  - `roles` (List[Role])
- **Example:**
```json
{
  "id": "user-001",
  "username": "jdoe",
  "email": "jdoe@example.com",
  "roles": ["Admin", "Viewer"]
}
```

## Resource
- **Description:** Any entity that can be accessed or managed (e.g., files, databases, applications).
- **Fields:**
  - `id` (UUID)
  - `name` (str)
  - `type` (str)
- **Example:**
```json
{
  "id": "res-001",
  "name": "Financial Reports",
  "type": "document"
}
```

## Relationships
- Users are assigned Roles.
- Roles are collections of Permissions.
- Permissions grant actions on Resources. 