# API Reference

This document describes the REST API endpoints exposed by the Role Intelligence Service (via FastAPI).

## Endpoints

### 1. Evaluate Role
- **Path:** `/evaluate-role`
- **Method:** POST
- **Description:** Evaluate the risk score of a given role.
- **Request Example:**
  ```json
  {
    "role_id": "123e4567-e89b-12d3-a456-426614174000"
  }
  ```
- **Response Example:**
  ```json
  {
    "role_id": "123e4567-e89b-12d3-a456-426614174000",
    "risk_score": 0.85
  }
  ```

### 2. List Roles
- **Path:** `/roles`
- **Method:** GET
- **Description:** Retrieve all roles in the system.
- **Response Example:**
  ```json
  [
    {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "name": "Admin",
      "risk_score": 0.85
    },
    ...
  ]
  ```

### 3. Analyze System
- **Path:** `/analyze`
- **Method:** POST
- **Description:** Run a full system analysis (role mining, risk evaluation, AI insights).
- **Request Example:**
  ```json
  {
    "analysis_type": "full"
  }
  ```
- **Response Example:**
  ```json
  {
    "summary": "3 high-risk roles found. 2 optimization suggestions generated.",
    "details": {...}
  }
  ```

### 4. System Insights
- **Path:** `/system-insights`
- **Method:** GET
- **Description:** Get high-level insights and statistics about the IAM system.
- **Response Example:**
  ```json
  {
    "total_users": 120,
    "total_roles": 15,
    "high_risk_roles": 3
  }
  ```

## Usage Notes
- All endpoints return JSON.
- Authentication may be required for production deployments.
- See [Core Data Models](core_data_models.md) for schema details. 