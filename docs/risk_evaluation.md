# Risk Evaluation Module

This module quantifies the risk associated with roles and permission assignments using mathematical models.

## Purpose
- Assess and quantify risk for roles, users, and permissions.
- Support risk-aware access management and recommendations.

## Key Functions
- `calculate_role_risk(role: Role) -> float`: Computes risk score for a role.
- `evaluate_user_risk(user: User) -> float`: Aggregates risk across all roles assigned to a user.

## Inputs
- Role, User, Permission objects (see [Core Data Models](core_data_models.md)).

## Outputs
- Risk score (float between 0 and 1).

## Algorithm
- Considers:
  - Permission criticality
  - Access frequency
  - Separation of duties
  - Historical incidents
- Example formula:
  ```python
  risk = (criticality_weight * permission_criticality +
          frequency_weight * access_frequency +
          incident_weight * incident_history) / normalization_factor
  ```

## Example Usage
```python
risk = risk_evaluator.calculate_role_risk(role)
print(f"Role {role.name} has risk score: {risk}")
``` 