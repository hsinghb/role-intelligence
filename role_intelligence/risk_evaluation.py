from typing import Dict, List, Optional, Set, Tuple
from uuid import UUID
from datetime import datetime, timedelta

import numpy as np
from pydantic import BaseModel

from role_intelligence.models import (
    AccessLog,
    Permission,
    PermissionLevel,
    Resource,
    ResourceType,
    RiskLevel,
    Role,
    RoleEvaluation,
)


class RiskFactors(BaseModel):
    """Factors that contribute to role risk assessment."""
    resource_sensitivity: float = 0.0
    permission_level: float = 0.0
    access_frequency: float = 0.0
    user_count: float = 0.0
    compliance_violations: float = 0.0
    historical_incidents: float = 0.0


class RiskEvaluator:
    """Evaluates risks associated with roles and permissions."""

    def __init__(self):
        # Weights for different risk factors
        self.weights = {
            "resource_sensitivity": 0.3,
            "permission_level": 0.25,
            "access_frequency": 0.15,
            "user_count": 0.1,
            "compliance_violations": 0.1,
            "historical_incidents": 0.1,
        }

        # Risk level thresholds
        self.risk_thresholds = {
            RiskLevel.LOW: 0.3,
            RiskLevel.MEDIUM: 0.6,
            RiskLevel.HIGH: 0.8,
            RiskLevel.CRITICAL: 1.0,
        }

    def _calculate_resource_sensitivity(self, resources: List[Resource]) -> float:
        """Calculate risk based on resource sensitivity."""
        sensitivity_scores = {
            RiskLevel.LOW: 0.2,
            RiskLevel.MEDIUM: 0.4,
            RiskLevel.HIGH: 0.7,
            RiskLevel.CRITICAL: 1.0,
        }
        
        if not resources:
            return 0.0
            
        return max(sensitivity_scores[r.sensitivity_level] for r in resources)

    def _calculate_permission_level_risk(self, permissions: List[Permission]) -> float:
        """Calculate risk based on permission levels."""
        level_scores = {
            PermissionLevel.READ: 0.2,
            PermissionLevel.EXECUTE: 0.4,
            PermissionLevel.WRITE: 0.7,
            PermissionLevel.ADMIN: 1.0,
        }
        
        if not permissions:
            return 0.0
            
        return max(level_scores[p.level] for p in permissions)

    def _calculate_access_frequency_risk(
        self, role_id: UUID, access_logs: List[AccessLog], time_window_days: int = 30
    ) -> float:
        """Calculate risk based on access frequency."""
        if not access_logs:
            return 0.0

        # Calculate the cutoff date
        cutoff_date = datetime.utcnow() - timedelta(days=time_window_days)

        # Count successful accesses in the time window
        recent_accesses = sum(
            1 for log in access_logs
            if log.success and log.timestamp >= cutoff_date
        )

        # Normalize to a 0-1 scale (assuming 100 accesses per month is high risk)
        return min(recent_accesses / 100, 1.0)

    def _calculate_user_count_risk(self, user_count: int) -> float:
        """Calculate risk based on number of users with the role."""
        # Normalize to a 0-1 scale (assuming 50 users is high risk)
        return min(user_count / 50, 1.0)

    def evaluate_role_risk(
        self,
        role: Role,
        resources: List[Resource],
        permissions: List[Permission],
        access_logs: List[AccessLog],
        user_count: int,
        compliance_violations: int = 0,
        historical_incidents: int = 0,
    ) -> RoleEvaluation:
        """Evaluate the overall risk of a role."""
        # Calculate individual risk factors
        factors = RiskFactors(
            resource_sensitivity=self._calculate_resource_sensitivity(resources),
            permission_level=self._calculate_permission_level_risk(permissions),
            access_frequency=self._calculate_access_frequency_risk(role.id, access_logs),
            user_count=self._calculate_user_count_risk(user_count),
            compliance_violations=min(compliance_violations / 5, 1.0),  # Normalize to 0-1
            historical_incidents=min(historical_incidents / 3, 1.0),  # Normalize to 0-1
        )

        # Calculate weighted risk score
        risk_score = sum(
            getattr(factors, factor) * weight
            for factor, weight in self.weights.items()
        )

        # Calculate coverage score (percentage of permissions that are actively used)
        coverage_score = self._calculate_coverage_score(role, access_logs)

        # Calculate complexity score
        complexity_score = self._calculate_complexity_score(role, permissions)

        # Calculate compliance score
        compliance_score = 1.0 - (compliance_violations / max(user_count, 1))

        # Generate recommendations
        recommendations = self._generate_recommendations(
            role, factors, risk_score, coverage_score, complexity_score, compliance_score
        )

        return RoleEvaluation(
            role_id=role.id,
            risk_score=risk_score,
            coverage_score=coverage_score,
            complexity_score=complexity_score,
            compliance_score=compliance_score,
            recommendations=recommendations,
        )

    def _calculate_coverage_score(
        self, role: Role, access_logs: List[AccessLog]
    ) -> float:
        """Calculate how well the role's permissions are being utilized."""
        if not role.permissions or not access_logs:
            return 0.0

        # Get unique permissions that were actually used
        used_permissions = {
            log.permission_id
            for log in access_logs
            if log.success and log.permission_id in role.permissions
        }

        return len(used_permissions) / len(role.permissions)

    def _calculate_complexity_score(
        self, role: Role, permissions: List[Permission]
    ) -> float:
        """Calculate role complexity based on number of permissions and inheritance."""
        if not permissions:
            return 0.0

        # Base complexity from number of permissions
        permission_complexity = min(len(role.permissions) / 20, 1.0)  # Normalize to 0-1

        # Additional complexity from role hierarchy
        hierarchy_complexity = min(len(role.parent_roles) / 5, 1.0)  # Normalize to 0-1

        # Weighted combination
        return 0.7 * permission_complexity + 0.3 * hierarchy_complexity

    def _generate_recommendations(
        self,
        role: Role,
        factors: RiskFactors,
        risk_score: float,
        coverage_score: float,
        complexity_score: float,
        compliance_score: float,
    ) -> List[str]:
        """Generate recommendations based on risk evaluation."""
        recommendations = []

        # Risk-based recommendations
        if risk_score > 0.8:
            recommendations.append(
                f"High risk role detected. Consider splitting role '{role.name}' into more granular roles."
            )
        elif risk_score > 0.6:
            recommendations.append(
                f"Medium risk role detected. Review permissions for role '{role.name}'."
            )

        # Coverage-based recommendations
        if coverage_score < 0.3:
            recommendations.append(
                f"Low permission utilization detected for role '{role.name}'. Consider removing unused permissions."
            )

        # Complexity-based recommendations
        if complexity_score > 0.8:
            recommendations.append(
                f"High complexity detected for role '{role.name}'. Consider simplifying the role structure."
            )

        # Compliance-based recommendations
        if compliance_score < 0.7:
            recommendations.append(
                f"Low compliance score for role '{role.name}'. Review access patterns and permissions."
            )

        # Factor-specific recommendations
        if factors.resource_sensitivity > 0.8:
            recommendations.append(
                f"Role '{role.name}' has access to highly sensitive resources. Implement additional controls."
            )

        if factors.permission_level > 0.8:
            recommendations.append(
                f"Role '{role.name}' has high-level permissions. Consider implementing privilege escalation controls."
            )

        if factors.user_count > 0.8:
            recommendations.append(
                f"Role '{role.name}' is assigned to many users. Consider role splitting for better access control."
            )

        return recommendations 