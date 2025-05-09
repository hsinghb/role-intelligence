from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from uuid import UUID

from role_intelligence.models import (
    AccessLog,
    Permission,
    Resource,
    Role,
    RoleEvaluation,
    RoleRecommendation,
    User,
)
from role_intelligence.risk_evaluation import RiskEvaluator
from role_intelligence.role_mining import RoleMiner


class RoleIntelligenceService:
    """Main service that orchestrates role intelligence operations."""

    def __init__(
        self,
        min_cluster_size: int = 3,
        similarity_threshold: float = 0.7,
        evaluation_window_days: int = 30,
    ):
        self.risk_evaluator = RiskEvaluator()
        self.role_miner = RoleMiner(
            min_cluster_size=min_cluster_size,
            similarity_threshold=similarity_threshold,
        )
        self.evaluation_window_days = evaluation_window_days

    def evaluate_role(
        self,
        role: Role,
        resources: List[Resource],
        permissions: List[Permission],
        users: List[User],
        access_logs: List[AccessLog],
        compliance_violations: int = 0,
        historical_incidents: int = 0,
    ) -> RoleEvaluation:
        """Evaluate a single role for risks and optimization opportunities."""
        # Get users with this role
        role_users = [u for u in users if role.id in u.roles]
        
        # Get role-specific access logs
        role_access_logs = [
            log for log in access_logs
            if log.user_id in {u.id for u in role_users}
            and log.timestamp >= datetime.utcnow() - timedelta(days=self.evaluation_window_days)
        ]
        
        # Get role-specific resources and permissions
        role_resources = [
            r for r in resources
            if any(p.resource_id == r.id for p in permissions if p.id in role.permissions)
        ]
        role_permissions = [p for p in permissions if p.id in role.permissions]
        
        # Evaluate role risk
        return self.risk_evaluator.evaluate_role_risk(
            role=role,
            resources=role_resources,
            permissions=role_permissions,
            access_logs=role_access_logs,
            user_count=len(role_users),
            compliance_violations=compliance_violations,
            historical_incidents=historical_incidents,
        )

    def analyze_roles(
        self,
        roles: List[Role],
        users: List[User],
        resources: List[Resource],
        permissions: List[Permission],
        access_logs: List[AccessLog],
    ) -> Tuple[List[RoleEvaluation], List[RoleRecommendation]]:
        """Analyze all roles and generate evaluations and recommendations."""
        evaluations = []
        recommendations = []

        # Evaluate each role
        for role in roles:
            evaluation = self.evaluate_role(
                role=role,
                resources=resources,
                permissions=permissions,
                users=users,
                access_logs=access_logs,
            )
            evaluations.append(evaluation)

        # Generate role mining recommendations
        mining_recommendations = self.role_miner.analyze_roles(
            roles=roles,
            users=users,
            permissions=permissions,
            access_logs=access_logs,
        )
        recommendations.extend(mining_recommendations)

        # Generate hierarchy optimization recommendations
        hierarchy_recommendations = self.role_miner.optimize_role_hierarchy(
            roles=roles,
            permissions=permissions,
        )
        recommendations.extend(hierarchy_recommendations)

        return evaluations, recommendations

    def get_role_insights(
        self,
        role: Role,
        users: List[User],
        resources: List[Resource],
        permissions: List[Permission],
        access_logs: List[AccessLog],
    ) -> Dict:
        """Get detailed insights about a specific role."""
        # Get role evaluation
        evaluation = self.evaluate_role(
            role=role,
            resources=resources,
            permissions=permissions,
            users=users,
            access_logs=access_logs,
        )

        # Get users with this role
        role_users = [u for u in users if role.id in u.roles]
        
        # Get role-specific access logs
        role_access_logs = [
            log for log in access_logs
            if log.user_id in {u.id for u in role_users}
            and log.timestamp >= datetime.utcnow() - timedelta(days=self.evaluation_window_days)
        ]

        # Calculate usage statistics
        total_accesses = len(role_access_logs)
        successful_accesses = sum(1 for log in role_access_logs if log.success)
        unique_users = len({log.user_id for log in role_access_logs})
        unique_resources = len({log.resource_id for log in role_access_logs})

        # Get permission usage statistics
        permission_usage = {}
        for perm_id in role.permissions:
            perm_accesses = sum(
                1 for log in role_access_logs
                if log.permission_id == perm_id and log.success
            )
            permission_usage[str(perm_id)] = {
                "total_uses": perm_accesses,
                "unique_users": len(
                    {log.user_id for log in role_access_logs if log.permission_id == perm_id}
                ),
            }

        return {
            "role_id": str(role.id),
            "role_name": role.name,
            "evaluation": evaluation.dict(),
            "usage_statistics": {
                "total_accesses": total_accesses,
                "successful_accesses": successful_accesses,
                "success_rate": successful_accesses / total_accesses if total_accesses > 0 else 0,
                "unique_users": unique_users,
                "unique_resources": unique_resources,
                "active_users_percentage": unique_users / len(role_users) if role_users else 0,
            },
            "permission_usage": permission_usage,
            "user_statistics": {
                "total_users": len(role_users),
                "active_users": unique_users,
                "inactive_users": len(role_users) - unique_users,
            },
            "risk_indicators": {
                "high_risk_permissions": [
                    str(perm_id)
                    for perm_id in role.permissions
                    if permission_usage.get(str(perm_id), {}).get("total_uses", 0) == 0
                ],
                "over_privileged_users": [
                    str(user.id)
                    for user in role_users
                    if len(
                        {
                            log.resource_id
                            for log in role_access_logs
                            if log.user_id == user.id and log.success
                        }
                    )
                    < len(role.permissions) / 2
                ],
            },
        }

    def get_system_insights(
        self,
        roles: List[Role],
        users: List[User],
        resources: List[Resource],
        permissions: List[Permission],
        access_logs: List[AccessLog],
    ) -> Dict:
        """Get system-wide insights about roles and access patterns."""
        # Get all evaluations and recommendations
        evaluations, recommendations = self.analyze_roles(
            roles=roles,
            users=users,
            resources=resources,
            permissions=permissions,
            access_logs=access_logs,
        )

        # Calculate system-wide statistics
        total_roles = len(roles)
        total_users = len(users)
        total_resources = len(resources)
        total_permissions = len(permissions)

        # Calculate role statistics
        role_stats = {
            "total_roles": total_roles,
            "high_risk_roles": sum(1 for e in evaluations if e.risk_score > 0.8),
            "medium_risk_roles": sum(1 for e in evaluations if 0.6 < e.risk_score <= 0.8),
            "low_risk_roles": sum(1 for e in evaluations if e.risk_score <= 0.6),
            "roles_with_low_coverage": sum(1 for e in evaluations if e.coverage_score < 0.3),
            "roles_with_high_complexity": sum(1 for e in evaluations if e.complexity_score > 0.8),
        }

        # Calculate recommendation statistics
        rec_stats = {
            "total_recommendations": len(recommendations),
            "merge_recommendations": sum(1 for r in recommendations if r.action == "merge"),
            "modify_recommendations": sum(1 for r in recommendations if r.action == "modify"),
            "create_recommendations": sum(1 for r in recommendations if r.action == "create"),
        }

        # Calculate user-role statistics
        user_role_stats = {
            "users_with_multiple_roles": sum(1 for u in users if len(u.roles) > 1),
            "average_roles_per_user": sum(len(u.roles) for u in users) / total_users if total_users > 0 else 0,
            "users_with_high_risk_roles": sum(
                1 for u in users
                if any(
                    e.risk_score > 0.8
                    for e in evaluations
                    if e.role_id in u.roles
                )
            ),
        }

        return {
            "system_statistics": {
                "total_roles": total_roles,
                "total_users": total_users,
                "total_resources": total_resources,
                "total_permissions": total_permissions,
            },
            "role_statistics": role_stats,
            "recommendation_statistics": rec_stats,
            "user_role_statistics": user_role_stats,
            "risk_distribution": {
                "high_risk": role_stats["high_risk_roles"] / total_roles if total_roles > 0 else 0,
                "medium_risk": role_stats["medium_risk_roles"] / total_roles if total_roles > 0 else 0,
                "low_risk": role_stats["low_risk_roles"] / total_roles if total_roles > 0 else 0,
            },
            "top_recommendations": sorted(
                recommendations,
                key=lambda x: x.confidence_score,
                reverse=True,
            )[:5],
        } 