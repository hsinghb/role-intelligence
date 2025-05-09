"""Role Intelligence Service - An intelligent role engine for IAM."""

from role_intelligence.models import (
    AccessLog,
    Permission,
    PermissionLevel,
    Resource,
    ResourceType,
    RiskLevel,
    Role,
    RoleEvaluation,
    RoleRecommendation,
    User,
)
from role_intelligence.service import RoleIntelligenceService

__version__ = "1.0.0"
__all__ = [
    "AccessLog",
    "Permission",
    "PermissionLevel",
    "Resource",
    "ResourceType",
    "RiskLevel",
    "Role",
    "RoleEvaluation",
    "RoleRecommendation",
    "User",
    "RoleIntelligenceService",
] 