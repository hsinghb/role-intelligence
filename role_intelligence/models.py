from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Union
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ResourceType(str, Enum):
    """Types of resources that can be accessed."""
    DATABASE = "database"
    API = "api"
    FILE = "file"
    SERVICE = "service"
    INFRASTRUCTURE = "infrastructure"


class PermissionLevel(str, Enum):
    """Levels of permission that can be granted."""
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    EXECUTE = "execute"


class RiskLevel(str, Enum):
    """Risk levels for roles and permissions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Resource(BaseModel):
    """Represents a resource that can be accessed."""
    id: UUID = Field(default_factory=uuid4)
    name: str
    type: ResourceType
    description: Optional[str] = None
    sensitivity_level: RiskLevel = RiskLevel.LOW
    metadata: Dict[str, str] = Field(default_factory=dict)


class Permission(BaseModel):
    """Represents a permission that can be granted to a role."""
    id: UUID = Field(default_factory=uuid4)
    resource_id: UUID
    level: PermissionLevel
    conditions: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, str] = Field(default_factory=dict)


class Role(BaseModel):
    """Represents a role in the system."""
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    permissions: Set[UUID] = Field(default_factory=set)  # Set of permission IDs
    parent_roles: Set[UUID] = Field(default_factory=set)  # Set of parent role IDs
    risk_score: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, str] = Field(default_factory=dict)


class User(BaseModel):
    """Represents a user in the system."""
    id: UUID = Field(default_factory=uuid4)
    username: str
    email: str
    roles: Set[UUID] = Field(default_factory=set)  # Set of role IDs
    metadata: Dict[str, str] = Field(default_factory=dict)
    last_active: Optional[datetime] = None


class RoleEvaluation(BaseModel):
    """Represents an evaluation of a role's effectiveness and risk."""
    role_id: UUID
    risk_score: float
    coverage_score: float
    complexity_score: float
    compliance_score: float
    recommendations: List[str] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)


class RoleRecommendation(BaseModel):
    """Represents a recommendation for role changes."""
    role_id: UUID
    action: str  # e.g., "merge", "split", "modify"
    reason: str
    suggested_changes: Dict[str, Union[str, List[str]]]
    confidence_score: float
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AccessLog(BaseModel):
    """Represents a log of access attempts."""
    id: UUID = Field(default_factory=uuid4)
    user_id: UUID
    resource_id: UUID
    permission_id: UUID
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    success: bool
    context: Dict[str, str] = Field(default_factory=dict) 