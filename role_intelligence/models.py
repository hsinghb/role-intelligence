from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Union, Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, ConfigDict


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


class RiskType(str, Enum):
    """Types of risks that can be identified."""
    EXCESSIVE_ACCESS = "excessive_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SEGREGATION_OF_DUTIES = "segregation_of_duties"
    SHADOW_ACCESS = "shadow_access"
    COMPLIANCE = "compliance"
    SECURITY = "security"
    OPERATIONAL = "operational"
    BUSINESS = "business"


class Resource(BaseModel):
    """Represents a resource that can be accessed."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    id: UUID = Field(default_factory=uuid4)
    name: str
    type: ResourceType
    description: Optional[str] = None
    sensitivity_level: RiskLevel = RiskLevel.LOW
    metadata: Dict[str, str] = Field(default_factory=dict)


class Permission(BaseModel):
    """Represents a permission that can be granted to a role."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    id: UUID = Field(default_factory=uuid4)
    resource_id: UUID
    name: str = ""
    description: str = ""
    level: PermissionLevel
    conditions: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Role(BaseModel):
    """Represents a role in the system."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
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
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    id: UUID = Field(default_factory=uuid4)
    username: str
    email: str
    roles: Set[UUID] = Field(default_factory=set)  # Set of role IDs
    metadata: Dict[str, str] = Field(default_factory=dict)
    last_active: Optional[datetime] = None


class RoleEvaluation(BaseModel):
    """Represents an evaluation of a role's effectiveness and risk."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    role_id: UUID
    risk_score: float
    coverage_score: float
    complexity_score: float
    compliance_score: float
    recommendations: List[str] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)


class RoleRecommendation(BaseModel):
    """Represents a recommendation for role changes."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    role_id: UUID
    action: str  # e.g., "merge", "split", "modify"
    reason: str
    suggested_changes: Dict[str, Union[str, List[str]]]
    confidence_score: float
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AccessLog(BaseModel):
    """Represents a log of access attempts."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    id: UUID = Field(default_factory=uuid4)
    user_id: UUID
    resource_id: UUID
    permission_id: UUID
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    success: bool
    context: Dict[str, str] = Field(default_factory=dict)


class ComplianceViolation(BaseModel):
    """Model for compliance violations."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    timestamp: datetime
    violation_type: str
    description: str
    severity: str
    affected_entities: List[Dict[str, Any]]
    compliance_standard: str
    status: str = "open"
    resolution: Optional[str] = None
    resolved_at: Optional[datetime] = None


class SecurityIncident(BaseModel):
    """Model for security incidents."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    timestamp: datetime
    incident_type: str
    description: str
    severity: str
    affected_entities: List[Dict[str, Any]]
    status: str = "open"
    resolution: Optional[str] = None
    resolved_at: Optional[datetime] = None


class RiskAssessment(BaseModel):
    """Model for risk assessments."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    timestamp: datetime
    risk_type: str
    risk_level: str
    description: str
    affected_entities: List[Dict[str, Any]]
    recommendations: List[str]
    status: str = "open"
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    resolution: Optional[str] = None
    resolved_at: Optional[datetime] = None


class RiskMitigation(BaseModel):
    """Model for risk mitigation strategies."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    id: str = Field(default_factory=lambda: str(uuid4()))
    assessment_id: str
    timestamp: datetime
    strategy: str
    priority: int
    status: str = "pending"
    assigned_to: Optional[str] = None
    completed_at: Optional[datetime] = None
    effectiveness: Optional[float] = None 