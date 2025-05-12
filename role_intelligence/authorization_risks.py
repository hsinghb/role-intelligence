from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, ConfigDict
from enum import Enum
import asyncio
from uuid import uuid4
from openai import AsyncOpenAI
from langchain.prompts import PromptTemplate, ChatPromptTemplate
from langchain.chains import LLMChain
from langchain_openai import ChatOpenAI

from .models import (
    Role,
    User,
    Resource,
    Permission,
    AccessLog,
    SecurityIncident
)
from role_intelligence.models import RiskLevel

class AuthorizationRiskType(str, Enum):
    """Types of authorization risks."""
    EXCESSIVE_ACCESS = "excessive_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SEGREGATION_OF_DUTIES = "segregation_of_duties"
    COMPLIANCE_VIOLATION = "compliance_violation"
    SHADOW_ACCESS = "shadow_access"
    ORPHANED_ACCESS = "orphaned_access"
    DORMANT_ACCESS = "dormant_access"
    UNAUTHORIZED_CHANGES = "unauthorized_changes"
    WEAK_CONTROLS = "weak_controls"
    SYSTEM_INTEGRATION = "system_integration"
    STALE_ACCESS = "stale_access"
    UNAUTHORIZED_DELEGATION = "unauthorized_delegation"
    OVERPRIVILEGED_SERVICE = "overprivileged_service"
    UNAUTHORIZED_SHARING = "unauthorized_sharing"

class AuthorizationRiskLevel(str, Enum):
    """Levels of authorization risk severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AuthorizationRisk(BaseModel):
    """Model for authorization risk assessment."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    id: str
    tenant_id: str
    timestamp: datetime
    risk_type: AuthorizationRiskType
    risk_level: AuthorizationRiskLevel
    title: str
    description: str
    affected_entities: List[Dict[str, Any]] = Field(default_factory=list)
    root_cause: Optional[str] = None
    impact: Optional[str] = None
    likelihood: Optional[str] = None
    detection_method: Optional[str] = None
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    status: str = "open"
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    resolution: Optional[str] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class AuthorizationRiskAnalyzer:
    """Analyzer for organization-wide authorization risks."""
    
    def __init__(self, openai_api_key: str):
        self.openai_client = AsyncOpenAI(api_key=openai_api_key)
        self.llm = ChatOpenAI(openai_api_key=openai_api_key, temperature=0.7, model_name="gpt-4")
        self.risk_prompts = {
            "excessive_access": PromptTemplate(
                input_variables=["users", "roles", "permissions", "access_logs"],
                template="""
                Analyze the following data for excessive access patterns:
                
                Users and their roles: {users}
                Role definitions: {roles}
                Permissions: {permissions}
                Access logs: {access_logs}
                
                Identify:
                1. Users with excessive permissions
                2. Roles with overlapping responsibilities
                3. Unnecessary access patterns
                4. Potential privilege abuse
                
                Provide detailed analysis and recommendations.
                """
            ),
            "privilege_escalation": PromptTemplate(
                input_variables=["users", "roles", "access_logs", "incidents"],
                template="""
                Analyze the following data for privilege escalation risks:
                
                Users and their roles: {users}
                Role definitions: {roles}
                Access logs: {access_logs}
                Security incidents: {incidents}
                
                Identify:
                1. Potential privilege escalation paths
                2. Weak role hierarchies
                3. Suspicious access patterns
                4. Historical escalation attempts
                
                Provide detailed analysis and recommendations.
                """
            ),
            "segregation_of_duties": PromptTemplate(
                input_variables=["roles", "permissions", "users"],
                template="""
                Analyze the following data for segregation of duties violations:
                
                Roles: {roles}
                Permissions: {permissions}
                User assignments: {users}
                
                Identify:
                1. Conflicting role assignments
                2. Separation of duties violations
                3. Control weaknesses
                4. Compliance gaps
                
                Provide detailed analysis and recommendations.
                """
            ),
            "shadow_access": PromptTemplate(
                input_variables=["users", "access_logs", "resources"],
                template="""
                Analyze the following data for shadow access:
                
                Users: {users}
                Access logs: {access_logs}
                Resources: {resources}
                
                Identify:
                1. Unauthorized access paths
                2. Bypassed controls
                3. Hidden permissions
                4. Shadow IT usage
                
                Provide detailed analysis and recommendations.
                """
            )
        }

    async def analyze_organization_risks(
        self,
        tenant_id: str,
        users: List[User],
        roles: List[Role],
        permissions: List[Permission],
        resources: List[Resource],
        access_logs: List[AccessLog],
        incidents: List[SecurityIncident]
    ) -> List[AuthorizationRisk]:
        """Analyze organization-wide authorization risks."""
        risks = []
        
        # Analyze excessive access
        excessive_access = await self._analyze_excessive_access(
            users=users,
            roles=roles,
            permissions=permissions,
            access_logs=access_logs,
            tenant_id=tenant_id
        )
        risks.extend(excessive_access)
        
        # Analyze privilege escalation
        privilege_escalation = await self._analyze_privilege_escalation(
            users=users,
            roles=roles,
            access_logs=access_logs,
            incidents=incidents,
            tenant_id=tenant_id
        )
        risks.extend(privilege_escalation)
        
        # Analyze segregation of duties
        segregation = await self._analyze_segregation_of_duties(
            roles=roles,
            permissions=permissions,
            users=users,
            tenant_id=tenant_id
        )
        risks.extend(segregation)
        
        # Analyze shadow access
        shadow_access = await self._analyze_shadow_access(
            users=users,
            access_logs=access_logs,
            resources=resources,
            tenant_id=tenant_id
        )
        risks.extend(shadow_access)
        
        return risks

    async def _analyze_excessive_access(
        self,
        users: List[User],
        roles: List[Role],
        permissions: List[Permission],
        access_logs: List[AccessLog],
        tenant_id: str
    ) -> List[AuthorizationRisk]:
        """Analyze excessive access patterns."""
        chain = LLMChain(llm=self.llm, prompt=self.risk_prompts["excessive_access"])
        
        # Prepare data for analysis
        users_data = [f"{u.username}: {u.roles}" for u in users]
        roles_data = [f"{r.name}: {r.description}" for r in roles]
        perms_data = [f"{p.name}: {p.description}" for p in permissions]
        logs_data = [f"{log.timestamp}: {log.user_id} -> {log.resource_id}" for log in access_logs]
        
        # Get AI analysis
        result = await chain.arun(
            users=users_data,
            roles=roles_data,
            permissions=perms_data,
            access_logs=logs_data
        )
        
        # Process and structure the AI response
        return self._process_risk_analysis(
            result,
            AuthorizationRiskType.EXCESSIVE_ACCESS,
            tenant_id=tenant_id
        )

    async def _analyze_privilege_escalation(
        self,
        users: List[User],
        roles: List[Role],
        access_logs: List[AccessLog],
        incidents: List[SecurityIncident],
        tenant_id: str
    ) -> List[AuthorizationRisk]:
        """Analyze privilege escalation risks."""
        chain = LLMChain(llm=self.llm, prompt=self.risk_prompts["privilege_escalation"])
        
        # Prepare data for analysis
        users_data = [f"{u.username}: {u.roles}" for u in users]
        roles_data = [f"{r.name}: {r.description}" for r in roles]
        logs_data = [f"{log.timestamp}: {log.user_id} -> {log.resource_id}" for log in access_logs]
        incidents_data = [f"{inc.timestamp}: {inc.description}" for inc in incidents]
        
        # Get AI analysis
        result = await chain.arun(
            users=users_data,
            roles=roles_data,
            access_logs=logs_data,
            incidents=incidents_data
        )
        
        # Process and structure the AI response
        return self._process_risk_analysis(
            result,
            AuthorizationRiskType.PRIVILEGE_ESCALATION,
            tenant_id=tenant_id
        )

    async def _analyze_segregation_of_duties(
        self,
        roles: List[Role],
        permissions: List[Permission],
        users: List[User],
        tenant_id: str
    ) -> List[AuthorizationRisk]:
        """Analyze segregation of duties violations."""
        chain = LLMChain(llm=self.llm, prompt=self.risk_prompts["segregation_of_duties"])
        
        # Prepare data for analysis
        roles_data = [f"{r.name}: {r.description}" for r in roles]
        perms_data = [f"{p.name}: {p.description}" for p in permissions]
        users_data = [f"{u.username}: {u.roles}" for u in users]
        
        # Get AI analysis
        result = await chain.arun(
            roles=roles_data,
            permissions=perms_data,
            users=users_data
        )
        
        # Process and structure the AI response
        return self._process_risk_analysis(
            result,
            AuthorizationRiskType.SEGREGATION_OF_DUTIES,
            tenant_id=tenant_id
        )

    async def _analyze_shadow_access(
        self,
        users: List[User],
        access_logs: List[AccessLog],
        resources: List[Resource],
        tenant_id: str
    ) -> List[AuthorizationRisk]:
        """Analyze shadow access patterns."""
        chain = LLMChain(llm=self.llm, prompt=self.risk_prompts["shadow_access"])
        
        # Prepare data for analysis
        users_data = [f"{u.username}: {u.roles}" for u in users]
        logs_data = [f"{log.timestamp}: {log.user_id} -> {log.resource_id}" for log in access_logs]
        resources_data = [f"{r.name}: {r.type}" for r in resources]
        
        # Get AI analysis
        result = await chain.arun(
            users=users_data,
            access_logs=logs_data,
            resources=resources_data
        )
        
        # Process and structure the AI response
        return self._process_risk_analysis(
            result,
            AuthorizationRiskType.SHADOW_ACCESS,
            tenant_id=tenant_id
        )

    def _process_risk_analysis(
        self,
        ai_response: str,
        risk_type: AuthorizationRiskType,
        tenant_id: str = "default"
    ) -> List[AuthorizationRisk]:
        """Process AI response into structured risk assessments."""
        # TODO: Implement sophisticated parsing of AI response
        # For now, return a simple structured assessment
        return [
            AuthorizationRisk(
                id=str(uuid4()),
                tenant_id=tenant_id,
                timestamp=datetime.utcnow(),
                risk_type=risk_type,
                risk_level=AuthorizationRiskLevel.HIGH,
                title=f"{risk_type.value.replace('_', ' ').title()} Risk",
                description=ai_response,
                affected_entities=[],
                root_cause="To be determined",
                impact="To be determined",
                likelihood="high",
                detection_method="AI Analysis",
                evidence=[],
                recommendations=[]
            )
        ]

    async def monitor_authorization_risks(
        self,
        tenant_id: str,
        users: List[User],
        roles: List[Role],
        permissions: List[Permission],
        resources: List[Resource],
        access_logs: List[AccessLog],
        incidents: List[SecurityIncident],
        interval_seconds: int = 300
    ) -> None:
        """Continuously monitor for authorization risks."""
        while True:
            try:
                # Analyze current state
                risks = await self.analyze_organization_risks(
                    tenant_id=tenant_id,
                    users=users,
                    roles=roles,
                    permissions=permissions,
                    resources=resources,
                    access_logs=access_logs,
                    incidents=incidents
                )
                
                # Process high-risk findings
                for risk in risks:
                    if risk.risk_level in [AuthorizationRiskLevel.HIGH, AuthorizationRiskLevel.CRITICAL]:
                        # TODO: Implement notification system
                        # TODO: Implement automated response system
                        pass
                
                # Wait for next interval
                await asyncio.sleep(interval_seconds)
                
            except Exception as e:
                # TODO: Implement proper error handling and logging
                print(f"Error in authorization risk monitoring: {e}")
                await asyncio.sleep(60)  # Wait before retrying 