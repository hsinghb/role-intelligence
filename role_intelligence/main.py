from typing import Dict, List, Optional
from uuid import UUID

from fastapi import FastAPI, HTTPException, Depends, Path
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from datetime import datetime

from role_intelligence.models import (
    AccessLog,
    Permission,
    Resource,
    Role,
    RoleEvaluation,
    RoleRecommendation,
    User,
    ComplianceViolation,
    SecurityIncident,
    RiskAssessment,
    RiskMitigation
)
from role_intelligence.service import RoleIntelligenceService
from role_intelligence.risk_monitoring import RealTimeRiskMonitor
from role_intelligence.notifications import NotificationManager
from role_intelligence.saas_config import SaaSConfig, SaaSConfigManager
from role_intelligence.authorization_risks import (
    AuthorizationRiskAnalyzer,
    AuthorizationRisk,
    AuthorizationRiskType,
    AuthorizationRiskLevel
)

app = FastAPI(
    title="Role Intelligence Service",
    description="An intelligent role engine that leverages AI and LLMs to revolutionize IAM",
    version="1.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the service
service = RoleIntelligenceService()

# Initialize managers
config_manager = SaaSConfigManager()
risk_monitors: Dict[str, RealTimeRiskMonitor] = {}
notification_managers: Dict[str, NotificationManager] = {}
auth_risk_analyzers: Dict[str, AuthorizationRiskAnalyzer] = {}

async def get_tenant_config(tenant_id: str = Path(...)) -> SaaSConfig:
    """Get tenant configuration."""
    config = config_manager.get_config(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")
    return config

async def get_risk_monitor(tenant_id: str = Path(...)) -> RealTimeRiskMonitor:
    """Get risk monitor for tenant."""
    if tenant_id not in risk_monitors:
        config = await get_tenant_config(tenant_id)
        risk_monitors[tenant_id] = RealTimeRiskMonitor(config)
    return risk_monitors[tenant_id]

async def get_notification_manager(tenant_id: str = Path(...)) -> NotificationManager:
    """Get notification manager for tenant."""
    if tenant_id not in notification_managers:
        notification_managers[tenant_id] = NotificationManager()
    return notification_managers[tenant_id]

async def get_auth_risk_analyzer(tenant_id: str = Path(...)) -> AuthorizationRiskAnalyzer:
    """Get authorization risk analyzer for tenant."""
    if tenant_id not in auth_risk_analyzers:
        config = await get_tenant_config(tenant_id)
        auth_risk_analyzers[tenant_id] = AuthorizationRiskAnalyzer(config.ai.openai_api_key)
    return auth_risk_analyzers[tenant_id]

class RoleInsightsResponse(BaseModel):
    """Response model for role insights."""
    role_id: str
    role_name: str
    evaluation: Dict
    usage_statistics: Dict
    permission_usage: Dict
    user_statistics: Dict
    risk_indicators: Dict


class SystemInsightsResponse(BaseModel):
    """Response model for system insights."""
    system_statistics: Dict
    role_statistics: Dict
    recommendation_statistics: Dict
    user_role_statistics: Dict
    risk_distribution: Dict
    top_recommendations: List[Dict]


@app.post("/roles/evaluate", response_model=RoleEvaluation)
async def evaluate_role(
    role: Role,
    resources: List[Resource],
    permissions: List[Permission],
    users: List[User],
    access_logs: List[AccessLog],
    compliance_violations: int = 0,
    historical_incidents: int = 0,
) -> RoleEvaluation:
    """Evaluate a single role for risks and optimization opportunities."""
    try:
        return service.evaluate_role(
            role=role,
            resources=resources,
            permissions=permissions,
            users=users,
            access_logs=access_logs,
            compliance_violations=compliance_violations,
            historical_incidents=historical_incidents,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/roles/analyze")
async def analyze_roles(
    roles: List[Role],
    users: List[User],
    resources: List[Resource],
    permissions: List[Permission],
    access_logs: List[AccessLog],
) -> Dict[str, List]:
    """Analyze all roles and generate evaluations and recommendations."""
    try:
        evaluations, recommendations = service.analyze_roles(
            roles=roles,
            users=users,
            resources=resources,
            permissions=permissions,
            access_logs=access_logs,
        )
        return {
            "evaluations": [e.dict() for e in evaluations],
            "recommendations": [r.dict() for r in recommendations],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/roles/{role_id}/insights", response_model=RoleInsightsResponse)
async def get_role_insights(
    role_id: UUID,
    users: List[User],
    resources: List[Resource],
    permissions: List[Permission],
    access_logs: List[AccessLog],
) -> Dict:
    """Get detailed insights about a specific role."""
    try:
        # Find the role
        role = next((r for r in roles if r.id == role_id), None)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")

        return service.get_role_insights(
            role=role,
            users=users,
            resources=resources,
            permissions=permissions,
            access_logs=access_logs,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/system/insights", response_model=SystemInsightsResponse)
async def get_system_insights(
    roles: List[Role],
    users: List[User],
    resources: List[Resource],
    permissions: List[Permission],
    access_logs: List[AccessLog],
) -> Dict:
    """Get system-wide insights about roles and access patterns."""
    try:
        return service.get_system_insights(
            roles=roles,
            users=users,
            resources=resources,
            permissions=permissions,
            access_logs=access_logs,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/tenants")
async def create_tenant(config: SaaSConfig):
    """Create a new tenant."""
    config_manager.create_config(config)
    return {"status": "success", "tenant_id": config.tenant.tenant_id}


@app.get("/tenants/{tenant_id}")
async def get_tenant(tenant_id: str = Path(...)):
    """Get tenant configuration."""
    config = config_manager.get_config(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return config


@app.get("/tenants/{tenant_id}/stats")
async def get_tenant_stats(tenant_id: str = Path(...)):
    """Get tenant statistics."""
    stats = config_manager.get_tenant_stats(tenant_id)
    if not stats:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return stats


@app.post("/tenants/{tenant_id}/analyze")
async def analyze_risks(
    tenant_id: str = Path(...),
    risk_monitor: RealTimeRiskMonitor = Depends(get_risk_monitor),
    notification_manager: NotificationManager = Depends(get_notification_manager)
):
    """Analyze risks for a tenant."""
    # Get tenant data
    users = await service.get_users()
    roles = await service.get_roles()
    permissions = await service.get_permissions()
    resources = await service.get_resources()
    access_logs = await service.get_access_logs()
    incidents = await service.get_security_incidents()
    
    # Analyze risks
    risks = await risk_monitor.analyze_organization_risks(
        users=users,
        roles=roles,
        permissions=permissions,
        resources=resources,
        access_logs=access_logs,
        incidents=incidents
    )
    
    # Notify about high-risk findings
    for risk in risks:
        if risk.risk_level in ["HIGH", "CRITICAL"]:
            notification_manager.notify_risk_assessment(risk)
    
    return risks


@app.post("/tenants/{tenant_id}/mitigate")
async def mitigate_risk(
    risk_id: str,
    strategy: str,
    tenant_id: str = Path(...),
    risk_monitor: RealTimeRiskMonitor = Depends(get_risk_monitor),
    notification_manager: NotificationManager = Depends(get_notification_manager)
):
    """Mitigate a specific risk."""
    # TODO: Implement risk mitigation
    return {"status": "success"}


@app.post("/tenants/{tenant_id}/compliance/check")
async def check_compliance(
    tenant_id: str = Path(...),
    risk_monitor: RealTimeRiskMonitor = Depends(get_risk_monitor)
):
    """Check compliance requirements."""
    # TODO: Implement compliance checking
    return {"status": "success"}


@app.post("/tenants/{tenant_id}/monitoring/start")
async def start_monitoring(
    tenant_id: str = Path(...),
    risk_monitor: RealTimeRiskMonitor = Depends(get_risk_monitor)
):
    """Start real-time risk monitoring."""
    await risk_monitor.start_monitoring()
    return {"status": "success"}


@app.post("/tenants/{tenant_id}/monitoring/stop")
async def stop_monitoring(
    tenant_id: str = Path(...),
    risk_monitor: RealTimeRiskMonitor = Depends(get_risk_monitor)
):
    """Stop real-time risk monitoring."""
    await risk_monitor.stop_monitoring()
    return {"status": "success"}


@app.post("/tenants/{tenant_id}/authorization-risks/analyze")
async def analyze_authorization_risks(
    tenant_id: str = Path(...),
    auth_risk_analyzer: AuthorizationRiskAnalyzer = Depends(get_auth_risk_analyzer),
    notification_manager: NotificationManager = Depends(get_notification_manager)
):
    """Analyze organization-wide authorization risks."""
    # Get tenant data
    users = await service.get_users()
    roles = await service.get_roles()
    permissions = await service.get_permissions()
    resources = await service.get_resources()
    access_logs = await service.get_access_logs()
    incidents = await service.get_security_incidents()

    # Analyze risks
    risks = await auth_risk_analyzer.analyze_organization_risks(
        tenant_id=tenant_id,
        users=users,
        roles=roles,
        permissions=permissions,
        resources=resources,
        access_logs=access_logs,
        incidents=incidents
    )

    # Send notifications for high-risk findings
    for risk in risks:
        if risk.risk_level in [AuthorizationRiskLevel.HIGH, AuthorizationRiskLevel.CRITICAL]:
            await notification_manager.notify_risk_assessment(
                tenant_id=tenant_id,
                assessment=risk
            )

    return {"risks": risks}


@app.get("/tenants/{tenant_id}/authorization-risks")
async def get_authorization_risks(
    tenant_id: str = Path(...),
    risk_type: Optional[AuthorizationRiskType] = None,
    risk_level: Optional[AuthorizationRiskLevel] = None,
    status: Optional[str] = None
):
    """Get authorization risks for a tenant with optional filtering."""
    # TODO: Implement risk storage and retrieval
    return {"message": "Not implemented yet"}


@app.post("/tenants/{tenant_id}/authorization-risks/monitoring/start")
async def start_auth_risk_monitoring(
    tenant_id: str = Path(...),
    auth_risk_analyzer: AuthorizationRiskAnalyzer = Depends(get_auth_risk_analyzer),
    notification_manager: NotificationManager = Depends(get_notification_manager)
):
    """Start real-time authorization risk monitoring for a tenant."""
    # Get tenant data
    users = await service.get_users()
    roles = await service.get_roles()
    permissions = await service.get_permissions()
    resources = await service.get_resources()
    access_logs = await service.get_access_logs()
    incidents = await service.get_security_incidents()

    # Start monitoring in background
    asyncio.create_task(
        auth_risk_analyzer.monitor_authorization_risks(
            tenant_id=tenant_id,
            users=users,
            roles=roles,
            permissions=permissions,
            resources=resources,
            access_logs=access_logs,
            incidents=incidents
        )
    )
    
    return {"status": "success", "message": "Authorization risk monitoring started"}


@app.post("/tenants/{tenant_id}/authorization-risks/monitoring/stop")
async def stop_auth_risk_monitoring(
    tenant_id: str = Path(...)
):
    """Stop real-time authorization risk monitoring for a tenant."""
    if tenant_id in auth_risk_analyzers:
        # TODO: Implement proper monitoring stop
        del auth_risk_analyzers[tenant_id]
        return {"status": "success", "message": "Authorization risk monitoring stopped"}
    else:
        raise HTTPException(status_code=404, detail="No active authorization risk monitoring found")


# Start monitoring for all tenants on startup
@app.on_event("startup")
async def startup_event():
    """Initialize monitoring for all tenants on startup."""
    for tenant_id in config_manager.list_tenants():
        config = config_manager.get_config(tenant_id)
        if config and config.ai.analysis_frequency == "realtime":
            # Initialize risk monitor
            risk_monitor = RealTimeRiskMonitor(
                openai_api_key=config.ai.model_version
            )
            notification_manager = NotificationManager(config.notifications)
            
            # Start role risk monitoring
            asyncio.create_task(
                risk_monitor.monitor_realtime_risks(
                    roles=await service.get_roles(),
                    users=await service.get_users(),
                    permissions=await service.get_permissions(),
                    access_logs=await service.get_access_logs()
                )
            )
            
            # Initialize and start authorization risk analyzer
            auth_risk_analyzer = AuthorizationRiskAnalyzer(
                openai_api_key=config.ai.model_version
            )
            
            asyncio.create_task(
                auth_risk_analyzer.monitor_authorization_risks(
                    tenant_id=tenant_id,
                    users=await service.get_users(),
                    roles=await service.get_roles(),
                    permissions=await service.get_permissions(),
                    resources=await service.get_resources(),
                    access_logs=await service.get_access_logs(),
                    incidents=await service.get_security_incidents()
                )
            ) 