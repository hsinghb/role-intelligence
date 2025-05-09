from typing import Dict, List, Optional
from uuid import UUID

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from role_intelligence.models import (
    AccessLog,
    Permission,
    Resource,
    Role,
    RoleEvaluation,
    RoleRecommendation,
    User,
)
from role_intelligence.service import RoleIntelligenceService

app = FastAPI(
    title="Role Intelligence Service",
    description="An intelligent role engine that leverages AI and LLMs to revolutionize IAM",
    version="1.0.0",
)

# Initialize the service
service = RoleIntelligenceService()


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
async def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"} 