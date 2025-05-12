import asyncio
import pytest
from datetime import datetime
from uuid import UUID, uuid4
from role_intelligence.models import (
    User,
    Role,
    Permission,
    Resource,
    AccessLog,
    SecurityIncident,
    ResourceType,
    PermissionLevel,
    RiskLevel
)
from role_intelligence.authorization_risks import (
    AuthorizationRiskAnalyzer,
    AuthorizationRiskType,
    AuthorizationRiskLevel
)

# Test data fixtures
@pytest.fixture
def test_roles():
    admin_role_id = uuid4()
    finance_role_id = uuid4()
    hr_role_id = uuid4()
    return [
        Role(
            id=admin_role_id,
            name="admin",
            description="System administrator with full access",
            permissions=set()  # Will be updated with permission IDs
        ),
        Role(
            id=finance_role_id,
            name="finance",
            description="Finance department role",
            permissions=set()  # Will be updated with permission IDs
        ),
        Role(
            id=hr_role_id,
            name="hr",
            description="Human Resources role",
            permissions=set()  # Will be updated with permission IDs
        )
    ]

@pytest.fixture
def test_permissions(test_roles):
    admin_role_id = test_roles[0].id
    finance_role_id = test_roles[1].id
    hr_role_id = test_roles[2].id
    
    permissions = [
        Permission(
            id=uuid4(),
            resource_id=uuid4(),
            level=PermissionLevel.ADMIN,
            conditions={},
            metadata={"role_id": str(admin_role_id)}
        ),
        Permission(
            id=uuid4(),
            resource_id=uuid4(),
            level=PermissionLevel.READ,
            conditions={},
            metadata={"role_id": str(finance_role_id)}
        ),
        Permission(
            id=uuid4(),
            resource_id=uuid4(),
            level=PermissionLevel.WRITE,
            conditions={},
            metadata={"role_id": str(hr_role_id)}
        )
    ]
    
    # Update role permissions
    test_roles[0].permissions.add(permissions[0].id)
    test_roles[1].permissions.add(permissions[1].id)
    test_roles[2].permissions.add(permissions[2].id)
    
    return permissions

@pytest.fixture
def test_users(test_roles):
    admin_role_id = test_roles[0].id
    finance_role_id = test_roles[1].id
    hr_role_id = test_roles[2].id
    
    return [
        User(
            id=uuid4(),
            username="admin",
            email="admin@company.com",
            roles={admin_role_id},
            metadata={}
        ),
        User(
            id=uuid4(),
            username="finance_user",
            email="finance@company.com",
            roles={finance_role_id},
            metadata={}
        ),
        User(
            id=uuid4(),
            username="hr_user",
            email="hr@company.com",
            roles={hr_role_id},
            metadata={}
        )
    ]

@pytest.fixture
def test_resources():
    return [
        Resource(
            id=uuid4(),
            name="financial_system",
            type=ResourceType.SERVICE,
            description="Financial system",
            sensitivity_level=RiskLevel.HIGH
        ),
        Resource(
            id=uuid4(),
            name="hr_system",
            type=ResourceType.SERVICE,
            description="HR system",
            sensitivity_level=RiskLevel.MEDIUM
        )
    ]

@pytest.fixture
def test_access_logs(test_users, test_resources, test_permissions):
    return [
        AccessLog(
            id=uuid4(),
            user_id=test_users[0].id,
            resource_id=test_resources[0].id,
            permission_id=test_permissions[0].id,
            timestamp=datetime.utcnow(),
            success=True,
            context={}
        ),
        AccessLog(
            id=uuid4(),
            user_id=test_users[1].id,
            resource_id=test_resources[0].id,
            permission_id=test_permissions[1].id,
            timestamp=datetime.utcnow(),
            success=True,
            context={}
        )
    ]

@pytest.fixture
def test_incidents(tenant_id, test_users):
    return [
        SecurityIncident(
            id=str(uuid4()),
            tenant_id=tenant_id,
            timestamp=datetime.utcnow(),
            incident_type="unauthorized_access",
            description="Multiple failed login attempts",
            severity="high",
            affected_entities=[{"type": "user", "id": str(test_users[1].id)}],
            status="open"
        )
    ]

@pytest.mark.asyncio
async def test_authorization_risk_analysis(
    openai_api_key,
    tenant_id,
    test_users,
    test_roles,
    test_permissions,
    test_resources,
    test_access_logs,
    test_incidents
):
    """Test the authorization risk analysis functionality."""
    # Initialize the analyzer
    analyzer = AuthorizationRiskAnalyzer(openai_api_key=openai_api_key)
    
    # Analyze risks
    risks = await analyzer.analyze_organization_risks(
        tenant_id=tenant_id,
        users=test_users,
        roles=test_roles,
        permissions=test_permissions,
        resources=test_resources,
        access_logs=test_access_logs,
        incidents=test_incidents
    )
    
    # Verify results
    assert len(risks) > 0, "No risks were identified"
    
    # Check risk types
    risk_types = {risk.risk_type for risk in risks}
    assert AuthorizationRiskType.EXCESSIVE_ACCESS in risk_types, "Excessive access analysis not performed"
    assert AuthorizationRiskType.PRIVILEGE_ESCALATION in risk_types, "Privilege escalation analysis not performed"
    assert AuthorizationRiskType.SEGREGATION_OF_DUTIES in risk_types, "Segregation of duties analysis not performed"
    
    # Check risk levels
    for risk in risks:
        assert risk.risk_level in AuthorizationRiskLevel.__members__.values(), f"Invalid risk level: {risk.risk_level}"
        assert risk.affected_entities, "Risk has no affected entities"
        assert risk.recommendations, "Risk has no recommendations"

@pytest.mark.asyncio
async def test_real_time_monitoring(
    openai_api_key,
    tenant_id,
    test_users,
    test_roles,
    test_permissions,
    test_resources,
    test_access_logs,
    test_incidents
):
    """Test the real-time monitoring functionality."""
    analyzer = AuthorizationRiskAnalyzer(openai_api_key=openai_api_key)
    
    # Start monitoring
    monitoring_task = asyncio.create_task(
        analyzer.monitor_authorization_risks(
            tenant_id=tenant_id,
            users=test_users,
            roles=test_roles,
            permissions=test_permissions,
            resources=test_resources,
            access_logs=test_access_logs,
            incidents=test_incidents,
            interval_seconds=5  # Short interval for testing
        )
    )
    
    # Wait for a few monitoring cycles
    await asyncio.sleep(15)
    
    # Cancel monitoring
    monitoring_task.cancel()
    try:
        await monitoring_task
    except asyncio.CancelledError:
        pass

if __name__ == "__main__":
    # Run tests
    asyncio.run(test_authorization_risk_analysis("your-api-key", "test_tenant", test_users(), test_roles(), test_permissions(), test_resources(), test_access_logs(), test_incidents("test_tenant")))
    asyncio.run(test_real_time_monitoring("your-api-key", "test_tenant", test_users(), test_roles(), test_permissions(), test_resources(), test_access_logs(), test_incidents("test_tenant"))) 