from datetime import datetime, timedelta
from uuid import uuid4

from role_intelligence.models import (
    AccessLog,
    Permission,
    PermissionLevel,
    Resource,
    ResourceType,
    RiskLevel,
    Role,
    User,
)
from role_intelligence.service import RoleIntelligenceService


def create_sample_data():
    """Create sample data for demonstration."""
    # Create resources
    resources = [
        Resource(
            id=uuid4(),
            name="customer_database",
            type=ResourceType.DATABASE,
            description="Customer information database",
            sensitivity_level=RiskLevel.HIGH,
        ),
        Resource(
            id=uuid4(),
            name="api_gateway",
            type=ResourceType.API,
            description="API Gateway service",
            sensitivity_level=RiskLevel.MEDIUM,
        ),
        Resource(
            id=uuid4(),
            name="log_files",
            type=ResourceType.FILE,
            description="Application log files",
            sensitivity_level=RiskLevel.LOW,
        ),
    ]

    # Create permissions
    permissions = []
    for resource in resources:
        for level in PermissionLevel:
            permissions.append(
                Permission(
                    id=uuid4(),
                    resource_id=resource.id,
                    level=level,
                )
            )

    # Create roles
    admin_role = Role(
        id=uuid4(),
        name="admin",
        description="System administrator role",
        permissions={p.id for p in permissions if p.level == PermissionLevel.ADMIN},
    )

    developer_role = Role(
        id=uuid4(),
        name="developer",
        description="Application developer role",
        permissions={
            p.id
            for p in permissions
            if p.level in {PermissionLevel.READ, PermissionLevel.WRITE}
            and p.resource_id != resources[0].id  # No access to customer database
        },
    )

    viewer_role = Role(
        id=uuid4(),
        name="viewer",
        description="Read-only access role",
        permissions={p.id for p in permissions if p.level == PermissionLevel.READ},
    )

    roles = [admin_role, developer_role, viewer_role]

    # Create users
    users = [
        User(
            id=uuid4(),
            username="admin_user",
            email="admin@example.com",
            roles={admin_role.id},
        ),
        User(
            id=uuid4(),
            username="dev_user",
            email="dev@example.com",
            roles={developer_role.id},
        ),
        User(
            id=uuid4(),
            username="viewer_user",
            email="viewer@example.com",
            roles={viewer_role.id},
        ),
        User(
            id=uuid4(),
            username="power_user",
            email="power@example.com",
            roles={developer_role.id, viewer_role.id},
        ),
    ]

    # Create access logs
    access_logs = []
    now = datetime.utcnow()
    
    # Generate some access logs for each user
    for user in users:
        for role_id in user.roles:
            role = next(r for r in roles if r.id == role_id)
            for perm_id in role.permissions:
                # Generate 0-5 access attempts for each permission
                for _ in range(5):
                    access_logs.append(
                        AccessLog(
                            id=uuid4(),
                            user_id=user.id,
                            resource_id=next(
                                p.resource_id for p in permissions if p.id == perm_id
                            ),
                            permission_id=perm_id,
                            timestamp=now - timedelta(days=1),
                            success=True,
                        )
                    )

    return resources, permissions, roles, users, access_logs


def main():
    """Demonstrate basic usage of the Role Intelligence Service."""
    # Create sample data
    resources, permissions, roles, users, access_logs = create_sample_data()

    # Initialize the service
    service = RoleIntelligenceService()

    print("\n=== Role Intelligence Service Demo ===\n")

    # Evaluate a single role
    print("Evaluating admin role...")
    admin_evaluation = service.evaluate_role(
        role=roles[0],  # admin role
        resources=resources,
        permissions=permissions,
        users=users,
        access_logs=access_logs,
    )
    print(f"Admin role risk score: {admin_evaluation.risk_score:.2f}")
    print(f"Recommendations: {admin_evaluation.recommendations}\n")

    # Analyze all roles
    print("Analyzing all roles...")
    evaluations, recommendations = service.analyze_roles(
        roles=roles,
        users=users,
        resources=resources,
        permissions=permissions,
        access_logs=access_logs,
    )
    print(f"Found {len(recommendations)} recommendations")
    for rec in recommendations[:3]:  # Show top 3 recommendations
        print(f"- {rec.action}: {rec.reason} (confidence: {rec.confidence_score:.2f})")
    print()

    # Get role insights
    print("Getting insights for developer role...")
    dev_insights = service.get_role_insights(
        role=roles[1],  # developer role
        users=users,
        resources=resources,
        permissions=permissions,
        access_logs=access_logs,
    )
    print(f"Active users: {dev_insights['user_statistics']['active_users']}")
    print(f"Success rate: {dev_insights['usage_statistics']['success_rate']:.2%}")
    print()

    # Get system insights
    print("Getting system-wide insights...")
    system_insights = service.get_system_insights(
        roles=roles,
        users=users,
        resources=resources,
        permissions=permissions,
        access_logs=access_logs,
    )
    print("System statistics:")
    print(f"- Total roles: {system_insights['system_statistics']['total_roles']}")
    print(f"- Total users: {system_insights['system_statistics']['total_users']}")
    print(f"- High risk roles: {system_insights['role_statistics']['high_risk_roles']}")
    print("\nRisk distribution:")
    for level, ratio in system_insights["risk_distribution"].items():
        print(f"- {level}: {ratio:.2%}")


if __name__ == "__main__":
    main() 