from datetime import datetime
from typing import Dict, List, Optional, Set
from uuid import UUID, uuid4

from neo4j import AsyncGraphDatabase
from neo4j.exceptions import ServiceUnavailable

from role_intelligence.integrations.base import IAMIntegrationAdapter
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


class Neo4jIntegrationAdapter(IAMIntegrationAdapter):
    """Neo4j integration adapter for the Role Intelligence Service."""

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        database: str = "neo4j",
    ):
        """Initialize the Neo4j integration adapter."""
        self.driver = AsyncGraphDatabase.driver(uri, auth=(username, password))
        self.database = database
        self._role_cache: Dict[str, Role] = {}
        self._user_cache: Dict[str, User] = {}
        self._resource_cache: Dict[str, Resource] = {}
        self._permission_cache: Dict[str, Permission] = {}

    async def get_roles(self) -> List[Role]:
        """Fetch all roles from Neo4j."""
        roles = []
        try:
            async with self.driver.session(database=self.database) as session:
                # Get all roles and their permissions
                result = await session.run(
                    """
                    MATCH (r:Role)
                    OPTIONAL MATCH (r)-[:HAS_PERMISSION]->(p:Permission)
                    RETURN r, collect(p) as permissions
                    """
                )
                async for record in result:
                    role_data = record["r"]
                    permissions = record["permissions"]
                    # Convert Neo4j role to our Role model
                    our_role = Role(
                        id=UUID(role_data["id"]),
                        name=role_data["name"],
                        description=role_data.get("description", ""),
                        permissions={
                            UUID(p["id"]) for p in permissions if p is not None
                        },
                        metadata={
                            "neo4j_id": role_data["id"],
                            "neo4j_created_at": role_data.get("created_at"),
                            "neo4j_updated_at": role_data.get("updated_at"),
                        },
                    )
                    self._role_cache[role_data["id"]] = our_role
                    roles.append(our_role)
        except ServiceUnavailable as error:
            print(f"Error fetching roles: {error}")
        return roles

    async def get_users(self) -> List[User]:
        """Fetch all users from Neo4j."""
        users = []
        try:
            async with self.driver.session(database=self.database) as session:
                # Get all users and their roles
                result = await session.run(
                    """
                    MATCH (u:User)
                    OPTIONAL MATCH (u)-[:HAS_ROLE]->(r:Role)
                    RETURN u, collect(r) as roles
                    """
                )
                async for record in result:
                    user_data = record["u"]
                    roles = record["roles"]
                    # Convert Neo4j user to our User model
                    our_user = User(
                        id=UUID(user_data["id"]),
                        username=user_data["username"],
                        email=user_data.get("email", ""),
                        roles={UUID(r["id"]) for r in roles if r is not None},
                        metadata={
                            "neo4j_id": user_data["id"],
                            "neo4j_created_at": user_data.get("created_at"),
                            "neo4j_updated_at": user_data.get("updated_at"),
                            "neo4j_status": user_data.get("status"),
                        },
                        last_active=datetime.fromisoformat(user_data["last_active"])
                        if "last_active" in user_data
                        else None,
                    )
                    self._user_cache[user_data["id"]] = our_user
                    users.append(our_user)
        except ServiceUnavailable as error:
            print(f"Error fetching users: {error}")
        return users

    async def get_resources(self) -> List[Resource]:
        """Fetch all resources from Neo4j."""
        resources = []
        try:
            async with self.driver.session(database=self.database) as session:
                # Get all resources and their permissions
                result = await session.run(
                    """
                    MATCH (r:Resource)
                    OPTIONAL MATCH (r)-[:HAS_PERMISSION]->(p:Permission)
                    RETURN r, collect(p) as permissions
                    """
                )
                async for record in result:
                    resource_data = record["r"]
                    permissions = record["permissions"]
                    # Convert Neo4j resource to our Resource model
                    our_resource = Resource(
                        id=UUID(resource_data["id"]),
                        name=resource_data["name"],
                        type=ResourceType[resource_data.get("type", "SERVICE")],
                        description=resource_data.get("description", ""),
                        sensitivity_level=RiskLevel[
                            resource_data.get("sensitivity_level", "LOW")
                        ],
                        metadata={
                            "neo4j_id": resource_data["id"],
                            "neo4j_created_at": resource_data.get("created_at"),
                            "neo4j_updated_at": resource_data.get("updated_at"),
                        },
                    )
                    self._resource_cache[resource_data["id"]] = our_resource
                    resources.append(our_resource)
        except ServiceUnavailable as error:
            print(f"Error fetching resources: {error}")
        return resources

    async def get_permissions(self) -> List[Permission]:
        """Fetch all permissions from Neo4j."""
        permissions = []
        try:
            async with self.driver.session(database=self.database) as session:
                # Get all permissions
                result = await session.run(
                    """
                    MATCH (p:Permission)-[:BELONGS_TO]->(r:Resource)
                    RETURN p, r
                    """
                )
                async for record in result:
                    permission_data = record["p"]
                    resource_data = record["r"]
                    # Convert Neo4j permission to our Permission model
                    our_permission = Permission(
                        id=UUID(permission_data["id"]),
                        resource_id=UUID(resource_data["id"]),
                        level=PermissionLevel[
                            permission_data.get("level", "READ")
                        ],
                        conditions=permission_data.get("conditions", {}),
                        metadata={
                            "neo4j_id": permission_data["id"],
                            "neo4j_created_at": permission_data.get("created_at"),
                            "neo4j_updated_at": permission_data.get("updated_at"),
                        },
                    )
                    self._permission_cache[permission_data["id"]] = our_permission
                    permissions.append(our_permission)
        except ServiceUnavailable as error:
            print(f"Error fetching permissions: {error}")
        return permissions

    async def get_access_logs(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> List[AccessLog]:
        """Fetch access logs from Neo4j."""
        logs = []
        try:
            async with self.driver.session(database=self.database) as session:
                # Get access logs with optional time filter
                query = """
                MATCH (l:AccessLog)-[:PERFORMED_BY]->(u:User)
                MATCH (l)-[:ACCESSED]->(r:Resource)
                MATCH (l)-[:USED_PERMISSION]->(p:Permission)
                WHERE $start_time IS NULL OR l.timestamp >= $start_time
                AND $end_time IS NULL OR l.timestamp <= $end_time
                RETURN l, u, r, p
                """
                result = await session.run(
                    query,
                    start_time=start_time.isoformat() if start_time else None,
                    end_time=end_time.isoformat() if end_time else None,
                )
                async for record in result:
                    log_data = record["l"]
                    # Convert Neo4j log to our AccessLog model
                    our_log = AccessLog(
                        id=UUID(log_data["id"]),
                        user_id=UUID(record["u"]["id"]),
                        resource_id=UUID(record["r"]["id"]),
                        permission_id=UUID(record["p"]["id"]),
                        timestamp=datetime.fromisoformat(log_data["timestamp"]),
                        success=log_data.get("success", True),
                        context=log_data.get("context", {}),
                    )
                    logs.append(our_log)
        except ServiceUnavailable as error:
            print(f"Error fetching access logs: {error}")
        return logs

    async def get_user_roles(self, user_id: UUID) -> Set[UUID]:
        """Get roles assigned to a specific user."""
        roles = set()
        try:
            async with self.driver.session(database=self.database) as session:
                result = await session.run(
                    """
                    MATCH (u:User {id: $user_id})-[:HAS_ROLE]->(r:Role)
                    RETURN r
                    """,
                    user_id=str(user_id),
                )
                async for record in result:
                    roles.add(UUID(record["r"]["id"]))
        except ServiceUnavailable as error:
            print(f"Error fetching user roles: {error}")
        return roles

    async def get_role_permissions(self, role_id: UUID) -> Set[UUID]:
        """Get permissions assigned to a specific role."""
        permissions = set()
        try:
            async with self.driver.session(database=self.database) as session:
                result = await session.run(
                    """
                    MATCH (r:Role {id: $role_id})-[:HAS_PERMISSION]->(p:Permission)
                    RETURN p
                    """,
                    role_id=str(role_id),
                )
                async for record in result:
                    permissions.add(UUID(record["p"]["id"]))
        except ServiceUnavailable as error:
            print(f"Error fetching role permissions: {error}")
        return permissions

    async def get_resource_permissions(self, resource_id: UUID) -> Set[UUID]:
        """Get permissions associated with a specific resource."""
        permissions = set()
        try:
            async with self.driver.session(database=self.database) as session:
                result = await session.run(
                    """
                    MATCH (r:Resource {id: $resource_id})-[:HAS_PERMISSION]->(p:Permission)
                    RETURN p
                    """,
                    resource_id=str(resource_id),
                )
                async for record in result:
                    permissions.add(UUID(record["p"]["id"]))
        except ServiceUnavailable as error:
            print(f"Error fetching resource permissions: {error}")
        return permissions

    async def get_compliance_violations(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Get compliance violations from Neo4j."""
        violations = {
            "separation_of_duty": 0,
            "least_privilege": 0,
            "role_explosion": 0,
        }
        try:
            async with self.driver.session(database=self.database) as session:
                # Get compliance violations with optional time filter
                query = """
                MATCH (v:ComplianceViolation)
                WHERE $start_time IS NULL OR v.timestamp >= $start_time
                AND $end_time IS NULL OR v.timestamp <= $end_time
                RETURN v.type, count(v) as count
                """
                result = await session.run(
                    query,
                    start_time=start_time.isoformat() if start_time else None,
                    end_time=end_time.isoformat() if end_time else None,
                )
                async for record in result:
                    violation_type = record["v.type"]
                    count = record["count"]
                    if violation_type in violations:
                        violations[violation_type] = count
        except ServiceUnavailable as error:
            print(f"Error fetching compliance violations: {error}")
        return violations

    async def get_historical_incidents(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Get historical security incidents from Neo4j."""
        incidents = {
            "unauthorized_access": 0,
            "privilege_escalation": 0,
            "role_abuse": 0,
        }
        try:
            async with self.driver.session(database=self.database) as session:
                # Get security incidents with optional time filter
                query = """
                MATCH (i:SecurityIncident)
                WHERE $start_time IS NULL OR i.timestamp >= $start_time
                AND $end_time IS NULL OR i.timestamp <= $end_time
                RETURN i.type, count(i) as count
                """
                result = await session.run(
                    query,
                    start_time=start_time.isoformat() if start_time else None,
                    end_time=end_time.isoformat() if end_time else None,
                )
                async for record in result:
                    incident_type = record["i.type"]
                    count = record["count"]
                    if incident_type in incidents:
                        incidents[incident_type] = count
        except ServiceUnavailable as error:
            print(f"Error fetching historical incidents: {error}")
        return incidents

    async def apply_role_recommendation(
        self, role_id: UUID, action: str, changes: Dict
    ) -> bool:
        """Apply a role recommendation to Neo4j."""
        try:
            async with self.driver.session(database=self.database) as session:
                if action == "merge":
                    # Merge roles
                    target_role_id = changes["merge_with"]
                    # Copy permissions from source role to target role
                    await session.run(
                        """
                        MATCH (source:Role {id: $source_id})-[:HAS_PERMISSION]->(p:Permission)
                        MATCH (target:Role {id: $target_id})
                        MERGE (target)-[:HAS_PERMISSION]->(p)
                        """,
                        source_id=str(role_id),
                        target_id=str(target_role_id),
                    )
                    # Delete source role
                    await session.run(
                        """
                        MATCH (r:Role {id: $role_id})
                        DETACH DELETE r
                        """,
                        role_id=str(role_id),
                    )

                elif action == "modify":
                    # Update role permissions
                    if "remove_permissions" in changes:
                        await session.run(
                            """
                            MATCH (r:Role {id: $role_id})-[rel:HAS_PERMISSION]->(p:Permission)
                            WHERE p.id IN $permission_ids
                            DELETE rel
                            """,
                            role_id=str(role_id),
                            permission_ids=[str(p) for p in changes["remove_permissions"]],
                        )

                elif action == "create":
                    # Create new role
                    new_role_id = str(uuid4())
                    await session.run(
                        """
                        CREATE (r:Role {
                            id: $role_id,
                            name: $name,
                            description: $description,
                            created_at: datetime(),
                            updated_at: datetime()
                        })
                        """,
                        role_id=new_role_id,
                        name=changes["new_role_name"],
                        description="Auto-generated role",
                    )
                    # Assign permissions
                    if "permissions" in changes:
                        await session.run(
                            """
                            MATCH (r:Role {id: $role_id})
                            MATCH (p:Permission)
                            WHERE p.id IN $permission_ids
                            MERGE (r)-[:HAS_PERMISSION]->(p)
                            """,
                            role_id=new_role_id,
                            permission_ids=[str(p) for p in changes["permissions"]],
                        )
                    # Assign users
                    if "assigned_users" in changes:
                        await session.run(
                            """
                            MATCH (r:Role {id: $role_id})
                            MATCH (u:User)
                            WHERE u.id IN $user_ids
                            MERGE (u)-[:HAS_ROLE]->(r)
                            """,
                            role_id=new_role_id,
                            user_ids=[str(u) for u in changes["assigned_users"]],
                        )
            return True
        except ServiceUnavailable as error:
            print(f"Error applying recommendation: {error}")
            return False

    async def close(self):
        """Close the Neo4j driver connection."""
        await self.driver.close() 