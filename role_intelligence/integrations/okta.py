from datetime import datetime
from typing import Dict, List, Optional, Set
from uuid import UUID, uuid4

import aiohttp
from okta.client import Client as OktaClient

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


class OktaIntegrationAdapter(IAMIntegrationAdapter):
    """Okta integration adapter for the Role Intelligence Service."""

    def __init__(
        self,
        org_url: str,
        api_token: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ):
        """Initialize the Okta integration adapter."""
        self.client = OktaClient(
            orgUrl=org_url,
            token=api_token,
            clientId=client_id,
            clientSecret=client_secret,
        )
        self._role_cache: Dict[str, Role] = {}
        self._user_cache: Dict[str, User] = {}
        self._resource_cache: Dict[str, Resource] = {}
        self._permission_cache: Dict[str, Permission] = {}

    async def get_roles(self) -> List[Role]:
        """Fetch all roles from Okta."""
        roles = []
        async for role in self.client.list_roles():
            # Convert Okta role to our Role model
            our_role = Role(
                id=UUID(role.id),
                name=role.label,
                description=role.description,
                permissions=await self._get_role_permissions(role.id),
                metadata={
                    "okta_type": role.type,
                    "okta_status": role.status,
                },
            )
            self._role_cache[role.id] = our_role
            roles.append(our_role)
        return roles

    async def get_users(self) -> List[User]:
        """Fetch all users from Okta."""
        users = []
        async for user in self.client.list_users():
            # Convert Okta user to our User model
            our_user = User(
                id=UUID(user.id),
                username=user.profile.login,
                email=user.profile.email,
                roles=await self._get_user_roles(user.id),
                metadata={
                    "okta_status": user.status,
                    "okta_type": user.type,
                },
                last_active=datetime.fromisoformat(user.lastLogin)
                if user.lastLogin
                else None,
            )
            self._user_cache[user.id] = our_user
            users.append(our_user)
        return users

    async def get_resources(self) -> List[Resource]:
        """Fetch all resources from Okta."""
        resources = []
        # Get applications as resources
        async for app in self.client.list_applications():
            # Convert Okta app to our Resource model
            our_resource = Resource(
                id=UUID(app.id),
                name=app.label,
                type=ResourceType.SERVICE,  # Default to SERVICE type
                description=app.description,
                sensitivity_level=self._map_okta_risk_to_risk_level(app.riskLevel),
                metadata={
                    "okta_type": app.type,
                    "okta_status": app.status,
                },
            )
            self._resource_cache[app.id] = our_resource
            resources.append(our_resource)
        return resources

    async def get_permissions(self) -> List[Permission]:
        """Fetch all permissions from Okta."""
        permissions = []
        # Get app permissions
        async for app in self.client.list_applications():
            async for scope in self.client.list_application_grants(app.id):
                # Convert Okta scope to our Permission model
                our_permission = Permission(
                    id=UUID(scope.id),
                    resource_id=UUID(app.id),
                    level=self._map_okta_scope_to_permission_level(scope.scope),
                    conditions=self._parse_scope_conditions(scope.scope),
                    metadata={
                        "okta_scope": scope.scope,
                        "okta_status": scope.status,
                    },
                )
                self._permission_cache[scope.id] = our_permission
                permissions.append(our_permission)
        return permissions

    async def get_access_logs(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> List[AccessLog]:
        """Fetch access logs from Okta."""
        logs = []
        # Get system logs
        async for log in self.client.get_logs(
            since=start_time.isoformat() if start_time else None,
            until=end_time.isoformat() if end_time else None,
        ):
            if log.eventType.startswith("app."):
                # Convert Okta log to our AccessLog model
                our_log = AccessLog(
                    id=UUID(log.id),
                    user_id=UUID(log.actor.id),
                    resource_id=UUID(log.target[0].id),
                    permission_id=await self._get_permission_id_for_log(log),
                    timestamp=datetime.fromisoformat(log.published),
                    success=log.outcome.result == "SUCCESS",
                    context={
                        "event_type": log.eventType,
                        "ip_address": log.client.ipAddress,
                        "user_agent": log.client.userAgent.rawUserAgent,
                    },
                )
                logs.append(our_log)
        return logs

    async def get_user_roles(self, user_id: UUID) -> Set[UUID]:
        """Get roles assigned to a specific user."""
        roles = set()
        async for role in self.client.list_user_roles(str(user_id)):
            if role.id in self._role_cache:
                roles.add(self._role_cache[role.id].id)
        return roles

    async def get_role_permissions(self, role_id: UUID) -> Set[UUID]:
        """Get permissions assigned to a specific role."""
        permissions = set()
        async for permission in self.client.list_role_permissions(str(role_id)):
            if permission.id in self._permission_cache:
                permissions.add(self._permission_cache[permission.id].id)
        return permissions

    async def get_resource_permissions(self, resource_id: UUID) -> Set[UUID]:
        """Get permissions associated with a specific resource."""
        permissions = set()
        async for scope in self.client.list_application_grants(str(resource_id)):
            if scope.id in self._permission_cache:
                permissions.add(self._permission_cache[scope.id].id)
        return permissions

    async def get_compliance_violations(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Get compliance violations from Okta."""
        violations = {
            "separation_of_duty": 0,
            "least_privilege": 0,
            "role_explosion": 0,
        }
        # Get compliance-related logs
        async for log in self.client.get_logs(
            since=start_time.isoformat() if start_time else None,
            until=end_time.isoformat() if end_time else None,
            q="eventType:compliance.violation",
        ):
            if "separation_of_duty" in log.eventType:
                violations["separation_of_duty"] += 1
            elif "least_privilege" in log.eventType:
                violations["least_privilege"] += 1
            elif "role_explosion" in log.eventType:
                violations["role_explosion"] += 1
        return violations

    async def get_historical_incidents(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Get historical security incidents from Okta."""
        incidents = {
            "unauthorized_access": 0,
            "privilege_escalation": 0,
            "role_abuse": 0,
        }
        # Get security incident logs
        async for log in self.client.get_logs(
            since=start_time.isoformat() if start_time else None,
            until=end_time.isoformat() if end_time else None,
            q="eventType:security.incident",
        ):
            if "unauthorized_access" in log.eventType:
                incidents["unauthorized_access"] += 1
            elif "privilege_escalation" in log.eventType:
                incidents["privilege_escalation"] += 1
            elif "role_abuse" in log.eventType:
                incidents["role_abuse"] += 1
        return incidents

    async def apply_role_recommendation(
        self, role_id: UUID, action: str, changes: Dict
    ) -> bool:
        """Apply a role recommendation to Okta."""
        try:
            if action == "merge":
                # Merge roles
                target_role_id = changes["merge_with"]
                await self.client.merge_roles(str(role_id), str(target_role_id))
            elif action == "modify":
                # Update role permissions
                if "remove_permissions" in changes:
                    for perm_id in changes["remove_permissions"]:
                        await self.client.remove_role_permission(
                            str(role_id), str(perm_id)
                        )
            elif action == "create":
                # Create new role
                new_role = await self.client.create_role(
                    {
                        "label": changes["new_role_name"],
                        "description": "Auto-generated role",
                        "type": "APP_ADMIN",
                    }
                )
                # Assign permissions
                for perm_id in changes["permissions"]:
                    await self.client.assign_role_permission(
                        str(new_role.id), str(perm_id)
                    )
                # Assign users
                for user_id in changes["assigned_users"]:
                    await self.client.assign_role_to_user(str(user_id), str(new_role.id))
            return True
        except Exception as e:
            print(f"Error applying recommendation: {e}")
            return False

    async def _get_role_permissions(self, role_id: str) -> Set[UUID]:
        """Helper method to get role permissions."""
        permissions = set()
        async for permission in self.client.list_role_permissions(role_id):
            permissions.add(UUID(permission.id))
        return permissions

    async def _get_user_roles(self, user_id: str) -> Set[UUID]:
        """Helper method to get user roles."""
        roles = set()
        async for role in self.client.list_user_roles(user_id):
            roles.add(UUID(role.id))
        return roles

    async def _get_permission_id_for_log(self, log) -> UUID:
        """Helper method to get permission ID from a log entry."""
        # This is a simplified version - in reality, you'd need to map
        # Okta event types to specific permissions
        return UUID(log.target[0].id)

    def _map_okta_risk_to_risk_level(self, okta_risk: str) -> RiskLevel:
        """Map Okta risk levels to our RiskLevel enum."""
        risk_map = {
            "LOW": RiskLevel.LOW,
            "MEDIUM": RiskLevel.MEDIUM,
            "HIGH": RiskLevel.HIGH,
            "CRITICAL": RiskLevel.CRITICAL,
        }
        return risk_map.get(okta_risk.upper(), RiskLevel.LOW)

    def _map_okta_scope_to_permission_level(self, scope: str) -> PermissionLevel:
        """Map Okta scopes to our PermissionLevel enum."""
        scope_map = {
            "read": PermissionLevel.READ,
            "write": PermissionLevel.WRITE,
            "admin": PermissionLevel.ADMIN,
            "execute": PermissionLevel.EXECUTE,
        }
        return scope_map.get(scope.lower(), PermissionLevel.READ)

    def _parse_scope_conditions(self, scope: str) -> Dict[str, str]:
        """Parse scope conditions from Okta scope string."""
        # This is a simplified version - in reality, you'd need to parse
        # the actual scope conditions from Okta
        return {"scope": scope} 