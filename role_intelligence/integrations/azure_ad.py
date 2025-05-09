from datetime import datetime
from typing import Dict, List, Optional, Set
from uuid import UUID

from azure.graphrbac import GraphRbacManagementClient
from azure.identity import ClientSecretCredential
from msrestazure.azure_active_directory import ServicePrincipalCredentials

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


class AzureADIntegrationAdapter(IAMIntegrationAdapter):
    """Azure AD integration adapter for the Role Intelligence Service."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
    ):
        """Initialize the Azure AD integration adapter."""
        credentials = ServicePrincipalCredentials(
            client_id=client_id,
            secret=client_secret,
            tenant=tenant_id,
        )
        self.client = GraphRbacManagementClient(
            credentials=credentials,
            tenant_id=tenant_id,
            subscription_id=subscription_id,
        )
        self._role_cache: Dict[str, Role] = {}
        self._user_cache: Dict[str, User] = {}
        self._resource_cache: Dict[str, Resource] = {}
        self._permission_cache: Dict[str, Permission] = {}

    async def get_roles(self) -> List[Role]:
        """Fetch all roles from Azure AD."""
        roles = []
        for role in self.client.applications.list():
            # Convert Azure AD role to our Role model
            our_role = Role(
                id=UUID(role.object_id),
                name=role.display_name,
                description=role.description,
                permissions=await self._get_role_permissions(role.object_id),
                metadata={
                    "azure_type": role.app_type,
                    "azure_enabled": role.enabled,
                },
            )
            self._role_cache[role.object_id] = our_role
            roles.append(our_role)
        return roles

    async def get_users(self) -> List[User]:
        """Fetch all users from Azure AD."""
        users = []
        for user in self.client.users.list():
            # Convert Azure AD user to our User model
            our_user = User(
                id=UUID(user.object_id),
                username=user.user_principal_name,
                email=user.mail,
                roles=await self._get_user_roles(user.object_id),
                metadata={
                    "azure_type": user.user_type,
                    "azure_enabled": user.account_enabled,
                },
                last_active=datetime.fromisoformat(user.last_sign_in)
                if user.last_sign_in
                else None,
            )
            self._user_cache[user.object_id] = our_user
            users.append(our_user)
        return users

    async def get_resources(self) -> List[Resource]:
        """Fetch all resources from Azure AD."""
        resources = []
        # Get service principals as resources
        for sp in self.client.service_principals.list():
            # Convert Azure AD service principal to our Resource model
            our_resource = Resource(
                id=UUID(sp.object_id),
                name=sp.display_name,
                type=ResourceType.SERVICE,  # Default to SERVICE type
                description=sp.description,
                sensitivity_level=self._map_azure_risk_to_risk_level(
                    sp.risk_level if hasattr(sp, "risk_level") else "LOW"
                ),
                metadata={
                    "azure_type": "service_principal",
                    "azure_enabled": sp.account_enabled,
                },
            )
            self._resource_cache[sp.object_id] = our_resource
            resources.append(our_resource)
        return resources

    async def get_permissions(self) -> List[Permission]:
        """Fetch all permissions from Azure AD."""
        permissions = []
        # Get app permissions
        for app in self.client.applications.list():
            for scope in self.client.oauth2_permissions.list(app.object_id):
                # Convert Azure AD scope to our Permission model
                our_permission = Permission(
                    id=UUID(scope.id),
                    resource_id=UUID(app.object_id),
                    level=self._map_azure_scope_to_permission_level(scope.value),
                    conditions=self._parse_scope_conditions(scope.value),
                    metadata={
                        "azure_scope": scope.value,
                        "azure_enabled": scope.is_enabled,
                    },
                )
                self._permission_cache[scope.id] = our_permission
                permissions.append(our_permission)
        return permissions

    async def get_access_logs(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> List[AccessLog]:
        """Fetch access logs from Azure AD."""
        logs = []
        # Get sign-in logs
        for log in self.client.sign_in_logs.list(
            filter=f"createdDateTime ge {start_time.isoformat() if start_time else '2020-01-01T00:00:00Z'} and "
            f"createdDateTime le {end_time.isoformat() if end_time else datetime.utcnow().isoformat()}"
        ):
            if log.app_id:  # Only include application access logs
                # Convert Azure AD log to our AccessLog model
                our_log = AccessLog(
                    id=UUID(log.id),
                    user_id=UUID(log.user_id),
                    resource_id=UUID(log.app_id),
                    permission_id=await self._get_permission_id_for_log(log),
                    timestamp=datetime.fromisoformat(log.created_date_time),
                    success=log.status.error_code == 0,
                    context={
                        "event_type": log.app_display_name,
                        "ip_address": log.ip_address,
                        "user_agent": log.user_agent,
                    },
                )
                logs.append(our_log)
        return logs

    async def get_user_roles(self, user_id: UUID) -> Set[UUID]:
        """Get roles assigned to a specific user."""
        roles = set()
        for role in self.client.users.list_app_role_assignments(str(user_id)):
            if role.id in self._role_cache:
                roles.add(self._role_cache[role.id].id)
        return roles

    async def get_role_permissions(self, role_id: UUID) -> Set[UUID]:
        """Get permissions assigned to a specific role."""
        permissions = set()
        for permission in self.client.applications.list_oauth2_permissions(str(role_id)):
            if permission.id in self._permission_cache:
                permissions.add(self._permission_cache[permission.id].id)
        return permissions

    async def get_resource_permissions(self, resource_id: UUID) -> Set[UUID]:
        """Get permissions associated with a specific resource."""
        permissions = set()
        for permission in self.client.service_principals.list_oauth2_permissions(
            str(resource_id)
        ):
            if permission.id in self._permission_cache:
                permissions.add(self._permission_cache[permission.id].id)
        return permissions

    async def get_compliance_violations(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Get compliance violations from Azure AD."""
        violations = {
            "separation_of_duty": 0,
            "least_privilege": 0,
            "role_explosion": 0,
        }
        # Get compliance-related logs
        for log in self.client.directory_audit_logs.list(
            filter=f"createdDateTime ge {start_time.isoformat() if start_time else '2020-01-01T00:00:00Z'} and "
            f"createdDateTime le {end_time.isoformat() if end_time else datetime.utcnow().isoformat()} and "
            f"category eq 'Compliance'"
        ):
            if "separation_of_duty" in log.activity_display_name:
                violations["separation_of_duty"] += 1
            elif "least_privilege" in log.activity_display_name:
                violations["least_privilege"] += 1
            elif "role_explosion" in log.activity_display_name:
                violations["role_explosion"] += 1
        return violations

    async def get_historical_incidents(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Get historical security incidents from Azure AD."""
        incidents = {
            "unauthorized_access": 0,
            "privilege_escalation": 0,
            "role_abuse": 0,
        }
        # Get security incident logs
        for log in self.client.directory_audit_logs.list(
            filter=f"createdDateTime ge {start_time.isoformat() if start_time else '2020-01-01T00:00:00Z'} and "
            f"createdDateTime le {end_time.isoformat() if end_time else datetime.utcnow().isoformat()} and "
            f"category eq 'Security'"
        ):
            if "unauthorized_access" in log.activity_display_name:
                incidents["unauthorized_access"] += 1
            elif "privilege_escalation" in log.activity_display_name:
                incidents["privilege_escalation"] += 1
            elif "role_abuse" in log.activity_display_name:
                incidents["role_abuse"] += 1
        return incidents

    async def apply_role_recommendation(
        self, role_id: UUID, action: str, changes: Dict
    ) -> bool:
        """Apply a role recommendation to Azure AD."""
        try:
            if action == "merge":
                # Merge roles
                target_role_id = changes["merge_with"]
                await self.client.applications.merge(
                    str(role_id), str(target_role_id)
                )
            elif action == "modify":
                # Update role permissions
                if "remove_permissions" in changes:
                    for perm_id in changes["remove_permissions"]:
                        await self.client.applications.remove_oauth2_permission(
                            str(role_id), str(perm_id)
                        )
            elif action == "create":
                # Create new role
                new_role = await self.client.applications.create(
                    {
                        "display_name": changes["new_role_name"],
                        "description": "Auto-generated role",
                        "app_type": "web",
                    }
                )
                # Assign permissions
                for perm_id in changes["permissions"]:
                    await self.client.applications.add_oauth2_permission(
                        str(new_role.object_id), str(perm_id)
                    )
                # Assign users
                for user_id in changes["assigned_users"]:
                    await self.client.users.assign_app_role(
                        str(user_id), str(new_role.object_id)
                    )
            return True
        except Exception as e:
            print(f"Error applying recommendation: {e}")
            return False

    async def _get_role_permissions(self, role_id: str) -> Set[UUID]:
        """Helper method to get role permissions."""
        permissions = set()
        for permission in self.client.applications.list_oauth2_permissions(role_id):
            permissions.add(UUID(permission.id))
        return permissions

    async def _get_user_roles(self, user_id: str) -> Set[UUID]:
        """Helper method to get user roles."""
        roles = set()
        for role in self.client.users.list_app_role_assignments(user_id):
            roles.add(UUID(role.id))
        return roles

    async def _get_permission_id_for_log(self, log) -> UUID:
        """Helper method to get permission ID from a log entry."""
        # This is a simplified version - in reality, you'd need to map
        # Azure AD event types to specific permissions
        return UUID(log.app_id)

    def _map_azure_risk_to_risk_level(self, azure_risk: str) -> RiskLevel:
        """Map Azure AD risk levels to our RiskLevel enum."""
        risk_map = {
            "LOW": RiskLevel.LOW,
            "MEDIUM": RiskLevel.MEDIUM,
            "HIGH": RiskLevel.HIGH,
            "CRITICAL": RiskLevel.CRITICAL,
        }
        return risk_map.get(azure_risk.upper(), RiskLevel.LOW)

    def _map_azure_scope_to_permission_level(self, scope: str) -> PermissionLevel:
        """Map Azure AD scopes to our PermissionLevel enum."""
        scope_map = {
            "read": PermissionLevel.READ,
            "write": PermissionLevel.WRITE,
            "admin": PermissionLevel.ADMIN,
            "execute": PermissionLevel.EXECUTE,
        }
        return scope_map.get(scope.lower(), PermissionLevel.READ)

    def _parse_scope_conditions(self, scope: str) -> Dict[str, str]:
        """Parse scope conditions from Azure AD scope string."""
        # This is a simplified version - in reality, you'd need to parse
        # the actual scope conditions from Azure AD
        return {"scope": scope} 