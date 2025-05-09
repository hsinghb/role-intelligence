from datetime import datetime
from typing import Dict, List, Optional, Set
from uuid import UUID, uuid4

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

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


class GoogleWorkspaceIntegrationAdapter(IAMIntegrationAdapter):
    """Google Workspace integration adapter for the Role Intelligence Service."""

    def __init__(
        self,
        credentials_file: str,
        admin_email: str,
        customer_id: Optional[str] = None,
    ):
        """Initialize the Google Workspace integration adapter."""
        self.credentials = service_account.Credentials.from_service_account_file(
            credentials_file,
            scopes=[
                "https://www.googleapis.com/auth/admin.directory.user",
                "https://www.googleapis.com/auth/admin.directory.rolemanagement",
                "https://www.googleapis.com/auth/admin.directory.group",
                "https://www.googleapis.com/auth/admin.reports.audit.readonly",
            ],
        )
        self.credentials = self.credentials.with_subject(admin_email)
        self.customer_id = customer_id or "my_customer"

        # Initialize Google Workspace API clients
        self.admin = build("admin", "directory_v1", credentials=self.credentials)
        self.reports = build("admin", "reports_v1", credentials=self.credentials)
        self.iam = build("iam", "v1", credentials=self.credentials)

        self._role_cache: Dict[str, Role] = {}
        self._user_cache: Dict[str, User] = {}
        self._resource_cache: Dict[str, Resource] = {}
        self._permission_cache: Dict[str, Permission] = {}

    async def get_roles(self) -> List[Role]:
        """Fetch all roles from Google Workspace."""
        roles = []
        try:
            # Get custom roles
            custom_roles = self.iam.roles().list(
                parent=f"organizations/{self.customer_id}",
                view="FULL",
            ).execute()

            for role in custom_roles.get("roles", []):
                # Convert Google role to our Role model
                our_role = Role(
                    id=UUID(role["name"].split("/")[-1]),
                    name=role["title"],
                    description=role.get("description", ""),
                    permissions=await self._get_role_permissions(role["name"]),
                    metadata={
                        "google_name": role["name"],
                        "google_stage": role["stage"],
                        "google_etag": role["etag"],
                    },
                )
                self._role_cache[role["name"]] = our_role
                roles.append(our_role)

            # Get predefined roles
            predefined_roles = self.iam.roles().list(
                parent=f"organizations/{self.customer_id}",
                view="FULL",
                showDeleted=False,
            ).execute()

            for role in predefined_roles.get("roles", []):
                if role["name"] not in self._role_cache:
                    our_role = Role(
                        id=UUID(role["name"].split("/")[-1]),
                        name=role["title"],
                        description=role.get("description", ""),
                        permissions=await self._get_role_permissions(role["name"]),
                        metadata={
                            "google_name": role["name"],
                            "google_stage": role["stage"],
                            "google_etag": role["etag"],
                        },
                    )
                    self._role_cache[role["name"]] = our_role
                    roles.append(our_role)

        except HttpError as error:
            print(f"Error fetching roles: {error}")
        return roles

    async def get_users(self) -> List[User]:
        """Fetch all users from Google Workspace."""
        users = []
        try:
            # Get users
            request = self.admin.users().list(
                customer=self.customer_id,
                maxResults=100,
                orderBy="email",
            )
            while request is not None:
                response = request.execute()
                for user in response.get("users", []):
                    # Get user roles
                    roles = []
                    try:
                        role_assignments = self.admin.roleAssignments().list(
                            customer=self.customer_id,
                            userKey=user["id"],
                        ).execute()
                        roles = [
                            UUID(role["roleId"])
                            for role in role_assignments.get("items", [])
                        ]
                    except HttpError:
                        pass

                    # Convert Google user to our User model
                    our_user = User(
                        id=UUID(user["id"]),
                        username=user["primaryEmail"],
                        email=user["primaryEmail"],
                        roles=set(roles),
                        metadata={
                            "google_id": user["id"],
                            "google_is_admin": user.get("isAdmin", False),
                            "google_is_enforced_2sv": user.get("isEnforcedIn2Sv", False),
                            "google_org_unit_path": user.get("orgUnitPath", ""),
                        },
                        last_active=datetime.fromisoformat(user["lastLoginTime"])
                        if "lastLoginTime" in user
                        else None,
                    )
                    self._user_cache[user["id"]] = our_user
                    users.append(our_user)
                request = self.admin.users().list_next(request, response)
        except HttpError as error:
            print(f"Error fetching users: {error}")
        return users

    async def get_resources(self) -> List[Resource]:
        """Fetch all resources from Google Workspace."""
        resources = []
        try:
            # Get Google Workspace services as resources
            services = self.admin.resources().calendars().list(
                customer=self.customer_id,
            ).execute()

            for service in services.get("items", []):
                # Convert Google service to our Resource model
                our_resource = Resource(
                    id=UUID(service["resourceId"]),
                    name=service["resourceName"],
                    type=ResourceType.SERVICE,
                    description=service.get("resourceDescription", ""),
                    sensitivity_level=self._map_google_risk_to_risk_level(
                        service.get("riskLevel", "LOW")
                    ),
                    metadata={
                        "google_resource_id": service["resourceId"],
                        "google_resource_type": service["resourceType"],
                        "google_capacity": service.get("capacity", {}),
                    },
                )
                self._resource_cache[service["resourceId"]] = our_resource
                resources.append(our_resource)

        except HttpError as error:
            print(f"Error fetching resources: {error}")
        return resources

    async def get_permissions(self) -> List[Permission]:
        """Fetch all permissions from Google Workspace."""
        permissions = []
        try:
            # Get role permissions
            for role_name in self._role_cache.keys():
                role_permissions = self.iam.roles().get(
                    name=role_name,
                ).execute()

                for permission in role_permissions.get("includedPermissions", []):
                    # Convert Google permission to our Permission model
                    our_permission = Permission(
                        id=UUID(str(uuid4())),  # Generate unique ID
                        resource_id=UUID(role_name.split("/")[-1]),
                        level=self._map_google_permission_to_level(permission),
                        conditions={},  # Google permissions don't have conditions
                        metadata={
                            "google_permission": permission,
                            "google_role": role_name,
                        },
                    )
                    self._permission_cache[str(our_permission.id)] = our_permission
                    permissions.append(our_permission)

        except HttpError as error:
            print(f"Error fetching permissions: {error}")
        return permissions

    async def get_access_logs(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> List[AccessLog]:
        """Fetch access logs from Google Workspace."""
        logs = []
        try:
            # Get admin audit logs
            request = self.reports.activities().list(
                userKey="all",
                applicationName="admin",
                startTime=start_time.isoformat() if start_time else None,
                endTime=end_time.isoformat() if end_time else None,
            )
            while request is not None:
                response = request.execute()
                for activity in response.get("items", []):
                    # Convert Google activity to our AccessLog model
                    our_log = AccessLog(
                        id=UUID(activity["id"]["time"] + activity["id"]["uniqueQualifier"]),
                        user_id=UUID(activity["actor"]["profileId"]),
                        resource_id=await self._get_resource_id_from_activity(activity),
                        permission_id=await self._get_permission_id_from_activity(activity),
                        timestamp=datetime.fromisoformat(activity["id"]["time"]),
                        success=activity.get("events", [{}])[0].get("type") != "ERROR",
                        context={
                            "event_type": activity.get("events", [{}])[0].get("name"),
                            "ip_address": activity.get("ipAddress"),
                            "user_agent": activity.get("actor", {}).get("callerType"),
                        },
                    )
                    logs.append(our_log)
                request = self.reports.activities().list_next(request, response)
        except HttpError as error:
            print(f"Error fetching access logs: {error}")
        return logs

    async def get_user_roles(self, user_id: UUID) -> Set[UUID]:
        """Get roles assigned to a specific user."""
        roles = set()
        try:
            user = next((u for u in self._user_cache.values() if u.id == user_id), None)
            if user:
                role_assignments = self.admin.roleAssignments().list(
                    customer=self.customer_id,
                    userKey=str(user_id),
                ).execute()
                roles = {
                    UUID(role["roleId"])
                    for role in role_assignments.get("items", [])
                }
        except HttpError as error:
            print(f"Error fetching user roles: {error}")
        return roles

    async def get_role_permissions(self, role_id: UUID) -> Set[UUID]:
        """Get permissions assigned to a specific role."""
        permissions = set()
        try:
            role = next((r for r in self._role_cache.values() if r.id == role_id), None)
            if role:
                role_permissions = self.iam.roles().get(
                    name=role.metadata["google_name"],
                ).execute()
                permissions = {
                    p.id
                    for p in self._permission_cache.values()
                    if p.metadata["google_role"] == role.metadata["google_name"]
                }
        except HttpError as error:
            print(f"Error fetching role permissions: {error}")
        return permissions

    async def get_resource_permissions(self, resource_id: UUID) -> Set[UUID]:
        """Get permissions associated with a specific resource."""
        permissions = set()
        resource = next(
            (r for r in self._resource_cache.values() if r.id == resource_id), None
        )
        if resource:
            permissions = {
                p.id
                for p in self._permission_cache.values()
                if p.resource_id == resource_id
            }
        return permissions

    async def get_compliance_violations(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Get compliance violations from Google Workspace."""
        violations = {
            "separation_of_duty": 0,
            "least_privilege": 0,
            "role_explosion": 0,
        }
        try:
            # Get admin audit logs for compliance events
            request = self.reports.activities().list(
                userKey="all",
                applicationName="admin",
                startTime=start_time.isoformat() if start_time else None,
                endTime=end_time.isoformat() if end_time else None,
            )
            while request is not None:
                response = request.execute()
                for activity in response.get("items", []):
                    event_name = activity.get("events", [{}])[0].get("name", "").lower()
                    if "separation_of_duty" in event_name:
                        violations["separation_of_duty"] += 1
                    elif "least_privilege" in event_name:
                        violations["least_privilege"] += 1
                    elif "role_explosion" in event_name:
                        violations["role_explosion"] += 1
                request = self.reports.activities().list_next(request, response)
        except HttpError as error:
            print(f"Error fetching compliance violations: {error}")
        return violations

    async def get_historical_incidents(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Get historical security incidents from Google Workspace."""
        incidents = {
            "unauthorized_access": 0,
            "privilege_escalation": 0,
            "role_abuse": 0,
        }
        try:
            # Get security audit logs
            request = self.reports.activities().list(
                userKey="all",
                applicationName="security",
                startTime=start_time.isoformat() if start_time else None,
                endTime=end_time.isoformat() if end_time else None,
            )
            while request is not None:
                response = request.execute()
                for activity in response.get("items", []):
                    event_name = activity.get("events", [{}])[0].get("name", "").lower()
                    if "unauthorized_access" in event_name:
                        incidents["unauthorized_access"] += 1
                    elif "privilege_escalation" in event_name:
                        incidents["privilege_escalation"] += 1
                    elif "role_abuse" in event_name:
                        incidents["role_abuse"] += 1
                request = self.reports.activities().list_next(request, response)
        except HttpError as error:
            print(f"Error fetching historical incidents: {error}")
        return incidents

    async def apply_role_recommendation(
        self, role_id: UUID, action: str, changes: Dict
    ) -> bool:
        """Apply a role recommendation to Google Workspace."""
        try:
            role = next((r for r in self._role_cache.values() if r.id == role_id), None)
            if not role:
                return False

            if action == "merge":
                # Merge roles
                target_role = next(
                    (r for r in self._role_cache.values() if r.id == changes["merge_with"]),
                    None,
                )
                if target_role:
                    # Copy permissions from source role to target role
                    source_permissions = self.iam.roles().get(
                        name=role.metadata["google_name"],
                    ).execute()
                    target_permissions = self.iam.roles().get(
                        name=target_role.metadata["google_name"],
                    ).execute()
                    merged_permissions = list(
                        set(
                            source_permissions.get("includedPermissions", [])
                            + target_permissions.get("includedPermissions", [])
                        )
                    )
                    # Update target role with merged permissions
                    self.iam.roles().patch(
                        name=target_role.metadata["google_name"],
                        body={"includedPermissions": merged_permissions},
                    ).execute()
                    # Delete source role
                    self.iam.roles().delete(
                        name=role.metadata["google_name"],
                    ).execute()

            elif action == "modify":
                # Update role permissions
                if "remove_permissions" in changes:
                    current_permissions = self.iam.roles().get(
                        name=role.metadata["google_name"],
                    ).execute()
                    updated_permissions = [
                        p
                        for p in current_permissions.get("includedPermissions", [])
                        if p not in changes["remove_permissions"]
                    ]
                    self.iam.roles().patch(
                        name=role.metadata["google_name"],
                        body={"includedPermissions": updated_permissions},
                    ).execute()

            elif action == "create":
                # Create new role
                new_role = self.iam.roles().create(
                    parent=f"organizations/{self.customer_id}",
                    body={
                        "title": changes["new_role_name"],
                        "description": "Auto-generated role",
                        "includedPermissions": [
                            p.metadata["google_permission"]
                            for p in self._permission_cache.values()
                            if p.id in changes["permissions"]
                        ],
                    },
                ).execute()
                # Assign users
                for user_id in changes["assigned_users"]:
                    user = next(
                        (u for u in self._user_cache.values() if u.id == user_id), None
                    )
                    if user:
                        self.admin.roleAssignments().insert(
                            customer=self.customer_id,
                            body={
                                "roleId": new_role["name"].split("/")[-1],
                                "assignedTo": str(user_id),
                            },
                        ).execute()
            return True
        except HttpError as error:
            print(f"Error applying recommendation: {error}")
            return False

    async def _get_role_permissions(self, role_name: str) -> Set[UUID]:
        """Helper method to get role permissions."""
        permissions = set()
        try:
            role_permissions = self.iam.roles().get(
                name=role_name,
            ).execute()
            permissions = {
                p.id
                for p in self._permission_cache.values()
                if p.metadata["google_role"] == role_name
            }
        except HttpError:
            pass
        return permissions

    async def _get_resource_id_from_activity(self, activity) -> UUID:
        """Helper method to get resource ID from an activity."""
        resource_id = activity.get("events", [{}])[0].get("parameters", [{}])[0].get(
            "value", ""
        )
        resource = next(
            (
                r
                for r in self._resource_cache.values()
                if r.metadata.get("google_resource_id") == resource_id
            ),
            None,
        )
        return resource.id if resource else UUID(activity["id"]["time"])

    async def _get_permission_id_from_activity(self, activity) -> UUID:
        """Helper method to get permission ID from an activity."""
        # This is a simplified version - in reality, you'd need to map
        # Google activity types to specific permissions
        return UUID(activity["id"]["time"])

    def _map_google_risk_to_risk_level(self, google_risk: str) -> RiskLevel:
        """Map Google risk levels to our RiskLevel enum."""
        risk_map = {
            "LOW": RiskLevel.LOW,
            "MEDIUM": RiskLevel.MEDIUM,
            "HIGH": RiskLevel.HIGH,
            "CRITICAL": RiskLevel.CRITICAL,
        }
        return risk_map.get(google_risk.upper(), RiskLevel.LOW)

    def _map_google_permission_to_level(self, permission: str) -> PermissionLevel:
        """Map Google permissions to our PermissionLevel enum."""
        permission = permission.lower()
        if "admin" in permission or "manage" in permission:
            return PermissionLevel.ADMIN
        elif "write" in permission or "create" in permission or "update" in permission:
            return PermissionLevel.WRITE
        elif "execute" in permission or "run" in permission:
            return PermissionLevel.EXECUTE
        else:
            return PermissionLevel.READ 