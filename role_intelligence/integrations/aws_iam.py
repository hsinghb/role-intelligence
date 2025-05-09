from datetime import datetime
from typing import Dict, List, Optional, Set
from uuid import UUID, uuid4

import boto3
from botocore.exceptions import ClientError

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


class AWSIAMIntegrationAdapter(IAMIntegrationAdapter):
    """AWS IAM integration adapter for the Role Intelligence Service."""

    def __init__(
        self,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        region_name: str = "us-east-1",
    ):
        """Initialize the AWS IAM integration adapter."""
        self.iam = boto3.client(
            "iam",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
        )
        self.cloudtrail = boto3.client(
            "cloudtrail",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
        )
        self._role_cache: Dict[str, Role] = {}
        self._user_cache: Dict[str, User] = {}
        self._resource_cache: Dict[str, Resource] = {}
        self._permission_cache: Dict[str, Permission] = {}

    async def get_roles(self) -> List[Role]:
        """Fetch all roles from AWS IAM."""
        roles = []
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                # Get role policies
                policies = []
                policy_paginator = self.iam.get_paginator("list_attached_role_policies")
                for policy_page in policy_paginator.paginate(RoleName=role["RoleName"]):
                    policies.extend(policy_page["AttachedPolicies"])

                # Convert AWS role to our Role model
                our_role = Role(
                    id=UUID(role["RoleId"]),
                    name=role["RoleName"],
                    description=role.get("Description", ""),
                    permissions=await self._get_role_permissions(role["RoleName"]),
                    metadata={
                        "aws_arn": role["Arn"],
                        "aws_create_date": role["CreateDate"].isoformat(),
                        "aws_path": role["Path"],
                        "aws_policies": [p["PolicyName"] for p in policies],
                    },
                )
                self._role_cache[role["RoleId"]] = our_role
                roles.append(our_role)
        return roles

    async def get_users(self) -> List[User]:
        """Fetch all users from AWS IAM."""
        users = []
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                # Get user groups (roles)
                groups = []
                group_paginator = self.iam.get_paginator("list_groups_for_user")
                for group_page in group_paginator.paginate(UserName=user["UserName"]):
                    groups.extend(group_page["Groups"])

                # Convert AWS user to our User model
                our_user = User(
                    id=UUID(user["UserId"]),
                    username=user["UserName"],
                    email=user.get("Email", ""),
                    roles=await self._get_user_roles(user["UserName"]),
                    metadata={
                        "aws_arn": user["Arn"],
                        "aws_create_date": user["CreateDate"].isoformat(),
                        "aws_path": user["Path"],
                        "aws_groups": [g["GroupName"] for g in groups],
                    },
                    last_active=user.get("PasswordLastUsed"),
                )
                self._user_cache[user["UserId"]] = our_user
                users.append(our_user)
        return users

    async def get_resources(self) -> List[Resource]:
        """Fetch all resources from AWS IAM."""
        resources = []
        # Get IAM resources (policies, groups, etc.)
        paginator = self.iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                # Convert AWS policy to our Resource model
                our_resource = Resource(
                    id=UUID(policy["PolicyId"]),
                    name=policy["PolicyName"],
                    type=ResourceType.POLICY,
                    description=policy.get("Description", ""),
                    sensitivity_level=self._map_aws_risk_to_risk_level(
                        policy.get("RiskLevel", "LOW")
                    ),
                    metadata={
                        "aws_arn": policy["Arn"],
                        "aws_create_date": policy["CreateDate"].isoformat(),
                        "aws_update_date": policy["UpdateDate"].isoformat(),
                        "aws_attachment_count": policy["AttachmentCount"],
                    },
                )
                self._resource_cache[policy["PolicyId"]] = our_resource
                resources.append(our_resource)
        return resources

    async def get_permissions(self) -> List[Permission]:
        """Fetch all permissions from AWS IAM."""
        permissions = []
        # Get policy permissions
        paginator = self.iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                try:
                    # Get policy version
                    policy_version = self.iam.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"],
                    )
                    # Parse policy document
                    for statement in policy_version["PolicyVersion"]["Document"]["Statement"]:
                        # Convert AWS permission to our Permission model
                        our_permission = Permission(
                            id=UUID(str(uuid4())),  # Generate unique ID
                            resource_id=UUID(policy["PolicyId"]),
                            level=self._map_aws_action_to_permission_level(
                                statement["Action"]
                            ),
                            conditions=statement.get("Condition", {}),
                            metadata={
                                "aws_effect": statement["Effect"],
                                "aws_resource": statement.get("Resource", "*"),
                                "aws_policy_name": policy["PolicyName"],
                            },
                        )
                        self._permission_cache[str(our_permission.id)] = our_permission
                        permissions.append(our_permission)
                except ClientError:
                    continue
        return permissions

    async def get_access_logs(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> List[AccessLog]:
        """Fetch access logs from AWS CloudTrail."""
        logs = []
        # Get CloudTrail events
        paginator = self.cloudtrail.get_paginator("lookup_events")
        for page in paginator.paginate(
            StartTime=start_time if start_time else datetime(2020, 1, 1),
            EndTime=end_time if end_time else datetime.utcnow(),
            LookupAttributes=[
                {"AttributeKey": "EventSource", "AttributeValue": "iam.amazonaws.com"}
            ],
        ):
            for event in page["Events"]:
                # Convert CloudTrail event to our AccessLog model
                our_log = AccessLog(
                    id=UUID(event["EventId"]),
                    user_id=await self._get_user_id_from_event(event),
                    resource_id=await self._get_resource_id_from_event(event),
                    permission_id=await self._get_permission_id_from_event(event),
                    timestamp=event["EventTime"],
                    success=event.get("ErrorCode") is None,
                    context={
                        "event_name": event["EventName"],
                        "event_source": event["EventSource"],
                        "aws_region": event["AwsRegion"],
                        "source_ip": event.get("SourceIPAddress"),
                        "user_agent": event.get("UserAgent"),
                    },
                )
                logs.append(our_log)
        return logs

    async def get_user_roles(self, user_id: UUID) -> Set[UUID]:
        """Get roles assigned to a specific user."""
        roles = set()
        user = next((u for u in self._user_cache.values() if u.id == user_id), None)
        if user:
            # Get user groups
            groups = []
            group_paginator = self.iam.get_paginator("list_groups_for_user")
            for group_page in group_paginator.paginate(UserName=user.username):
                groups.extend(group_page["Groups"])
            # Get roles from groups
            for group in groups:
                role_paginator = self.iam.get_paginator("list_group_policies")
                for role_page in role_paginator.paginate(GroupName=group["GroupName"]):
                    for role_name in role_page["PolicyNames"]:
                        role = next(
                            (r for r in self._role_cache.values() if r.name == role_name),
                            None,
                        )
                        if role:
                            roles.add(role.id)
        return roles

    async def get_role_permissions(self, role_id: UUID) -> Set[UUID]:
        """Get permissions assigned to a specific role."""
        permissions = set()
        role = next((r for r in self._role_cache.values() if r.id == role_id), None)
        if role:
            # Get role policies
            policy_paginator = self.iam.get_paginator("list_attached_role_policies")
            for policy_page in policy_paginator.paginate(RoleName=role.name):
                for policy in policy_page["AttachedPolicies"]:
                    # Get policy permissions
                    policy_permissions = [
                        p.id for p in self._permission_cache.values()
                        if p.metadata.get("aws_policy_name") == policy["PolicyName"]
                    ]
                    permissions.update(policy_permissions)
        return permissions

    async def get_resource_permissions(self, resource_id: UUID) -> Set[UUID]:
        """Get permissions associated with a specific resource."""
        permissions = set()
        resource = next(
            (r for r in self._resource_cache.values() if r.id == resource_id), None
        )
        if resource:
            # Get resource permissions
            resource_permissions = [
                p.id for p in self._permission_cache.values()
                if p.resource_id == resource_id
            ]
            permissions.update(resource_permissions)
        return permissions

    async def get_compliance_violations(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Get compliance violations from AWS CloudTrail."""
        violations = {
            "separation_of_duty": 0,
            "least_privilege": 0,
            "role_explosion": 0,
        }
        # Get compliance-related events
        paginator = self.cloudtrail.get_paginator("lookup_events")
        for page in paginator.paginate(
            StartTime=start_time if start_time else datetime(2020, 1, 1),
            EndTime=end_time if end_time else datetime.utcnow(),
            LookupAttributes=[
                {
                    "AttributeKey": "EventName",
                    "AttributeValue": "PutRolePolicy",
                }
            ],
        ):
            for event in page["Events"]:
                if "separation_of_duty" in event.get("EventName", "").lower():
                    violations["separation_of_duty"] += 1
                elif "least_privilege" in event.get("EventName", "").lower():
                    violations["least_privilege"] += 1
                elif "role_explosion" in event.get("EventName", "").lower():
                    violations["role_explosion"] += 1
        return violations

    async def get_historical_incidents(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Get historical security incidents from AWS CloudTrail."""
        incidents = {
            "unauthorized_access": 0,
            "privilege_escalation": 0,
            "role_abuse": 0,
        }
        # Get security-related events
        paginator = self.cloudtrail.get_paginator("lookup_events")
        for page in paginator.paginate(
            StartTime=start_time if start_time else datetime(2020, 1, 1),
            EndTime=end_time if end_time else datetime.utcnow(),
            LookupAttributes=[
                {
                    "AttributeKey": "EventSource",
                    "AttributeValue": "iam.amazonaws.com",
                }
            ],
        ):
            for event in page["Events"]:
                if event.get("ErrorCode") == "AccessDenied":
                    incidents["unauthorized_access"] += 1
                elif "privilege" in event.get("EventName", "").lower():
                    incidents["privilege_escalation"] += 1
                elif "role" in event.get("EventName", "").lower():
                    incidents["role_abuse"] += 1
        return incidents

    async def apply_role_recommendation(
        self, role_id: UUID, action: str, changes: Dict
    ) -> bool:
        """Apply a role recommendation to AWS IAM."""
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
                    # Copy policies from source role to target role
                    policy_paginator = self.iam.get_paginator("list_attached_role_policies")
                    for policy_page in policy_paginator.paginate(RoleName=role.name):
                        for policy in policy_page["AttachedPolicies"]:
                            self.iam.attach_role_policy(
                                RoleName=target_role.name,
                                PolicyArn=policy["PolicyArn"],
                            )
                    # Delete source role
                    self.iam.delete_role(RoleName=role.name)

            elif action == "modify":
                # Update role permissions
                if "remove_permissions" in changes:
                    for perm_id in changes["remove_permissions"]:
                        permission = self._permission_cache.get(str(perm_id))
                        if permission:
                            policy_name = permission.metadata.get("aws_policy_name")
                            if policy_name:
                                self.iam.detach_role_policy(
                                    RoleName=role.name,
                                    PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}",
                                )

            elif action == "create":
                # Create new role
                new_role = self.iam.create_role(
                    RoleName=changes["new_role_name"],
                    AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}',
                    Description="Auto-generated role",
                )
                # Assign permissions
                for perm_id in changes["permissions"]:
                    permission = self._permission_cache.get(str(perm_id))
                    if permission:
                        policy_name = permission.metadata.get("aws_policy_name")
                        if policy_name:
                            self.iam.attach_role_policy(
                                RoleName=new_role["Role"]["RoleName"],
                                PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}",
                            )
                # Assign users
                for user_id in changes["assigned_users"]:
                    user = next(
                        (u for u in self._user_cache.values() if u.id == user_id), None
                    )
                    if user:
                        self.iam.add_user_to_group(
                            GroupName=new_role["Role"]["RoleName"],
                            UserName=user.username,
                        )
            return True
        except ClientError as e:
            print(f"Error applying recommendation: {e}")
            return False

    async def _get_role_permissions(self, role_name: str) -> Set[UUID]:
        """Helper method to get role permissions."""
        permissions = set()
        policy_paginator = self.iam.get_paginator("list_attached_role_policies")
        for policy_page in policy_paginator.paginate(RoleName=role_name):
            for policy in policy_page["AttachedPolicies"]:
                # Get policy permissions
                policy_permissions = [
                    p.id for p in self._permission_cache.values()
                    if p.metadata.get("aws_policy_name") == policy["PolicyName"]
                ]
                permissions.update(policy_permissions)
        return permissions

    async def _get_user_roles(self, username: str) -> Set[UUID]:
        """Helper method to get user roles."""
        roles = set()
        group_paginator = self.iam.get_paginator("list_groups_for_user")
        for group_page in group_paginator.paginate(UserName=username):
            for group in group_page["Groups"]:
                role_paginator = self.iam.get_paginator("list_group_policies")
                for role_page in role_paginator.paginate(GroupName=group["GroupName"]):
                    for role_name in role_page["PolicyNames"]:
                        role = next(
                            (r for r in self._role_cache.values() if r.name == role_name),
                            None,
                        )
                        if role:
                            roles.add(role.id)
        return roles

    async def _get_user_id_from_event(self, event) -> UUID:
        """Helper method to get user ID from a CloudTrail event."""
        user_arn = event.get("UserIdentity", {}).get("Arn", "")
        user = next(
            (u for u in self._user_cache.values() if u.metadata["aws_arn"] == user_arn),
            None,
        )
        return user.id if user else UUID(event["EventId"])

    async def _get_resource_id_from_event(self, event) -> UUID:
        """Helper method to get resource ID from a CloudTrail event."""
        resource_arn = event.get("Resources", [{}])[0].get("ARN", "")
        resource = next(
            (
                r
                for r in self._resource_cache.values()
                if r.metadata["aws_arn"] == resource_arn
            ),
            None,
        )
        return resource.id if resource else UUID(event["EventId"])

    async def _get_permission_id_from_event(self, event) -> UUID:
        """Helper method to get permission ID from a CloudTrail event."""
        # This is a simplified version - in reality, you'd need to map
        # AWS event types to specific permissions
        return UUID(event["EventId"])

    def _map_aws_risk_to_risk_level(self, aws_risk: str) -> RiskLevel:
        """Map AWS risk levels to our RiskLevel enum."""
        risk_map = {
            "LOW": RiskLevel.LOW,
            "MEDIUM": RiskLevel.MEDIUM,
            "HIGH": RiskLevel.HIGH,
            "CRITICAL": RiskLevel.CRITICAL,
        }
        return risk_map.get(aws_risk.upper(), RiskLevel.LOW)

    def _map_aws_action_to_permission_level(self, action: str) -> PermissionLevel:
        """Map AWS actions to our PermissionLevel enum."""
        action = action.lower()
        if "admin" in action or "manage" in action:
            return PermissionLevel.ADMIN
        elif "write" in action or "create" in action or "update" in action:
            return PermissionLevel.WRITE
        elif "execute" in action or "run" in action:
            return PermissionLevel.EXECUTE
        else:
            return PermissionLevel.READ 