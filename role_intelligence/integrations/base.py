from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Set
from uuid import UUID

from role_intelligence.models import (
    AccessLog,
    Permission,
    Resource,
    Role,
    User,
)


class IAMIntegrationAdapter(ABC):
    """Base class for IAM platform integrations."""

    @abstractmethod
    async def get_roles(self) -> List[Role]:
        """Fetch all roles from the IAM platform."""
        pass

    @abstractmethod
    async def get_users(self) -> List[User]:
        """Fetch all users from the IAM platform."""
        pass

    @abstractmethod
    async def get_resources(self) -> List[Resource]:
        """Fetch all resources from the IAM platform."""
        pass

    @abstractmethod
    async def get_permissions(self) -> List[Permission]:
        """Fetch all permissions from the IAM platform."""
        pass

    @abstractmethod
    async def get_access_logs(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> List[AccessLog]:
        """Fetch access logs from the IAM platform."""
        pass

    @abstractmethod
    async def get_user_roles(self, user_id: UUID) -> Set[UUID]:
        """Get roles assigned to a specific user."""
        pass

    @abstractmethod
    async def get_role_permissions(self, role_id: UUID) -> Set[UUID]:
        """Get permissions assigned to a specific role."""
        pass

    @abstractmethod
    async def get_resource_permissions(self, resource_id: UUID) -> Set[UUID]:
        """Get permissions associated with a specific resource."""
        pass

    @abstractmethod
    async def get_compliance_violations(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Get compliance violations from the IAM platform."""
        pass

    @abstractmethod
    async def get_historical_incidents(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Get historical security incidents from the IAM platform."""
        pass

    @abstractmethod
    async def apply_role_recommendation(
        self, role_id: UUID, action: str, changes: Dict
    ) -> bool:
        """Apply a role recommendation to the IAM platform."""
        pass 