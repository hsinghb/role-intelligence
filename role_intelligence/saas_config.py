from typing import Dict, List, Optional, Set, Any
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime, timedelta
from uuid import UUID, uuid4

class TenantConfig(BaseModel):
    """Configuration for a tenant in the SaaS platform."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    tenant_id: str
    name: str
    subscription_tier: str = "standard"  # basic, standard, enterprise
    max_users: int = 100
    max_roles: int = 50
    features: List[str] = Field(default_factory=list)
    integrations: List[str] = Field(default_factory=list)
    retention_days: int = 90
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class EnterpriseFeatures(BaseModel):
    """Enterprise-specific features and configurations."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    sso_enabled: bool = False
    audit_logging: bool = True
    custom_integrations: bool = False
    api_rate_limit: int = 1000
    backup_frequency: str = "daily"
    support_level: str = "standard"  # standard, premium, enterprise
    custom_domain: Optional[str] = None
    ip_whitelist: List[str] = Field(default_factory=list)
    compliance_frameworks: List[str] = Field(default_factory=list)

class NotificationConfig(BaseModel):
    """Configuration for notifications and alerts."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    email_notifications: bool = True
    slack_integration: bool = False
    webhook_urls: List[str] = Field(default_factory=list)
    alert_thresholds: Dict[str, Any] = Field(default_factory=dict)
    notification_frequency: str = "realtime"  # realtime, daily, weekly
    notification_channels: List[str] = Field(default_factory=list)

class AIConfig(BaseModel):
    """Configuration for AI features and models."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    model_version: str = "gpt-4-turbo-preview"
    temperature: float = 0.7
    max_tokens: int = 2000
    custom_prompts: Dict[str, str] = Field(default_factory=dict)
    analysis_frequency: str = "realtime"  # realtime, hourly, daily
    confidence_threshold: float = 0.8
    training_data_retention: int = 365  # days

class SaaSConfig(BaseModel):
    """Main configuration for the SaaS platform."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    tenant: TenantConfig
    enterprise: EnterpriseFeatures
    notifications: NotificationConfig
    ai: AIConfig
    custom_settings: Dict[str, Any] = Field(default_factory=dict)

    def is_feature_enabled(self, feature: str) -> bool:
        """Check if a specific feature is enabled for the tenant."""
        return feature in self.tenant.features

    def can_add_user(self) -> bool:
        """Check if the tenant can add more users."""
        # TODO: Implement actual user count check
        return True

    def can_add_role(self) -> bool:
        """Check if the tenant can add more roles."""
        # TODO: Implement actual role count check
        return True

    def get_retention_date(self) -> datetime:
        """Get the date before which data can be deleted."""
        return datetime.utcnow() - timedelta(days=self.tenant.retention_days)

    def update_last_activity(self):
        """Update the last activity timestamp."""
        self.tenant.updated_at = datetime.utcnow()

class SaaSConfigManager:
    """Manager for handling SaaS configurations."""
    def __init__(self):
        self.configs: Dict[str, SaaSConfig] = {}

    def get_config(self, tenant_id: str) -> Optional[SaaSConfig]:
        """Get configuration for a specific tenant."""
        return self.configs.get(tenant_id)

    def create_config(self, config: SaaSConfig) -> None:
        """Create a new tenant configuration."""
        self.configs[config.tenant.tenant_id] = config

    def update_config(self, tenant_id: str, config: SaaSConfig) -> None:
        """Update an existing tenant configuration."""
        if tenant_id in self.configs:
            self.configs[tenant_id] = config

    def delete_config(self, tenant_id: str) -> None:
        """Delete a tenant configuration."""
        if tenant_id in self.configs:
            del self.configs[tenant_id]

    def list_tenants(self) -> List[str]:
        """List all tenant IDs."""
        return list(self.configs.keys())

    def get_active_tenants(self) -> List[str]:
        """Get list of active tenants."""
        # TODO: Implement actual activity check
        return self.list_tenants()

    def get_tenant_stats(self, tenant_id: str) -> Dict[str, any]:
        """Get statistics for a specific tenant."""
        config = self.get_config(tenant_id)
        if not config:
            return {}

        return {
            "subscription_tier": config.tenant.subscription_tier,
            "active_features": config.tenant.features,
            "integrations": config.tenant.integrations,
            "last_activity": config.tenant.updated_at,
            "enterprise_features": {
                "sso_enabled": config.enterprise.sso_enabled,
                "audit_logging": config.enterprise.audit_logging,
                "custom_integrations": config.enterprise.custom_integrations
            }
        } 