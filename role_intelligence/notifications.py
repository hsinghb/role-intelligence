from typing import Dict, List, Optional, Union, Any
import asyncio
import aiohttp
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from uuid import UUID, uuid4

from .models import RiskAssessment, RiskMitigation
from .saas_config import NotificationConfig

class NotificationChannel(BaseModel):
    """Base class for notification channels."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    name: str
    enabled: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)

class EmailChannel(NotificationChannel):
    """Email notification channel."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    smtp_server: str
    smtp_port: int
    username: str
    password: str
    from_email: str
    to_emails: List[str] = Field(default_factory=list)

class SlackChannel(NotificationChannel):
    """Slack notification channel."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    webhook_url: str
    channel: str
    username: Optional[str] = None
    icon_emoji: Optional[str] = None

class WebhookChannel(NotificationChannel):
    """Generic webhook notification channel."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    url: str
    method: str = "POST"
    headers: Dict[str, str] = Field(default_factory=dict)
    auth: Optional[Dict[str, str]] = None

class Notification(BaseModel):
    """Represents a notification."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    level: str  # info, warning, error, critical
    title: str
    message: str
    data: Dict[str, Any] = Field(default_factory=dict)
    channels: List[str] = Field(default_factory=list)
    status: str = "pending"  # pending, sent, failed

class NotificationManager:
    """Manages notifications across different channels."""
    
    def __init__(self):
        self.channels: Dict[str, NotificationChannel] = {}
    
    def setup_channel(self, channel: NotificationChannel) -> None:
        """Set up a notification channel."""
        self.channels[channel.name] = channel
    
    async def send_notification(self, notification: Notification) -> None:
        """Send a notification through configured channels."""
        for channel_name in notification.channels:
            if channel_name in self.channels:
                channel = self.channels[channel_name]
                if channel.enabled:
                    try:
                        if isinstance(channel, EmailChannel):
                            await self._send_email(channel, notification)
                        elif isinstance(channel, SlackChannel):
                            await self._send_slack(channel, notification)
                        elif isinstance(channel, WebhookChannel):
                            await self._send_webhook(channel, notification)
                    except Exception as e:
                        print(f"Error sending notification through {channel_name}: {e}")
    
    async def _send_email(self, channel: EmailChannel, notification: Notification) -> None:
        """Send notification via email."""
        # TODO: Implement email sending
        pass
    
    async def _send_slack(self, channel: SlackChannel, notification: Notification) -> None:
        """Send notification via Slack."""
        # TODO: Implement Slack message sending
        pass
    
    async def _send_webhook(self, channel: WebhookChannel, notification: Notification) -> None:
        """Send notification via webhook."""
        # TODO: Implement webhook sending
        pass
    
    def notify_risk_assessment(self, assessment: Any) -> None:
        """Send notification for a risk assessment."""
        notification = Notification(
            tenant_id=assessment.tenant_id,
            level=self._get_notification_level(assessment.risk_level),
            title=f"Risk Assessment: {assessment.risk_type}",
            message=assessment.description,
            data={"assessment": assessment.dict()},
            channels=["email", "slack"]
        )
        asyncio.create_task(self.send_notification(notification))
    
    def notify_risk_mitigation(self, mitigation: Any) -> None:
        """Send notification for a risk mitigation."""
        notification = Notification(
            tenant_id=mitigation.tenant_id,
            level="info",
            title="Risk Mitigation Required",
            message=f"Mitigation strategy: {mitigation.strategy}",
            data={"mitigation": mitigation.dict()},
            channels=["email", "slack"]
        )
        asyncio.create_task(self.send_notification(notification))
    
    def _get_notification_level(self, risk_level: str) -> str:
        """Convert risk level to notification level."""
        level_map = {
            "low": "info",
            "medium": "warning",
            "high": "error",
            "critical": "critical"
        }
        return level_map.get(risk_level.lower(), "info") 