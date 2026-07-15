"""
AWS CloudWatch Logs Integration Service.
Provides integration with AWS CloudWatch for centralized logging.
"""

import logging
import threading
import queue
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
import json

import boto3
from botocore.exceptions import ClientError, BotoCoreError

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class CloudWatchLogEvent:
    """CloudWatch log event."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))
    message: str = ""
    level: str = "INFO"
    source: str = "guardrail-ai"
    event_type: str = "app_log"
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "message": self.message,
            "level": self.level,
            "source": self.source,
            "event_type": self.event_type,
            "data": self.raw_data,
        }


class AWSCloudWatchConfig:
    """AWS CloudWatch configuration manager."""

    @staticmethod
    def get_config() -> Dict[str, Any]:
        """Get AWS CloudWatch configuration."""
        return {
            "enabled": getattr(settings, "AWS_CLOUDWATCH_ENABLED", False),
            "region": getattr(settings, "AWS_REGION", "us-east-1"),
            "access_key_id": getattr(settings, "AWS_ACCESS_KEY_ID", ""),
            "secret_access_key": getattr(settings, "AWS_SECRET_ACCESS_KEY", ""),
            "log_group": getattr(
                settings, "AWS_CLOUDWATCH_LOG_GROUP", "/aws/guardrail-ai"
            ),
            "log_stream": getattr(settings, "AWS_CLOUDWATCH_LOG_STREAM", "app-logs"),
            "batch_size": getattr(settings, "AWS_CLOUDWATCH_BATCH_SIZE", 100),
            "batch_interval": getattr(settings, "AWS_CLOUDWATCH_BATCH_INTERVAL", 5),
        }


class CloudWatchClient:
    """AWS CloudWatch Logs client with batching."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client = None
        self._sequence_token = None
        self._event_buffer: List[Dict[str, Any]] = []
        self._buffer_lock = threading.Lock()
        self._flush_thread: Optional[threading.Thread] = None
        self._running = False

        if config.get("enabled"):
            self._init_client()

    def _init_client(self):
        """Initialize boto3 CloudWatch client."""
        try:
            session_kwargs = {"region_name": self.config.get("region", "us-east-1")}

            if self.config.get("access_key_id") and self.config.get(
                "secret_access_key"
            ):
                session_kwargs["aws_access_key_id"] = self.config.get("access_key_id")
                session_kwargs["aws_secret_access_key"] = self.config.get(
                    "secret_access_key"
                )

            self.client = boto3.client("logs", **session_kwargs)
            self._ensure_log_group()
            self._ensure_log_stream()
            logger.info("CloudWatch client initialized")
        except Exception as e:
            logger.error(f"Failed to initialize CloudWatch client: {e}")

    def _ensure_log_group(self):
        """Ensure CloudWatch log group exists."""
        try:
            self.client.create_log_group(logGroupName=self.config.get("log_group"))
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
                logger.warning(f"Log group creation: {e}")

    def _ensure_log_stream(self):
        """Ensure CloudWatch log stream exists."""
        try:
            self.client.create_log_stream(
                logGroupName=self.config.get("log_group"),
                logStreamName=self.config.get("log_stream"),
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
                logger.warning(f"Log stream creation: {e}")

    def _get_sequence_token(self) -> Optional[str]:
        """Get sequence token for next log entry."""
        try:
            response = self.client.describe_log_streams(
                logGroupName=self.config.get("log_group"),
                logStreamNamePrefix=self.config.get("log_stream"),
                limit=1,
            )
            if response["logStreams"]:
                return response["logStreams"][0].get("uploadSequenceToken")
        except Exception as e:
            logger.warning(f"Failed to get sequence token: {e}")
        return None

    def _flush_buffer(self):
        """Flush buffered events to CloudWatch."""
        with self._buffer_lock:
            if not self._event_buffer:
                return

            events = self._event_buffer.copy()
            self._event_buffer.clear()

        if not events:
            return

        log_events = [
            {"timestamp": int(e["timestamp"] * 1000), "message": json.dumps(e)}
            for e in events
        ]

        try:
            sequence_token = self._get_sequence_token()
            put_kwargs = {
                "logGroupName": self.config.get("log_group"),
                "logStreamName": self.config.get("log_stream"),
                "logEvents": log_events,
            }

            if sequence_token:
                put_kwargs["sequenceToken"] = sequence_token

            self.client.put_log_events(**put_kwargs)
            logger.debug(f"Pushed {len(log_events)} events to CloudWatch")
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidSequenceTokenException":
                self._sequence_token = None
                logger.warning("Invalid sequence token, will retry")
            else:
                logger.error(f"Failed to push to CloudWatch: {e}")
        except Exception as e:
            logger.error(f"CloudWatch flush error: {e}")

    def _flush_worker(self):
        """Background worker for periodic flushing."""
        interval = self.config.get("batch_interval", 5)
        while self._running:
            try:
                self._flush_buffer()
            except Exception as e:
                logger.error(f"CloudWatch flush worker error: {e}")
            threading.Event().wait(interval)

    def start(self):
        """Start the background flush worker."""
        if not self._running and self.client:
            self._running = True
            self._flush_thread = threading.Thread(
                target=self._flush_worker, daemon=True
            )
            self._flush_thread.start()
            logger.info("CloudWatch integration started")

    def stop(self):
        """Stop and flush remaining events."""
        self._running = False
        if self._flush_thread:
            self._flush_thread.join(timeout=10)
        self._flush_buffer()
        logger.info("CloudWatch integration stopped")

    def send(self, event: CloudWatchLogEvent) -> bool:
        """Add event to buffer for batch sending."""
        if not self.client:
            return False

        try:
            with self._buffer_lock:
                self._event_buffer.append(event.to_dict())

                if len(self._event_buffer) >= self.config.get("batch_size", 100):
                    self._flush_buffer()

            return True
        except Exception as e:
            logger.error(f"Failed to queue CloudWatch event: {e}")
            return False

    def send_log(self, message: str, level: str = "INFO", **kwargs) -> bool:
        """Convenience method to send a log message."""
        event = CloudWatchLogEvent(message=message, level=level, raw_data=kwargs)
        return self.send(event)


class CloudWatchService:
    """Main CloudWatch integration service."""

    def __init__(self):
        self.config = AWSCloudWatchConfig.get_config()
        self.client: Optional[CloudWatchClient] = None

        if self.config.get("enabled"):
            self.client = CloudWatchClient(self.config)

    def start(self):
        """Start the service."""
        if self.client:
            self.client.start()

    def stop(self):
        """Stop the service."""
        if self.client:
            self.client.stop()

    def send_event(self, event: CloudWatchLogEvent) -> bool:
        """Send event to CloudWatch."""
        if self.client:
            return self.client.send(event)
        return False

    def send_log(self, message: str, level: str = "INFO", **kwargs) -> bool:
        """Send log message."""
        return self.client.send_log(message, level, **kwargs) if self.client else False

    def get_status(self) -> Dict[str, Any]:
        """Get integration status."""
        return {
            "enabled": self.config.get("enabled"),
            "region": self.config.get("region"),
            "log_group": self.config.get("log_group"),
            "log_stream": self.config.get("log_stream"),
            "connected": self.client is not None and self.client.client is not None,
        }
