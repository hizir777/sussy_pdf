"""
Audit Logging Module (v1.1.0+)

Handles:
- Structured logging (JSON format)
- Audit trail for sensitive operations
- Rate limiting detection
- Error tracking
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

# ============================================
# Structured Logger Setup
# ============================================

class StructuredLogger:
    """JSON-formatted structured logging."""

    def __init__(self, name: str, log_file: str | None = None):
        """Initialize structured logger.

        Args:
            name: Logger name
            log_file: Optional log file path
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        # Create handlers
        handlers = []

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(os.getenv("LOG_LEVEL", "INFO"))
        handlers.append(console_handler)

        # File handler (if specified)
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            handlers.append(file_handler)

        # Set formatters
        log_format = os.getenv("LOG_FORMAT", "json")

        if log_format == "json":
            formatter = JSONFormatter()
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )

        for handler in handlers:
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        **kwargs
    ) -> None:
        """Log structured event.

        Args:
            event_type: Type of event (e.g., 'auth_login', 'file_uploaded')
            severity: Severity level (INFO, WARNING, ERROR, CRITICAL)
            message: Human-readable message
            **kwargs: Additional context (user, file, etc.)
        """
        data = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'message': message,
            'extra': kwargs
        }

        level = getattr(logging, severity, logging.INFO)
        self.logger.log(level, json.dumps(data))


class JSONFormatter(logging.Formatter):
    """JSON logging formatter."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }

        # Add extra fields if available
        if hasattr(record, 'extra'):
            log_data.update(record.extra)

        return json.dumps(log_data)


# ============================================
# Audit Trail Logger
# ============================================

class AuditLogger:
    """Audit trail for sensitive operations."""

    def __init__(self):
        """Initialize audit logger."""
        log_file = os.getenv(
            "LOG_FILE",
            "./logs/sussy_pdf.log"
        )
        self.logger = StructuredLogger(__name__, log_file)

    def log_authentication(
        self,
        user: str,
        success: bool,
        ip_address: str | None = None,
    ) -> None:
        """Log authentication attempt.

        Args:
            user: Username or API key
            success: Whether authentication succeeded
            ip_address: Client IP address
        """
        self.logger.log_event(
            event_type='auth_attempt',
            severity='INFO' if success else 'WARNING',
            message=f"Authentication {'succeeded' if success else 'failed'} for {user}",
            user=user,
            ip_address=ip_address,
            success=success
        )

    def log_file_analysis(
        self,
        file_name: str,
        file_size_bytes: int,
        user: str | None = None,
        duration_seconds: float = 0,
    ) -> None:
        """Log PDF analysis operation.

        Args:
            file_name: Analyzed file name
            file_size_bytes: File size in bytes
            user: User who initiated analysis
            duration_seconds: Analysis duration
        """
        self.logger.log_event(
            event_type='pdf_analysis',
            severity='INFO',
            message=f"PDF analysis completed: {file_name}",
            file_name=file_name,
            file_size_mb=round(file_size_bytes / (1024**2), 2),
            user=user,
            duration_seconds=duration_seconds
        )

    def log_security_event(
        self,
        event_name: str,
        description: str,
        severity: str = 'WARNING',
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log security-related event.

        Args:
            event_name: Security event name
            description: Event description
            severity: Event severity
            details: Additional details
        """
        self.logger.log_event(
            event_type='security_event',
            severity=severity,
            message=description,
            event_name=event_name,
            **(details or {})
        )

    def log_error(
        self,
        error_type: str,
        error_message: str,
        user: str | None = None,
        file_name: str | None = None,
    ) -> None:
        """Log error event.

        Args:
            error_type: Type of error
            error_message: Error message
            user: User involved (if applicable)
            file_name: File involved (if applicable)
        """
        self.logger.log_event(
            event_type='error',
            severity='ERROR',
            message=error_message,
            error_type=error_type,
            user=user,
            file_name=file_name
        )

    def log_rate_limit_exceeded(
        self,
        user_or_ip: str,
        endpoint: str,
        limit: int,
    ) -> None:
        """Log rate limit exceeded.

        Args:
            user_or_ip: User or IP address
            endpoint: API endpoint
            limit: Rate limit threshold
        """
        self.logger.log_event(
            event_type='rate_limit_exceeded',
            severity='WARNING',
            message=f"Rate limit exceeded for {user_or_ip} on {endpoint}",
            user_or_ip=user_or_ip,
            endpoint=endpoint,
            limit=limit
        )


# Global audit logger instance
audit_logger = AuditLogger()
