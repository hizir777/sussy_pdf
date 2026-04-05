"""
Security & Authentication Module (v1.1.0+)

Handles:
- JWT token generation & validation
- API Key management
- Input validation & sanitization
"""

import logging
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthCredentials, HTTPBearer
import jwt
from jwt.exceptions import InvalidTokenError as JWTError

logger = logging.getLogger(__name__)

# ============================================
# JWT Token Management
# ============================================

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-key-change-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", 24))


class TokenManager:
    """JWT token generation & validation."""

    @staticmethod
    def create_token(
        data: dict[str, Any],
        expires_delta: timedelta | None = None,
    ) -> str:
        """Generate JWT token.

        Args:
            data: Claims to encode
            expires_delta: Custom expiration time

        Returns:
            Encoded JWT token
        """
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)

        to_encode.update({"exp": expire})

        encoded_jwt = jwt.encode(
            to_encode,
            JWT_SECRET,
            algorithm=JWT_ALGORITHM
        )

        logger.info(f"Token created for user: {data.get('sub', 'unknown')}")
        return encoded_jwt

    @staticmethod
    def verify_token(token: str) -> dict[str, Any]:
        """Verify & decode JWT token.

        Args:
            token: JWT token to verify

        Returns:
            Decoded token payload

        Raises:
            HTTPException: If token invalid/expired
        """
        try:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALGORITHM]
            )
            return payload

        except JWTError as e:
            logger.warning(f"Invalid token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )


# ============================================
# API Key Management
# ============================================

class APIKeyManager:
    """API Key generation & validation."""

    @staticmethod
    def generate_api_key(prefix: str = "sussy") -> str:
        """Generate secure API key.

        Args:
            prefix: Key prefix (e.g., "sussy_")

        Returns:
            Generated API key
        """
        # Format: prefix_randomstring
        random_part = secrets.token_urlsafe(32)
        api_key = f"{prefix}_{random_part}"

        logger.info(f"API key generated with prefix: {prefix}")
        return api_key

    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """Hash API key for storage (simple example).

        In production, use bcryptjs.

        Args:
            api_key: Raw API key

        Returns:
            Hashed API key
        """
        import hashlib
        return hashlib.sha256(api_key.encode()).hexdigest()


# ============================================
# Input Validation & Sanitization
# ============================================

class InputValidator:
    """Input validation & sanitization."""

    @staticmethod
    def validate_file_path(file_path: str, max_size_mb: int = 500) -> bool:
        """Validate PDF file path & size.

        Args:
            file_path: Path to PDF file
            max_size_mb: Maximum file size in MB

        Returns:
            True if valid

        Raises:
            ValueError: If invalid
        """
        # Check if file exists
        if not os.path.exists(file_path):
            raise ValueError(f"File not found: {file_path}")

        # Check if it's a file (not directory)
        if not os.path.isfile(file_path):
            raise ValueError(f"Not a file: {file_path}")

        # Check file size
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        if file_size_mb > max_size_mb:
            raise ValueError(
                f"File too large: {file_size_mb:.2f}MB (max {max_size_mb}MB)"
            )

        # Check magic bytes
        with open(file_path, 'rb') as f:
            magic = f.read(4)

        if magic != b'%PDF':
            raise ValueError("Invalid PDF file (magic bytes mismatch)")

        return True

    @staticmethod
    def validate_url(url: str, allow_local: bool = False) -> bool:
        """Validate & sanitize URL (SSRF prevention).

        Args:
            url: URL to validate
            allow_local: Allow localhost/private IPs

        Returns:
            True if valid

        Raises:
            ValueError: If invalid or suspicious
        """
        import ipaddress

        try:
            parsed = urlparse(url)
        except Exception:
            raise ValueError(f"Invalid URL: {url}")

        # Whitelist protocols
        if parsed.scheme not in ['http', 'https']:
            raise ValueError(f"Invalid protocol: {parsed.scheme}")

        # Extract hostname
        hostname = parsed.hostname
        if not hostname:
            raise ValueError(f"No hostname in URL: {url}")

        # Blocked hosts
        blocked_hosts = [
            'localhost', '127.0.0.1', '0.0.0.0',
            '169.254.169.254',  # AWS metadata
        ]

        if hostname.lower() in [h.lower() for h in blocked_hosts]:
            if not allow_local:
                raise ValueError(f"Blocked host: {hostname}")

        # Blocked IP ranges (CIDR)
        try:
            ip = ipaddress.ip_address(hostname)

            blocked_ranges = [
                ipaddress.ip_network('10.0.0.0/8'),
                ipaddress.ip_network('172.16.0.0/12'),
                ipaddress.ip_network('192.168.0.0/16'),
                ipaddress.ip_network('169.254.0.0/16'),
                ipaddress.ip_network('127.0.0.0/8'),
            ]

            for blocked in blocked_ranges:
                if ip in blocked:
                    if not allow_local:
                        raise ValueError(f"Blocked private IP: {hostname}")

        except ValueError as e:
            if "does not appear to be an IPv4 or IPv6 address" not in str(e):
                raise

        return True

    @staticmethod
    def sanitize_string(s: str, max_length: int = 1000) -> str:
        """Sanitize string input.

        Args:
            s: String to sanitize
            max_length: Maximum length

        Returns:
            Sanitized string

        Raises:
            ValueError: If exceeds length
        """
        if len(s) > max_length:
            raise ValueError(f"String exceeds max length: {max_length}")

        # Remove null bytes
        s = s.replace('\x00', '')

        # Remove control characters
        s = ''.join(c for c in s if ord(c) >= 32 or c in '\n\r\t')

        return s.strip()


# ============================================
# HTTP Bearer Token Authentication
# ============================================

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthCredentials = Depends(security)
) -> dict[str, Any]:
    """Validate JWT token from Authorization header.

    Args:
        credentials: HTTP Bearer credentials

    Returns:
        Decoded token payload

    Raises:
        HTTPException: If token invalid
    """
    token = credentials.credentials
    payload = TokenManager.verify_token(token)

    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token claims",
        )

    return payload


# ============================================
# API Key Authentication (Alternative)
# ============================================

async def get_api_key(api_key: str) -> str:
    """Validate API key from header.

    Args:
        api_key: API key from X-API-Key header

    Returns:
        Validated API key

    Raises:
        HTTPException: If invalid
    """
    # In production, hash and compare against database
    # For now, simple environment variable check

    valid_keys = os.getenv("VALID_API_KEYS", "").split(",")

    if api_key not in valid_keys:
        logger.warning(f"Invalid API key attempt: {api_key[:10]}...")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )

    return api_key


def require_auth(func):
    """Decorator for endpoints requiring authentication.

    Usage:
        @app.get("/protected")
        @require_auth
        async def protected_endpoint(...):
            ...
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Implementation in main.py integration
        return await func(*args, **kwargs)

    return wrapper
