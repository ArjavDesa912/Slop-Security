"""
🛡️ Slop Security - Python SDK

One line to secure, zero lines to worry.

Example:
    >>> from slop import secure
    >>> app = Flask(__name__)
    >>> secure(app)
"""

from slop.core import (
    Slop,
    SlopConfig,
    sanitize,
    sanitize_sql,
    sanitize_html,
    validate_url,
    detect_sql_injection,
    detect_xss,
    hash_password,
    verify_password,
    generate_token,
)
from slop.flask import secure as flask_secure
from slop.fastapi import SlopMiddleware as FastAPISlopMiddleware
from slop.django import SlopSecurityMiddleware as DjangoSlopMiddleware

__version__ = "1.0.0"
__all__ = [
    "Slop",
    "SlopConfig",
    "sanitize",
    "sanitize_sql",
    "sanitize_html",
    "validate_url",
    "detect_sql_injection",
    "detect_xss",
    "hash_password",
    "verify_password",
    "generate_token",
    "flask_secure",
    "FastAPISlopMiddleware",
    "DjangoSlopMiddleware",
]


def secure(app, **kwargs):
    """
    Universal secure function that auto-detects the framework.
    
    Args:
        app: Flask, FastAPI, or Django application instance
        **kwargs: Configuration options
    
    Returns:
        The secured application
    
    Example:
        >>> from slop import secure
        >>> secure(app)
    """
    app_type = type(app).__name__
    
    if app_type == "Flask":
        return flask_secure(app, **kwargs)
    elif app_type == "FastAPI":
        app.add_middleware(FastAPISlopMiddleware, **kwargs)
        return app
    else:
        # Try to detect Django
        if hasattr(app, "middleware"):
            print("🛡️ For Django, add 'slop.django.SlopSecurityMiddleware' to MIDDLEWARE")
        else:
            print(f"🛡️ Unknown framework: {app_type}. Using generic protection.")
        return app
