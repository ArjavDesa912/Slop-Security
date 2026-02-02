"""
🛡️ Slop Security - Flask Integration

Example:
    >>> from flask import Flask
    >>> from slop import secure
    >>> app = Flask(__name__)
    >>> secure(app)
"""

from functools import wraps
from typing import Optional, Callable, Any

from slop.core import Slop, SlopConfig


def secure(app: Any, config: Optional[SlopConfig] = None) -> Any:
    """
    Secure a Flask application with Slop Security.
    
    Args:
        app: Flask application instance
        config: Optional SlopConfig for customization
    
    Returns:
        The secured Flask application
    
    Example:
        >>> from flask import Flask
        >>> from slop import secure
        >>> app = Flask(__name__)
        >>> secure(app)
    """
    slop = Slop(config)
    
    @app.before_request
    def slop_before_request():
        from flask import request, abort, g
        
        # Store slop instance in g for access in routes
        g.slop = slop
        
        # Rate limiting
        client_ip = request.remote_addr or "unknown"
        if not slop.check_rate_limit(client_ip):
            abort(429, description="Too many requests")
        
        # Sanitize query parameters
        for key in request.args:
            value = request.args.get(key)
            if value and isinstance(value, str):
                sanitized = slop.sanitize(value)
                if sanitized != value:
                    # Log potential attack (in production, use proper logging)
                    print(f"🛡️ SLOP: Sanitized query param '{key}'")
        
        # SSRF protection for URL parameters
        url_params = ["url", "redirect", "next", "return", "callback", "target"]
        for param in url_params:
            url_value = request.args.get(param) or (request.json or {}).get(param)
            if url_value and isinstance(url_value, str) and url_value.startswith("http"):
                valid, reason = slop.validate_url(url_value)
                if not valid:
                    abort(400, description=f"Invalid URL: {reason}")
    
    @app.after_request
    def slop_after_request(response):
        # Add security headers
        for header, value in slop.get_security_headers().items():
            response.headers[header] = value
        return response
    
    print("🛡️ Slop Security initialized for Flask")
    return app


def rate_limit(requests_per_minute: int = 60):
    """
    Rate limiting decorator for Flask routes.
    
    Args:
        requests_per_minute: Maximum requests allowed per minute
    
    Example:
        >>> @app.route('/api/expensive')
        >>> @rate_limit(10)
        >>> def expensive_operation():
        >>>     return {"result": "ok"}
    """
    def decorator(f: Callable) -> Callable:
        slop = Slop(SlopConfig(
            rate_limiting={"enabled": True, "requests_per_minute": requests_per_minute}
        ))
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, abort
            
            client_ip = request.remote_addr or "unknown"
            if not slop.check_rate_limit(f"{f.__name__}:{client_ip}"):
                abort(429, description="Rate limit exceeded")
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def brute_force_protection(max_attempts: int = 5, lockout_minutes: int = 15):
    """
    Brute force protection decorator for authentication routes.
    
    Args:
        max_attempts: Maximum failed attempts before lockout
        lockout_minutes: Lockout duration in minutes
    
    Example:
        >>> @app.route('/login', methods=['POST'])
        >>> @brute_force_protection(max_attempts=5)
        >>> def login():
        >>>     # Your login logic
        >>>     pass
    """
    _attempts: dict = {}
    
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, abort, g
            import time
            
            client_ip = request.remote_addr or "unknown"
            current_time = time.time()
            lockout_seconds = lockout_minutes * 60
            
            # Check if locked out
            if client_ip in _attempts:
                attempts, last_attempt = _attempts[client_ip]
                if attempts >= max_attempts:
                    if current_time - last_attempt < lockout_seconds:
                        abort(429, description="Too many failed attempts. Try again later.")
                    else:
                        # Reset after lockout period
                        _attempts[client_ip] = (0, current_time)
            
            # Add helper functions to g
            def record_failure():
                attempts, _ = _attempts.get(client_ip, (0, current_time))
                _attempts[client_ip] = (attempts + 1, current_time)
            
            def record_success():
                if client_ip in _attempts:
                    del _attempts[client_ip]
            
            g.auth_failure = record_failure
            g.auth_success = record_success
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator
