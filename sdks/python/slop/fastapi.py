"""
🛡️ Slop Security - FastAPI Integration

Example:
    >>> from fastapi import FastAPI
    >>> from slop.fastapi import SlopMiddleware
    >>> 
    >>> app = FastAPI()
    >>> app.add_middleware(SlopMiddleware)
"""

from typing import Optional, Callable

from slop.core import Slop, SlopConfig


class SlopMiddleware:
    """
    FastAPI/Starlette middleware for Slop Security.
    
    Example:
        >>> from fastapi import FastAPI
        >>> from slop.fastapi import SlopMiddleware
        >>> 
        >>> app = FastAPI()
        >>> app.add_middleware(SlopMiddleware)
    """
    
    def __init__(self, app: Callable, config: Optional[SlopConfig] = None):
        self.app = app
        self.slop = Slop(config)
        print("🛡️ Slop Security initialized for FastAPI")
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        # Extract client IP
        client = scope.get("client")
        client_ip = client[0] if client else "unknown"
        
        # Rate limiting
        if not self.slop.check_rate_limit(client_ip):
            await self._send_error(send, 429, "Too many requests")
            return
        
        # Check for SSRF in query params
        query_string = scope.get("query_string", b"").decode()
        if query_string:
            from urllib.parse import parse_qs
            params = parse_qs(query_string)
            
            url_params = ["url", "redirect", "next", "return", "callback"]
            for param in url_params:
                if param in params:
                    url_value = params[param][0]
                    if url_value.startswith("http"):
                        valid, reason = self.slop.validate_url(url_value)
                        if not valid:
                            await self._send_error(send, 400, f"Invalid URL: {reason}")
                            return
        
        # Add security headers to response
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                for name, value in self.slop.get_security_headers().items():
                    headers.append((name.lower().encode(), value.encode()))
                message = {**message, "headers": headers}
            await send(message)
        
        # Store slop in scope for access in routes
        scope["slop"] = self.slop
        
        await self.app(scope, receive, send_wrapper)
    
    async def _send_error(self, send, status_code: int, message: str):
        """Send an error response."""
        import json
        
        body = json.dumps({"error": message}).encode()
        
        await send({
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })


def get_slop(request) -> Slop:
    """
    Get Slop instance from request.
    
    Example:
        >>> from fastapi import Request, Depends
        >>> from slop.fastapi import get_slop
        >>> 
        >>> @app.get("/")
        >>> async def root(request: Request):
        >>>     slop = get_slop(request)
        >>>     sanitized = slop.sanitize(user_input)
    """
    return request.scope.get("slop", Slop())


# Dependency for FastAPI
async def slop_dependency():
    """
    FastAPI dependency for accessing Slop.
    
    Example:
        >>> from fastapi import Depends
        >>> from slop.fastapi import slop_dependency
        >>> 
        >>> @app.get("/")
        >>> async def root(slop: Slop = Depends(slop_dependency)):
        >>>     sanitized = slop.sanitize(user_input)
    """
    return Slop()
