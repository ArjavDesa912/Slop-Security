"""
🛡️ Slop Security - Django Integration

Add to your MIDDLEWARE in settings.py:
    MIDDLEWARE = [
        'slop.django.SlopSecurityMiddleware',
        # ... other middleware
    ]
"""

from typing import Callable, Any

from slop.core import Slop, SlopConfig


class SlopSecurityMiddleware:
    """
    Django middleware for Slop Security.
    
    Add to MIDDLEWARE in settings.py:
        MIDDLEWARE = [
            'slop.django.SlopSecurityMiddleware',
            # ... other middleware
        ]
    """
    
    def __init__(self, get_response: Callable):
        self.get_response = get_response
        self.slop = Slop()
        print("🛡️ Slop Security initialized for Django")
    
    def __call__(self, request):
        # Pre-request processing
        
        # Rate limiting
        client_ip = self._get_client_ip(request)
        if not self.slop.check_rate_limit(client_ip):
            from django.http import JsonResponse
            return JsonResponse({"error": "Too many requests"}, status=429)
        
        # Sanitize GET parameters
        for key, value in request.GET.items():
            if isinstance(value, str):
                sanitized = self.slop.sanitize(value)
                if sanitized != value:
                    # Log potential attack
                    import logging
                    logger = logging.getLogger("slop.security")
                    logger.warning(f"Sanitized GET param '{key}' from {client_ip}")
        
        # SSRF protection
        url_params = ["url", "redirect", "next", "return", "callback"]
        for param in url_params:
            url_value = request.GET.get(param) or request.POST.get(param)
            if url_value and isinstance(url_value, str) and url_value.startswith("http"):
                valid, reason = self.slop.validate_url(url_value)
                if not valid:
                    from django.http import JsonResponse
                    return JsonResponse({"error": f"Invalid URL: {reason}"}, status=400)
        
        # Store slop in request for access in views
        request.slop = self.slop
        
        # Get response
        response = self.get_response(request)
        
        # Add security headers
        for header, value in self.slop.get_security_headers().items():
            response[header] = value
        
        return response
    
    def _get_client_ip(self, request) -> str:
        """Get client IP from request, handling proxies."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")


def get_slop(request) -> Slop:
    """
    Get Slop instance from Django request.
    
    Example:
        >>> from slop.django import get_slop
        >>> 
        >>> def my_view(request):
        >>>     slop = get_slop(request)
        >>>     sanitized = slop.sanitize(user_input)
    """
    return getattr(request, "slop", Slop())
