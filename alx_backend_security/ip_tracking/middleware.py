import logging
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from django.core.cache import cache
from .models import RequestLog, BlockedIP

logger = logging.getLogger(__name__)

class IPTrackingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Get the client's IP address
        ip_address = self.get_client_ip(request)
        
        # Check if IP is blocked
        if self.is_ip_blocked(ip_address):
            logger.warning(f"Blocked request from {ip_address} - {request.get_full_path()}")
            return HttpResponseForbidden("Access denied: Your IP address is blocked.")
        
        # Get the request path
        path = request.get_full_path()
        
        try:
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path
            )
            
            logger.info(f"Request logged: {ip_address} - {path}")
            
        except Exception as e:
            logger.error(f"Error logging request: {e}")
        
        return None
    
    def is_ip_blocked(self, ip_address):
        """
        Check if IP address is blocked.
        Uses caching to avoid database hits on every request.
        """
        cache_key = f"blocked_ip_{ip_address}"
        
        cached_result = cache.get(cache_key)
        if cached_result is not None:
            return cached_result
        
        is_blocked = BlockedIP.objects.filter(ip_address=ip_address).exists()
        
        cache.set(cache_key, is_blocked, 300)
        
        return is_blocked
    
    def get_client_ip(self, request):
        """
        Get the client's IP address from the request.
        Handles cases where request comes through proxies.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip