import logging
from django.utils.deprecation import MiddlewareMixin
from .models import RequestLog

logger = logging.getLogger(__name__)

class IPTrackingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        ip_address = self.get_client_ip(request)

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