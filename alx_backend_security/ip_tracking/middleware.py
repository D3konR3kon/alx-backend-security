import logging
import requests
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.conf import settings
from .models import RequestLog, BlockedIP

logger = logging.getLogger(__name__)

class IPTrackingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        ip_address = self.get_client_ip(request)
        

        if self.is_ip_blocked(ip_address):
            logger.warning(f"Blocked request from {ip_address} - {request.get_full_path()}")
            return HttpResponseForbidden("Access denied: Your IP address is blocked.")

        path = request.get_full_path()
        
        geolocation_data = self.get_geolocation(ip_address)
        
        try:
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path,
                country=geolocation_data.get('country'),
                city=geolocation_data.get('city')
            )
            
            location_info = f"{geolocation_data.get('city', 'Unknown')}, {geolocation_data.get('country', 'Unknown')}"
            logger.info(f"Request logged: {ip_address} ({location_info}) - {path}")
            
        except Exception as e:
            logger.error(f"Error logging request: {e}")
        
        return None
    
    def get_geolocation(self, ip_address):
        """
        Get geolocation data for an IP address.
        Uses multiple fallback services and caches results for 24 hours.
        """
        if self.is_private_ip(ip_address):
            return {'country': 'Local', 'city': 'Local'}
        
        cache_key = f"geolocation_{ip_address}"
        cached_result = cache.get(cache_key)
        if cached_result is not None:
            return cached_result
        
        geolocation_data = self.fetch_geolocation_data(ip_address)
        

        cache.set(cache_key, geolocation_data, 86400)
        
        return geolocation_data
    
    def fetch_geolocation_data(self, ip_address):
        """
        Fetch geolocation data from multiple services with fallbacks.
        """
        services = [
            self.get_geolocation_ipapi,
            self.get_geolocation_ipgeolocation,
            self.get_geolocation_ipstack,
            self.get_geolocation_freeipapi
        ]
        
        for service in services:
            try:
                result = service(ip_address)
                if result and result.get('country'):
                    return result
            except Exception as e:
                logger.warning(f"Geolocation service failed for {ip_address}: {e}")
                continue
        
        return {'country': 'Unknown', 'city': 'Unknown'}
    
    def get_geolocation_ipapi(self, ip_address):
        """
        Get geolocation from ip-api.com (free, no API key required).
        """
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'city': data.get('city')
                    }
        except Exception as e:
            logger.debug(f"ip-api.com failed: {e}")
        return None
    
    # def get_geolocation_ipgeolocation(self, ip_address):
    #     """
    #     Get geolocation from ipgeolocation.io (requires API key).
    #     """
    #     api_key = getattr(settings, 'IPGEOLOCATION_API_KEY', None)
    #     if not api_key:
    #         return None
        
    #     try:
    #         response = requests.get(
    #             f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip_address}",
    #             timeout=5
    #         )
    #         if response.status_code == 200:
    #             data = response.json()
    #             return {
    #                 'country': data.get('country_name'),
    #                 'city': data.get('city')
    #             }
    #     except Exception as e:
    #         logger.debug(f"ipgeolocation.io failed: {e}")
    #     return None
    
    # def get_geolocation_ipstack(self, ip_address):
    #     """
    #     Get geolocation from ipstack.com (requires API key).
    #     """
    #     api_key = getattr(settings, 'IPSTACK_API_KEY', None)
    #     if not api_key:
    #         return None
        
    #     try:
    #         response = requests.get(
    #             f"http://api.ipstack.com/{ip_address}?access_key={api_key}",
    #             timeout=5
    #         )
    #         if response.status_code == 200:
    #             data = response.json()
    #             return {
    #                 'country': data.get('country_name'),
    #                 'city': data.get('city')
    #             }
    #     except Exception as e:
    #         logger.debug(f"ipstack.com failed: {e}")
    #     return None
    
    # def get_geolocation_freeipapi(self, ip_address):
    #     """
    #     Get geolocation from freeipapi.com (free, no API key required).
    #     """
    #     try:
    #         response = requests.get(
    #             f"https://freeipapi.com/api/json/{ip_address}",
    #             timeout=5
    #         )
    #         if response.status_code == 200:
    #             data = response.json()
    #             return {
    #                 'country': data.get('countryName'),
    #                 'city': data.get('cityName')
    #             }
    #     except Exception as e:
    #         logger.debug(f"freeipapi.com failed: {e}")
    #     return None
    
    def is_private_ip(self, ip_address):
        """
        Check if IP address is private/local.
        """
        import ipaddress
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return False
    
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
