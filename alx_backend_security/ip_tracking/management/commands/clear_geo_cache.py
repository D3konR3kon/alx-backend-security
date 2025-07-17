from django.core.management.base import BaseCommand
from django.core.cache import cache
from ip_tracking.models import RequestLog

class Command(BaseCommand):
    help = 'Clear geolocation cache for all IPs'

    def handle(self, *args, **options):
        unique_ips = RequestLog.objects.values_list('ip_address', flat=True).distinct()
        
        cleared_count = 0
        for ip in unique_ips:
            cache_key = f"geolocation_{ip}"
            if cache.delete(cache_key):
                cleared_count += 1
        
        self.stdout.write(
            self.style.SUCCESS(f'Cleared geolocation cache for {cleared_count} IP addresses.')
        )