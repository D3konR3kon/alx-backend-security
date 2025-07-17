from django.core.management.base import BaseCommand
from django.core.cache import cache
from ip_tracking.models import RequestLog
from ip_tracking.middleware import IPTrackingMiddleware

class Command(BaseCommand):
    help = 'Update missing geolocation data for existing request logs'

    def add_arguments(self, parser):
        parser.add_argument(
            '--limit',
            type=int,
            default=100,
            help='Maximum number of records to update (default: 100)'
        )

    def handle(self, *args, **options):
        limit = options['limit']
        
        logs_to_update = RequestLog.objects.filter(
            country__isnull=True
        ).exclude(
            ip_address__isnull=True
        ).exclude(
            ip_address__exact=''
        )[:limit]
        
        if not logs_to_update.exists():
            self.stdout.write(
                self.style.SUCCESS('No logs found with missing geolocation data.')
            )
            return

        self.stdout.write(
            f'Found {logs_to_update.count()} logs to update...'
        )
        
        middleware = IPTrackingMiddleware()
        updated_count = 0
        failed_count = 0
        
        for log in logs_to_update:
            try:
                geo_data = middleware.get_geolocation_data(log.ip_address)
                
                if geo_data:
                    log.country = geo_data.get('country')
                    log.city = geo_data.get('city')
                    log.region = geo_data.get('region')
                    log.latitude = geo_data.get('latitude')
                    log.longitude = geo_data.get('longitude')
                    log.save()
                    
                    updated_count += 1
                    self.stdout.write(
                        f'Updated log {log.id} for IP {log.ip_address}'
                    )
                else:
                    failed_count += 1
                    self.stdout.write(
                        self.style.WARNING(
                            f'Could not get geolocation data for IP {log.ip_address}'
                        )
                    )
                    
            except Exception as e:
                failed_count += 1
                self.stdout.write(
                    self.style.ERROR(
                        f'Error updating log {log.id} (IP: {log.ip_address}): {str(e)}'
                    )
                )

        self.stdout.write('\n' + '='*50)
        self.stdout.write(
            self.style.SUCCESS(f'Successfully updated: {updated_count} logs')
        )
        if failed_count > 0:
            self.stdout.write(
                self.style.WARNING(f'Failed to update: {failed_count} logs')
            )
        self.stdout.write('='*50)