from django.core.management.base import BaseCommand
from django.core.cache import cache
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = 'Clear all blocked IP addresses'

    def add_arguments(self, parser):
        parser.add_argument(
            '--confirm',
            action='store_true',
            help='Confirm that you want to clear all blocked IPs'
        )

    def handle(self, *args, **options):
        if not options['confirm']:
            self.stdout.write(
                self.style.WARNING(
                    'This will remove ALL blocked IP addresses. '
                    'Use --confirm to proceed.'
                )
            )
            return

        blocked_ips = BlockedIP.objects.all()
        count = blocked_ips.count()
        
        if count == 0:
            self.stdout.write(
                self.style.SUCCESS('No blocked IP addresses to clear.')
            )
            return

        for blocked_ip in blocked_ips:
            cache.delete(f"blocked_ip_{blocked_ip.ip_address}")
            
        blocked_ips.delete()
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully cleared {count} blocked IP(s).')
        )
