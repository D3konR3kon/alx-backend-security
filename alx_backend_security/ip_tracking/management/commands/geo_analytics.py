from django.core.management.base import BaseCommand
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from ip_tracking.models import RequestLog

class Command(BaseCommand):
    help = 'Analyze geolocation data from request logs'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Number of days to analyze (default: 7)'
        )
        parser.add_argument(
            '--top',
            type=int,
            default=10,
            help='Number of top results to show (default: 10)'
        )
        parser.add_argument(
            '--type',
            choices=['country', 'city', 'ip', 'path'],
            default='country',
            help='Type of analysis to perform'
        )

    def handle(self, *args, **options):
        days = options['days']
        top = options['top']
        analysis_type = options['type']
        
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        logs = RequestLog.objects.filter(
            timestamp__gte=start_date,
            timestamp__lte=end_date
        )
        
        self.stdout.write(
            self.style.SUCCESS(f'\nGeolocation Analytics - Last {days} days')
        )
        self.stdout.write('=' * 50)
        
        total_requests = logs.count()
        self.stdout.write(f'Total requests analyzed: {total_requests}')
        
        if total_requests == 0:
            self.stdout.write(self.style.WARNING('No requests found in the specified period.'))
            return
        
        if analysis_type == 'country':
            self.analyze_countries(logs, top)
        elif analysis_type == 'city':
            self.analyze_cities(logs, top)
        elif analysis_type == 'ip':
            self.analyze_ips(logs, top)
        elif analysis_type == 'path':
            self.analyze_paths(logs, top)

    def analyze_countries(self, logs, top):
        """Analyze requests by country"""
        self.stdout.write(f'\nTop {top} Countries:')
        self.stdout.write('-' * 30)
        
        country_stats = logs.values('country').annotate(
            count=Count('id')
        ).order_by('-count')[:top]
        
        for stat in country_stats:
            country = stat['country'] or 'Unknown'
            count = stat['count']
            percentage = (count / logs.count()) * 100
            self.stdout.write(f'{country:<20} {count:>6} ({percentage:.1f}%)')

    def analyze_cities(self, logs, top):
        """Analyze requests by city"""
        self.stdout.write(f'\nTop {top} Cities:')
        self.stdout.write('-' * 30)
        
        city_stats = logs.values('city', 'country').annotate(
            count=Count('id')
        ).order_by('-count')[:top]
        
        for stat in city_stats:
            city = stat['city'] or 'Unknown'
            country = stat['country'] or 'Unknown'
            count = stat['count']
            percentage = (count / logs.count()) * 100
            location = f"{city}, {country}"
            self.stdout.write(f'{location:<30} {count:>6} ({percentage:.1f}%)')

    def analyze_ips(self, logs, top):
        """Analyze requests by IP address"""
        self.stdout.write(f'\nTop {top} IP Addresses:')
        self.stdout.write('-' * 40)
        
        ip_stats = logs.values('ip_address', 'country', 'city').annotate(
            count=Count('id')
        ).order_by('-count')[:top]
        
        for stat in ip_stats:
            ip = stat['ip_address']
            country = stat['country'] or 'Unknown'
            city = stat['city'] or 'Unknown'
            count = stat['count']
            location = f"{city}, {country}"
            self.stdout.write(f'{ip:<15} {location:<25} {count:>6}')

    def analyze_paths(self, logs, top):
        """Analyze requests by path"""
        self.stdout.write(f'\nTop {top} Requested Paths:')
        self.stdout.write('-' * 40)
        
        path_stats = logs.values('path').annotate(
            count=Count('id')
        ).order_by('-count')[:top]
        
        for stat in path_stats:
            path = stat['path']
            count = stat['count']
            percentage = (count / logs.count()) * 100
            self.stdout.write(f'{path:<50} {count:>6} ({percentage:.1f}%)')