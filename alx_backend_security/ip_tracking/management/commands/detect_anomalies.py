from django.core.management.base import BaseCommand
from django.utils import timezone
from ip_tracking.tasks import detect_suspicious_ips, generate_security_report


class Command(BaseCommand):
    help = 'Manually run anomaly detection for suspicious IPs'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--report',
            action='store_true',
            help='Also generate security report',
        )
        parser.add_argument(
            '--sync',
            action='store_true',
            help='Run synchronously instead of as Celery task',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Verbose output',
        )
    
    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS(f'Starting anomaly detection at {timezone.now()}')
        )
        
        try:
            if options['sync']:
                # Run synchronously (useful for testing)
                result = detect_suspicious_ips()
                self.stdout.write(
                    self.style.SUCCESS(f'Anomaly detection completed: {result}')
                )
                
                if options['report']:
                    report_result = generate_security_report()
                    self.stdout.write(
                        self.style.SUCCESS(f'Security report generated: {report_result["summary"]}')
                    )
            else:
                # Run as Celery task
                task = detect_suspicious_ips.delay()
                self.stdout.write(
                    self.style.SUCCESS(f'Anomaly detection task started: {task.id}')
                )
                
                if options['report']:
                    report_task = generate_security_report.delay()
                    self.stdout.write(
                        self.style.SUCCESS(f'Security report task started: {report_task.id}')
                    )
                
                if options['verbose']:
                    self.stdout.write('Waiting for task completion...')
                    result = task.get(timeout=60)
                    self.stdout.write(
                        self.style.SUCCESS(f'Task completed: {result}')
                    )
        
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error running anomaly detection: {str(e)}')
            )
            raise
        
        self.stdout.write(
            self.style.SUCCESS('Anomaly detection command finished')
        )
