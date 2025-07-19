# celery.py - Place this in your project root directory (same level as settings.py)

import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'your_project.settings')

app = Celery('your_project')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks()

app.conf.beat_schedule = {
    'detect-suspicious-ips': {
        'task': 'ip_tracking.tasks.detect_suspicious_ips',
        'schedule': 60.0 * 60,
        'options': {
            'expires': 60 * 50 
        }
    },
    'cleanup-old-suspicious-ips': {
        'task': 'ip_tracking.tasks.cleanup_old_suspicious_ips',
        'schedule': 60.0 * 60 * 24,
        'options': {
            'expires': 60 * 60 * 12 
        }
    },
    'generate-security-report': {
        'task': 'ip_tracking.tasks.generate_security_report',
        'schedule': 60.0 * 60 * 24,
        'options': {
            'expires': 60 * 60 * 12 
        }
    },
}

app.conf.timezone = 'UTC'

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')