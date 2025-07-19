from celery import shared_task
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta
import logging

from .models import RequestLog, SuspiciousIP, BlockedIP

logger = logging.getLogger(__name__)

@shared_task(bind=True)
def detect_suspicious_ips(self):
    """
    Celery task to detect suspicious IP addresses based on:
    1. High request frequency (>100 requests/hour)
    2. Access to sensitive paths (/admin, /login, etc.)
    
    Runs hourly to analyze recent activity.
    """
    try:
        one_hour_ago = timezone.now() - timedelta(hours=1)
        
        logger.info(f"Starting anomaly detection for requests since {one_hour_ago}")

        stats = {
            'high_frequency_ips': 0,
            'sensitive_path_ips': 0,
            'new_suspicious_ips': 0,
            'total_processed_requests': 0
        }

        high_frequency_ips = detect_high_frequency_ips(one_hour_ago, stats)

        sensitive_path_ips = detect_sensitive_path_access(one_hour_ago, stats)

        all_suspicious_ips = {}
        all_suspicious_ips.update(high_frequency_ips)

        for ip, data in sensitive_path_ips.items():
            if ip in all_suspicious_ips:
                all_suspicious_ips[ip]['reason'] += f"; {data['reason']}"
                all_suspicious_ips[ip]['request_count'] += data['request_count']
            else:
                all_suspicious_ips[ip] = data

        for ip_address, data in all_suspicious_ips.items():
            suspicious_ip, created = SuspiciousIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={
                    'reason': data['reason'],
                    'request_count': data['request_count'],
                    'first_detected': timezone.now(),
                    'last_detected': timezone.now(),
                    'detection_count': 1
                }
            )
            
            if not created:
                suspicious_ip.reason = data['reason']
                suspicious_ip.request_count = data['request_count']
                suspicious_ip.last_detected = timezone.now()
                suspicious_ip.detection_count += 1
                suspicious_ip.save()
                logger.info(f"Updated suspicious IP {ip_address} (detection #{suspicious_ip.detection_count})")
            else:
                stats['new_suspicious_ips'] += 1
                logger.warning(f"New suspicious IP detected: {ip_address} - {data['reason']}")

        auto_block_repeat_offenders()
        
        logger.info(f"Anomaly detection completed. Stats: {stats}")
        
        return {
            'status': 'success',
            'stats': stats,
            'suspicious_ips_found': len(all_suspicious_ips)
        }
        
    except Exception as e:
        logger.error(f"Error in anomaly detection task: {str(e)}")
        raise


def detect_high_frequency_ips(one_hour_ago, stats):
    """Detect IPs with more than 100 requests in the last hour"""
    high_frequency_ips = {}

    high_freq_data = (RequestLog.objects
                     .filter(timestamp__gte=one_hour_ago)
                     .values('ip_address')
                     .annotate(request_count=Count('id'))
                     .filter(request_count__gt=100)
                     .order_by('-request_count'))
    
    for data in high_freq_data:
        ip_address = data['ip_address']
        request_count = data['request_count']
        
        high_frequency_ips[ip_address] = {
            'reason': f'High frequency requests: {request_count} requests/hour',
            'request_count': request_count
        }
        
        stats['high_frequency_ips'] += 1
        stats['total_processed_requests'] += request_count
    
    logger.info(f"Found {len(high_frequency_ips)} high frequency IPs")
    return high_frequency_ips

def detect_sensitive_path_access(one_hour_ago, stats):
    """Detect IPs accessing sensitive paths"""
    sensitive_path_ips = {}

    sensitive_paths = [
        '/admin',
        '/login',
        '/wp-admin',
        '/wp-login',
        '/.env',
        '/config',
        '/api/admin',
        '/dashboard',
        '/phpmyadmin',
        '/xmlrpc.php',
        '/robots.txt',
        '/.git',
        '/backup',
        '/uploads',
        '/wp-config.php'
    ]

    path_filter = Q()
    for path in sensitive_paths:
        path_filter |= Q(path__icontains=path)

    sensitive_access_data = (RequestLog.objects
                           .filter(timestamp__gte=one_hour_ago)
                           .filter(path_filter)
                           .values('ip_address')
                           .annotate(
                               request_count=Count('id'),
                               accessed_paths=Count('path', distinct=True)
                           )
                           .order_by('-request_count'))
    
    for data in sensitive_access_data:
        ip_address = data['ip_address']
        request_count = data['request_count']
        path_count = data['accessed_paths']

        paths_accessed = (RequestLog.objects
                         .filter(
                             timestamp__gte=one_hour_ago,
                             ip_address=ip_address
                         )
                         .filter(path_filter)
                         .values_list('path', flat=True)
                         .distinct()[:10])
        
        paths_list = list(paths_accessed)
        paths_str = ', '.join(paths_list[:5])
        if len(paths_list) > 5:
            paths_str += f' (and {len(paths_list) - 5} more)'

        reason = f'Accessing sensitive paths: {paths_str} ({request_count} requests to {path_count} sensitive endpoints)'
        
        sensitive_path_ips[ip_address] = {
            'reason': reason,
            'request_count': request_count
        }
        
        stats['sensitive_path_ips'] += 1
    
    logger.info(f"Found {len(sensitive_path_ips)} IPs accessing sensitive paths")
    return sensitive_path_ips


def auto_block_repeat_offenders():
    """Automatically block IPs that have been flagged as suspicious multiple times"""
    
    twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
    repeat_offenders = (SuspiciousIP.objects
                       .filter(
                           last_detected__gte=twenty_four_hours_ago,
                           detection_count__gte=5
                       )
                       .exclude(ip_address__in=BlockedIP.objects.values_list('ip_address', flat=True)))
    blocked_count = 0
    for suspicious_ip in repeat_offenders:
        blocked_ip, created = BlockedIP.objects.get_or_create(
            ip_address=suspicious_ip.ip_address,
            defaults={
                'reason': f'Auto-blocked: Repeated suspicious activity ({suspicious_ip.detection_count} detections). Last reason: {suspicious_ip.reason[:200]}'
            }
        )
        
        if created:
            blocked_count += 1
            logger.warning(f"Auto-blocked repeat offender: {suspicious_ip.ip_address}")

            from django.core.cache import cache
            cache.delete(f"blocked_ip_{suspicious_ip.ip_address}")
    
    if blocked_count > 0:
        logger.info(f"Auto-blocked {blocked_count} repeat offenders")


@shared_task(bind=True)
def cleanup_old_suspicious_ips(self):
    """
    Cleanup task to remove old suspicious IP records.
    Runs daily to keep the database clean.
    """
    try:

        seven_days_ago = timezone.now() - timedelta(days=7)
        
        deleted_count, _ = SuspiciousIP.objects.filter(
            last_detected__lt=seven_days_ago
        ).delete()
        
        logger.info(f"Cleaned up {deleted_count} old suspicious IP records")
        
        return {
            'status': 'success',
            'deleted_count': deleted_count
        }
        
    except Exception as e:
        logger.error(f"Error in cleanup task: {str(e)}")
        raise


@shared_task(bind=True)
def generate_security_report(self):
    """
    Generate a daily security report with suspicious activity summary.
    """
    try:
        twenty_four_hours_ago = timezone.now() - timedelta(hours=24)

        total_requests = RequestLog.objects.filter(timestamp__gte=twenty_four_hours_ago).count()
        unique_ips = RequestLog.objects.filter(timestamp__gte=twenty_four_hours_ago).values('ip_address').distinct().count()
        new_suspicious_ips = SuspiciousIP.objects.filter(first_detected__gte=twenty_four_hours_ago).count()
        total_blocked = BlockedIP.objects.count()
        
        top_suspicious = (SuspiciousIP.objects
                         .filter(last_detected__gte=twenty_four_hours_ago)
                         .order_by('-detection_count', '-request_count')[:10])
        
        report = {
            'timestamp': timezone.now().isoformat(),
            'period': '24 hours',
            'summary': {
                'total_requests': total_requests,
                'unique_ips': unique_ips,
                'new_suspicious_ips': new_suspicious_ips,
                'total_blocked_ips': total_blocked
            },
            'top_suspicious_ips': [
                {
                    'ip_address': ip.ip_address,
                    'detection_count': ip.detection_count,
                    'request_count': ip.request_count,
                    'reason': ip.reason[:100] + '...' if len(ip.reason) > 100 else ip.reason
                }
                for ip in top_suspicious
            ]
        }
        
        logger.info(f"Generated security report: {report['summary']}")
        
        return report
        
    except Exception as e:
        logger.error(f"Error generating security report: {str(e)}")
        raise