from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django_ratelimit.decorators import ratelimit
from django_ratelimit.core import is_ratelimited
from django.core.cache import cache
from .models import RequestLog, BlockedIP
import logging

logger = logging.getLogger(__name__)

def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def rate_limit_exceeded(request, exception):
    """Custom view for rate limit exceeded"""
    client_ip = get_client_ip(request)
    logger.warning(f"Rate limit exceeded for IP: {client_ip}")
    
    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please try again later.',
            'retry_after': getattr(exception, 'retry_after', 60)
        }, status=429)
    
    return render(request, 'ip_tracking/rate_limit_exceeded.html', {
        'retry_after': getattr(exception, 'retry_after', 60)
    }, status=429)

@ratelimit(key='ip', rate=settings.RATELIMIT_SETTINGS['LOGIN_RATE'], method='POST', block=True)
def login_view(request):
    """Login view with rate limiting"""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, 'Login successful!')
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid credentials.')

            logger.warning(f"Failed login attempt for username: {username} from IP: {get_client_ip(request)}")
    
    return render(request, 'ip_tracking/login.html')

def logout_view(request):
    """Logout view"""
    logout(request)
    messages.success(request, 'Logged out successfully!')
    return redirect('login')

@login_required
@ratelimit(key='user', rate=settings.RATELIMIT_SETTINGS['AUTHENTICATED_USER_RATE'], method='GET', block=True)
def dashboard(request):
    """Dashboard view for authenticated users"""
    recent_logs = RequestLog.objects.all()[:10]
    blocked_ips = BlockedIP.objects.all()[:5]
    
    context = {
        'recent_logs': recent_logs,
        'blocked_ips': blocked_ips,
        'total_requests': RequestLog.objects.count(),
        'total_blocked': BlockedIP.objects.count(),
    }
    return render(request, 'ip_tracking/dashboard.html', context)

@ratelimit(key='ip', rate=settings.RATELIMIT_SETTINGS['ANONYMOUS_USER_RATE'], method='GET', block=True)
def public_stats(request):
    """Public statistics view with rate limiting for anonymous users"""
    stats = {
        'total_requests': RequestLog.objects.count(),
        'unique_ips': RequestLog.objects.values('ip_address').distinct().count(),
        'total_blocked': BlockedIP.objects.count(),
    }
    
    if request.headers.get('Accept') == 'application/json':
        return JsonResponse(stats)
    
    return render(request, 'ip_tracking/public_stats.html', {'stats': stats})

@csrf_exempt
@require_http_methods(["POST"])
@ratelimit(key='ip', rate=settings.RATELIMIT_SETTINGS['SENSITIVE_ACTION_RATE'], method='POST', block=True)
def api_report_abuse(request):
    """API endpoint for reporting abuse - heavily rate limited"""
    try:
        client_ip = get_client_ip(request)
        
        logger.info(f"Abuse report received from IP: {client_ip}")
        
        
        return JsonResponse({
            'success': True,
            'message': 'Abuse report submitted successfully'
        })
    except Exception as e:
        logger.error(f"Error processing abuse report: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': 'Error processing report'
        }, status=500)

def check_rate_limit_status(request):
    """View to check rate limit status for debugging"""
    if not settings.DEBUG:
        return HttpResponse("Not available in production", status=404)
    
    client_ip = get_client_ip(request)
    user = request.user if request.user.is_authenticated else None
    
    limits = {}
    

    limits['ip_anonymous'] = is_ratelimited(
        request, 
        key='ip', 
        rate=settings.RATELIMIT_SETTINGS['ANONYMOUS_USER_RATE'],
        method='GET'
    )
    
    if user and user.is_authenticated:
        limits['user_authenticated'] = is_ratelimited(
            request,
            key='user',
            rate=settings.RATELIMIT_SETTINGS['AUTHENTICATED_USER_RATE'],
            method='GET'
        )
    
    limits['login_attempts'] = is_ratelimited(
        request,
        key='ip',
        rate=settings.RATELIMIT_SETTINGS['LOGIN_RATE'],
        method='POST'
    )
    
    return JsonResponse({
        'client_ip': client_ip,
        'user': str(user) if user else 'Anonymous',
        'rate_limits': limits,
        'cache_key_prefix': f'rl:{client_ip}' if not user else f'rl:{user.id}'
    })

def user_or_ip(group, request):
    """Return user ID for authenticated users, IP for anonymous users"""
    return str(request.user.id) if request.user.is_authenticated else get_client_ip(request)

def ip_and_user(group, request):
    """Return combination of IP and user for more strict limiting"""
    client_ip = get_client_ip(request)
    if request.user.is_authenticated:
        return f"{client_ip}:{request.user.id}"
    return client_ip

@ratelimit(key=user_or_ip, rate='10/m', method='GET', block=True)
def protected_resource(request):
    """Example of a protected resource with custom rate limiting"""
    return JsonResponse({
        'message': 'This is a protected resource',
        'user': str(request.user) if request.user.is_authenticated else 'Anonymous',
        'ip': get_client_ip(request)
    })