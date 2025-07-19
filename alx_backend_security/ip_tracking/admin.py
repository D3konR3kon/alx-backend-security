from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import RequestLog, BlockedIP, SuspiciousIP
from alx_backend_security.ip_tracking import models

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'country', 'city', 'path', 'timestamp']
    list_filter = ['timestamp', 'country', 'city', 'ip_address']
    search_fields = ['ip_address', 'path', 'country', 'city']
    readonly_fields = ['ip_address', 'timestamp', 'path', 'country', 'city']
    date_hierarchy = 'timestamp'
    list_per_page = 50
    
    def has_add_permission(self, request):
        return False
    def has_change_permission(self, request, obj=None):
        return False

@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'created_at', 'reason_short']
    list_filter = ['created_at']
    search_fields = ['ip_address', 'reason']
    readonly_fields = ['created_at']
    date_hierarchy = 'created_at'
    
    def reason_short(self, obj):
        """Display shortened reason"""
        if obj.reason and len(obj.reason) > 50:
            return obj.reason[:50] + '...'
        return obj.reason or 'No reason provided'
    reason_short.short_description = 'Reason'
    
    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        from django.core.cache import cache
        cache.delete(f"blocked_ip_{obj.ip_address}")
    
    def delete_model(self, request, obj):
        from django.core.cache import cache
        cache.delete(f"blocked_ip_{obj.ip_address}")
        super().delete_model(request, obj)
    
    actions = ['clear_cache_for_selected']
    
    def clear_cache_for_selected(self, request, queryset):
        """Clear cache for selected blocked IPs"""
        from django.core.cache import cache
        count = 0
        for blocked_ip in queryset:
            cache.delete(f"blocked_ip_{blocked_ip.ip_address}")
            count += 1
        self.message_user(request, f'Cleared cache for {count} blocked IPs.')
    clear_cache_for_selected.short_description = "Clear cache for selected blocked IPs"

@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    list_display = [
        'ip_address', 
        'risk_level_colored',
        'detection_count', 
        'request_count',
        'days_since_detection',
        'is_investigated',
        'last_detected',
        'block_ip_link'
    ]
    list_filter = [
        'is_investigated',
        'detection_count',
        'last_detected',
        'first_detected'
    ]
    search_fields = ['ip_address', 'reason']
    readonly_fields = [
        'ip_address',
        'first_detected', 
        'last_detected',
        'detection_count',
        'risk_level',
        'days_since_first_detection'
    ]
    date_hierarchy = 'last_detected'
    list_per_page = 50

    class RiskLevelFilter(admin.SimpleListFilter):
        title = 'risk level'
        parameter_name = 'risk_level'
        
        def lookups(self, request, model_admin):
            return (
                ('HIGH', 'High Risk'),
                ('MEDIUM', 'Medium Risk'),
                ('LOW', 'Low Risk'),
            )
        
        def queryset(self, request, queryset):
            if self.value() == 'HIGH':
                return queryset.filter(
                    models.Q(detection_count__gte=10) | models.Q(request_count__gte=500)
                )
            elif self.value() == 'MEDIUM':
                return queryset.filter(
                    models.Q(detection_count__gte=5, detection_count__lt=10) |
                    models.Q(request_count__gte=200, request_count__lt=500)
                )
            elif self.value() == 'LOW':
                return queryset.filter(
                    detection_count__lt=5,
                    request_count__lt=200
                )
    
    list_filter = list_filter + [RiskLevelFilter]
    
    def risk_level_colored(self, obj):
        """Display risk level with color coding"""
        colors = {
            'HIGH': '#dc3545',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745'     
        }
        level = obj.risk_level
        color = colors.get(level, '#6c757d')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            level
        )
    risk_level_colored.short_description = 'Risk Level'
    risk_level_colored.admin_order_field = 'detection_count'
    
    def days_since_detection(self, obj):
        """Display days since first detection"""
        days = obj.days_since_first_detection
        if days == 0:
            return 'Today'
        elif days == 1:
            return '1 day ago'
        else:
            return f'{days} days ago'
    days_since_detection.short_description = 'First Detected'
    days_since_detection.admin_order_field = 'first_detected'
    
    def block_ip_link(self, obj):
        """Display link to block this IP"""
        try:
            BlockedIP.objects.get(ip_address=obj.ip_address)
            return format_html('<span style="color: #dc3545;">Already Blocked</span>')
        except BlockedIP.DoesNotExist:
            url = reverse('admin:ip_tracking_blockedip_add')
            return format_html(
                '<a href="{}?ip_address={}" class="button" style="background: #dc3545; color: white; padding: 5px 10px; text-decoration: none; border-radius: 3px;">Block IP</a>',
                url,
                obj.ip_address
            )
    block_ip_link.short_description = 'Actions'
    
    def reason_short(self, obj):
        """Display shortened reason"""
        if len(obj.reason) > 100:
            return obj.reason[:100] + '...'
        return obj.reason
    reason_short.short_description = 'Reason'
    
    fieldsets = (
        ('IP Information', {
            'fields': ('ip_address', 'risk_level')
        }),
        ('Detection Details', {
            'fields': ('reason', 'request_count', 'detection_count')
        }),
        ('Timeline', {
            'fields': ('first_detected', 'last_detected', 'days_since_first_detection')
        }),
        ('Investigation', {
            'fields': ('is_investigated',),
            'classes': ('collapse',)
        })
    )
    
    actions = [
        'mark_as_investigated',
        'mark_as_not_investigated',
        'block_selected_ips',
        'delete_low_risk'
    ]
    
    def mark_as_investigated(self, request, queryset):
        """Mark selected suspicious IPs as investigated"""
        count = queryset.update(is_investigated=True)
        self.message_user(request, f'Marked {count} suspicious IPs as investigated.')
    mark_as_investigated.short_description = "Mark selected as investigated"
    
    def mark_as_not_investigated(self, request, queryset):
        """Mark selected suspicious IPs as not investigated"""
        count = queryset.update(is_investigated=False)
        self.message_user(request, f'Marked {count} suspicious IPs as not investigated.')
    mark_as_not_investigated.short_description = "Mark selected as not investigated"
    
    def block_selected_ips(self, request, queryset):
        """Block selected suspicious IPs"""
        blocked_count = 0
        for suspicious_ip in queryset:
            blocked_ip, created = BlockedIP.objects.get_or_create(
                ip_address=suspicious_ip.ip_address,
                defaults={
                    'reason': f'Blocked from admin: {suspicious_ip.reason[:200]}'
                }
            )
            if created:
                blocked_count += 1
                from django.core.cache import cache
                cache.delete(f"blocked_ip_{suspicious_ip.ip_address}")
        
        self.message_user(
            request, 
            f'Blocked {blocked_count} IPs. {queryset.count() - blocked_count} were already blocked.'
        )
    block_selected_ips.short_description = "Block selected IPs"
    
    def delete_low_risk(self, request, queryset):
        """Delete low-risk suspicious IPs older than 3 days"""
        three_days_ago = timezone.now() - timezone.timedelta(days=3)
        low_risk_old = queryset.filter(
            detection_count__lt=5,
            request_count__lt=200,
            last_detected__lt=three_days_ago
        )
        count = low_risk_old.count()
        low_risk_old.delete()
        self.message_user(request, f'Deleted {count} low-risk old suspicious IP records.')
    delete_low_risk.short_description = "Delete old low-risk entries"
    
    def has_add_permission(self, request):
        return False