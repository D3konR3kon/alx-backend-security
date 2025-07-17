from django.contrib import admin
from .models import BlockedIP, RequestLog
from django.core.cache import cache
 
@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'path', 'timestamp']
    list_filter = ['timestamp', 'ip_address']
    search_fields = ['ip_address', 'path']
    readonly_fields = ['ip_address', 'timestamp', 'path']
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
    
@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'created_at', 'reason']
    list_filter = ['created_at']
    search_fields = ['ip_address', 'reason']
    readonly_fields = ['created_at']
    
    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        cache.delete(f"blocked_ip_{obj.ip_address}")
    
    def delete_model(self, request, obj):
        cache.delete(f"blocked_ip_{obj.ip_address}")
        super().delete_model(request, obj)