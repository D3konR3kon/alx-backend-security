from django.db import models
from django.utils import timezone

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now)
    path = models.CharField(max_length=500)
    
    class Meta:
        ordering = ['-timestamp']
        
    def __str__(self):
        return f"{self.ip_address} - {self.path} - {self.timestamp}"

class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    reason = models.TextField(blank=True, null=True)
    
    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        ordering = ['-created_at']
        
    def __str__(self):
        return f"Blocked: {self.ip_address}"