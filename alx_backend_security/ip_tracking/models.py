from django.db import models
from django.utils import timezone

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now)
    path = models.CharField(max_length=500)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['path']),
        ]
        
    def __str__(self):
        location = f"{self.city}, {self.country}" if self.city and self.country else "Unknown"
        return f"{self.ip_address} ({location}) - {self.path} - {self.timestamp}"


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    reason = models.TextField(blank=True, null=True)
    
    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['ip_address']),
        ]
        
    def __str__(self):
        return f"Blocked: {self.ip_address}"


class SuspiciousIP(models.Model):
    ip_address = models.GenericIPAddressField()
    reason = models.TextField()
    request_count = models.PositiveIntegerField(default=0)
    first_detected = models.DateTimeField(default=timezone.now)
    last_detected = models.DateTimeField(default=timezone.now)
    detection_count = models.PositiveIntegerField(default=1)
    is_investigated = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
        ordering = ['-last_detected', '-detection_count']
        indexes = [
            models.Index(fields=['ip_address', 'last_detected']),
            models.Index(fields=['last_detected']),
            models.Index(fields=['detection_count']),
        ]
    
    def __str__(self):
        return f"Suspicious: {self.ip_address} (detected {self.detection_count} times)"
    
    @property
    def risk_level(self):
        """Determine risk level based on detection count and request count"""
        if self.detection_count >= 10 or self.request_count >= 500:
            return 'HIGH'
        elif self.detection_count >= 5 or self.request_count >= 200:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    @property
    def days_since_first_detection(self):
        """Get number of days since first detection"""
        return (timezone.now() - self.first_detected).days
    
    def mark_investigated(self):
        """Mark this suspicious IP as investigated"""
        self.is_investigated = True
        self.save()
    
    def add_detection(self, reason, request_count=0):
        """Add a new detection event for this IP"""
        self.reason = reason
        self.request_count = request_count
        self.last_detected = timezone.now()
        self.detection_count += 1
        self.is_investigated = False  # Reset investigation status
        self.save()