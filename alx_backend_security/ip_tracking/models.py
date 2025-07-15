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
