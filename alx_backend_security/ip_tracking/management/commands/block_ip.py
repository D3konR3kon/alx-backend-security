from django.core.management.base import BaseCommand, CommandError
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv4_address, validate_ipv6_address
from ip_tracking.models import BlockedIP
import ipaddress

class Command(BaseCommand):
    help = 'Block or unblock IP addresses'

    def add_arguments(self, parser):
        parser.add_argument('ip_address', type=str, help='IP address to block/unblock')
        parser.add_argument(
            '--unblock',
            action='store_true',
            help='Unblock the IP address instead of blocking it'
        )
        parser.add_argument(
            '--reason',
            type=str,
            help='Reason for blocking the IP address'
        )

    def handle(self, *args, **options):
        ip_address = options['ip_address']
        unblock = options['unblock']
        reason = options.get('reason', '')


        if not self.is_valid_ip(ip_address):
            raise CommandError(f'Invalid IP address: {ip_address}')

        if unblock:
            self.unblock_ip(ip_address)
        else:
            self.block_ip(ip_address, reason)

    def is_valid_ip(self, ip_address):
        """Validate if the IP address is valid IPv4 or IPv6"""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def block_ip(self, ip_address, reason):
        """Block an IP address"""
        try:
            blocked_ip, created = BlockedIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={'reason': reason}
            )
            
            if created:
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully blocked IP: {ip_address}')
                )
                if reason:
                    self.stdout.write(f'Reason: {reason}')
            else:
                self.stdout.write(
                    self.style.WARNING(f'IP {ip_address} is already blocked')
                )
                
                if reason and blocked_ip.reason != reason:
                    blocked_ip.reason = reason
                    blocked_ip.save()
                    self.stdout.write(f'Updated reason: {reason}')
            
            cache.delete(f"blocked_ip_{ip_address}")
            
        except Exception as e:
            raise CommandError(f'Error blocking IP {ip_address}: {str(e)}')

    def unblock_ip(self, ip_address):
        """Unblock an IP address"""
        try:
            blocked_ip = BlockedIP.objects.get(ip_address=ip_address)
            blocked_ip.delete()

            cache.delete(f"blocked_ip_{ip_address}")
            
            self.stdout.write(
                self.style.SUCCESS(f'Successfully unblocked IP: {ip_address}')
            )
            
        except BlockedIP.DoesNotExist:
            self.stdout.write(
                self.style.WARNING(f'IP {ip_address} is not blocked')
            )
        except Exception as e:
            raise CommandError(f'Error unblocking IP {ip_address}: {str(e)}')

