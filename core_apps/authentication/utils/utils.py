# stakeholders/utils.py
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.db.models import Q
from datetime import timedelta
import logging

from .models import StakeholderInvitation

logger = logging.getLogger(__name__)

class InvitationEmailService:
    """Service class for handling invitation emails"""
    
    @staticmethod
    def send_invitation_email(invitation):
        """Send invitation email with error handling"""
        try:
            subject = f"Invitation to join {invitation.stakeholder_group.name}"
            message = InvitationEmailService._get_invitation_message(invitation)
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[invitation.email],
                fail_silently=False
            )
            
            invitation.email_status = 'delivered'
            invitation.save(update_fields=['email_status'])
            
            logger.info(f"Invitation email sent successfully to {invitation.email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send invitation email to {invitation.email}: {str(e)}")
            invitation.email_status = 'failed'
            invitation.save(update_fields=['email_status'])
            return False
    
    @staticmethod
    def _get_invitation_message(invitation):
        """Generate invitation email message"""
        return (
            f"Hello,\n\n"
            f"You have been invited to join the stakeholder group "
            f"'{invitation.stakeholder_group.name}' at {invitation.stakeholder_group.client.company_name}.\n\n"
            f"Click the following link to accept your invitation:\n"
            f"{invitation.get_invitation_url()}\n\n"
            f"This invitation will expire on {invitation.expires_at.strftime('%B %d, %Y at %I:%M %p')}.\n\n"
            f"If you did not expect this invitation, please ignore this email.\n\n"
            f"Best regards,\n"
            f"The {invitation.stakeholder_group.client.company_name} Team"
        )

class InvitationCleanupService:
    """Service for cleaning up expired invitations"""
    
    @staticmethod
    def cleanup_expired_invitations():
        """Mark expired invitations as expired"""
        try:
            expired_count = StakeholderInvitation.objects.filter(
                expires_at__lt=timezone.now(),
                status__in=['sent', 'clicked', 'email_verified']
            ).update(status='expired')
            
            if expired_count > 0:
                logger.info(f"Marked {expired_count} invitations as expired")
            
            return expired_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired invitations: {str(e)}")
            return 0
    
    @staticmethod
    def get_expiring_invitations(days=1):
        """Get invitations expiring within specified days"""
        expiry_threshold = timezone.now() + timedelta(days=days)
        
        return StakeholderInvitation.objects.filter(
            expires_at__lte=expiry_threshold,
            expires_at__gt=timezone.now(),
            status__in=['sent', 'clicked', 'email_verified']
        )

# class StakeholderAnalyticsService:
#     """Service for stakeholder analytics and reporting"""
    
#     @staticmethod
#     def get_invitation_stats(client):
#         """Get invitation statistics for a client"""
#         invitations = StakeholderInvitation.objects.filter(
#             stakeholder_group__client=client
#         )
        
#         stats = {
#             'total_invitations': invitations.count(),
#             'pending_invitations': invitations.filter(
#                 status__in=['sent', 'clicked', 'email_verified']
#             ).count(),
#             'completed_registrations': invitations.filter(
#                 status='completed'
#             ).count(),
#             'expired_invitations': invitations.filter(
#                 status='expired'
#             ).count(),
#             'email_delivery_stats': {
#                 'delivered': invitations.filter(email_status='delivered').count(),
#                 'failed': invitations.filter