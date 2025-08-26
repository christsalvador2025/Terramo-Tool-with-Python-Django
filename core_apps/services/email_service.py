from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class EmailService:
    """
    Centralized email service for all email operations
    """
    
    @staticmethod
    def send_login_token_email(user, login_url: str, role_display) -> bool:
        """Send login token email to user"""
        try:
            context = {
                'user': user,
                'expires_in_hours': 1,
                'login_url': login_url,
                'site_name': settings.SITE_NAME,
                'role_display': role_display,
            }
            
            html_content = render_to_string(
                'emails/login_token.html', 
                context
            )
            text_content = strip_tags(html_content)
            
            return send_mail(
                subject=f'Login Token for {settings.SITE_NAME}',
                message=text_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_content,
                fail_silently=False
            )
        except Exception as e:
            logger.error(f"Failed to send login token email to {user.email}: {e}")
            return False
    
    @staticmethod
    def send_invitation_email(user_info, inviter: str, role: str, invite_url: str) -> bool:
        """Send invitation email to participate"""
        # invitation_link = f"{settings.FRONTEND_DOMAIN_URL}/client-admin/accept-invitation/{invitation_token.token}"
        # role_endpoint = "/client-admin/accept-invitation/" if role == "client_admin" else "stakeholder"

            
        try:
            context = {
                'inviter': inviter, # who invites
                'role': role,
                'invitation_url': invite_url,
                'site_name': settings.SITE_NAME,
                'user_info': user_info,
                'support_mail': settings.TERRAMO_SUPPORT,
                'expiry_days': settings.SEND_INVITATION_EXPIRY,
                'role_permissions': {
                    'terramo_admin': ['Full access'],
                    'client_admin': ['ESG ( view question responses, charts and average)', 'Stakeholder Analysis ( if purchased )'],
                    'stakeholder': ['Answer Survey']
                }.get(user_info.get("role"), []),
            }
            
            html_content = render_to_string(
                'emails/send_invitation.html', 
                context
            )
            
            return send_mail(
                subject=f'You are invited to participate in {settings.SITE_NAME}',
                message=strip_tags(html_content),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user_info.get("email")],
                html_message=html_content
            )
        except Exception as e:
            logger.error(f"Failed to send invitation email to {user_info.get("email")}: {e}")
            return False
    
    @staticmethod
    def send_approval_status_email(user, status: str, details: str = None) -> bool:
        """Send approval/rejection notification"""
        try:
            is_approved = status == 'approved'
            template = 'notifications/approval_email.html' if is_approved else 'notifications/rejection_email.html'
            subject = f'Your request has been {"approved" if is_approved else "rejected"}'
            
            context = {
                'user': user,
                'status': status,
                'details': details,
                'is_approved': is_approved,
                'site_name': settings.SITE_NAME
            }
            
            html_content = render_to_string(template, context)
            
            return send_mail(
                subject=subject,
                message=strip_tags(html_content),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_content
            )
        except Exception as e:
            logger.error(f"Failed to send approval email to {user.email}: {e}")
            return False