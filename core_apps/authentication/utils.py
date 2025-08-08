from django.conf import settings
from django.core.mail import send_mail
from rest_framework.response import Response

def set_auth_cookies(response: Response, access_token: str, refresh_token: str = None) -> None:
    """Set authentication cookies"""
    access_token_lifetime = settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds()
    cookie_settings = {
        "path": settings.COOKIE_PATH,
        "secure": settings.COOKIE_SECURE,
        "httponly": settings.COOKIE_HTTPONLY,
        "samesite": settings.COOKIE_SAMESITE,
        "max_age": access_token_lifetime,
    }
    response.set_cookie("access", access_token, **cookie_settings)

    if refresh_token:
        refresh_token_lifetime = settings.SIMPLE_JWT[
            "REFRESH_TOKEN_LIFETIME"
        ].total_seconds()
        refresh_cookie_settings = cookie_settings.copy()
        refresh_cookie_settings["max_age"] = refresh_token_lifetime
        response.set_cookie("refresh", refresh_token, **refresh_cookie_settings)

    logged_in_cookie_settings = cookie_settings.copy()
    logged_in_cookie_settings["httponly"] = False
    response.set_cookie("logged_in", "true", **logged_in_cookie_settings)

def generate_invitation_email(first_name: str, company_name: str, invitation_link: str) -> str:
    """Generate invitation email content"""
    return f"""
    Dear {first_name},

    You have been invited to join the Terramo System as a Client Administrator for {company_name}.

    Please click the following link to accept your invitation and set up your account:
    {invitation_link}

    This invitation link will expire in 7 days.

    If you have any questions, please contact our support team.

    Best regards,
    Terramo Team
    """

def generate_login_email(first_name: str, login_link: str) -> str:
    """Generate login email content"""
    return f"""
    Dear {first_name},

    You have requested to login to the Terramo System.

    Please click the following link to login:
    {login_link}

    This login link will expire in 1 hour.

    If you did not request this login, please ignore this email.

    Best regards,
    Terramo Team
    """



 
from django.template.loader import render_to_string
from .models import StakeholderInvitation
import logging
from django.utils import timezone

logger = logging.getLogger(__name__)
def send_stakeholder_invitation_email(invitation):
    """
    Utility function to send stakeholder invitation email
    """
    try:
        subject = f"Invitation to join {invitation.stakeholder_group.name}"
        context = {
            'group_name': invitation.stakeholder_group.name,
            'invitation_url': invitation.get_invitation_url(),
            'company_name': invitation.stakeholder_group.client.company_name,
        }
        
        html_message = render_to_string('emails/stakeholder_invitation.html', context)
        plain_message = render_to_string('emails/stakeholder_invitation.txt', context)
        
        send_mail(
            subject=subject,
            message=plain_message,
            html_message=html_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[invitation.email],
            fail_silently=False,
        )
        
        invitation.email_status = 'delivered'
        invitation.save()
        
        logger.info(f"Invitation email sent successfully to {invitation.email}")
        return True
        
    except Exception as e:
        invitation.email_status = 'failed'
        invitation.save()
        
        logger.error(f"Failed to send invitation email to {invitation.email}: {str(e)}")
        return False

def cleanup_expired_invitations():
    """
    Utility function to cleanup expired invitations
    """
    
    
    expired_invitations = StakeholderInvitation.objects.filter(
        expires_at__lt=timezone.now(),
        status__in=['sent', 'clicked', 'email_verified']
    )
    
    count = expired_invitations.count()
    expired_invitations.update(status='expired')
    
    logger.info(f"Marked {count} invitations as expired")
    return count