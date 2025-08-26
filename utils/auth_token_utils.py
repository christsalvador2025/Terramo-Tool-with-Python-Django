import logging
from django.utils import timezone
from core_apps.clients.models import ClientAdminLoginToken
from core_apps.authentication.models import StakeholderLoginToken, StakeholderInvitation
from core_apps.services.email_service import EmailService

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Utility to extract client IP from request META headers."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    return x_forwarded_for.split(",")[0] if x_forwarded_for else request.META.get("REMOTE_ADDR")


def generate_client_admin_token(user, request, invitation=None):
    """Generate and return a ClientAdmin login token + metadata."""
    print(f"user==={user}")
    # Invalidate previous unused tokens
    ClientAdminLoginToken.objects.filter(user=user, is_used=False).update(
        is_used=True, used_at=timezone.now()
    )

    # Create new token
    login_token = ClientAdminLoginToken.objects.create(
        user=user,
        client_invitation=invitation,
        ip_address=get_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
    )
    role_display = "Client Admin"
    user_name = user.first_name or getattr(user.client, "contact_person_first_name", "")
    login_url = login_token.get_login_url()

    logger.info(f"Generated client_admin login token for {user.email}: {login_token.token}")
    

    # Send email
    EmailService.send_login_token_email(user, login_url, role_display)

def generate_stakeholder_token(stakeholder, request, email):
    """Generate and return a Stakeholder login token + metadata."""
    # Invalidate previous unused tokens
    StakeholderLoginToken.objects.filter(stakeholder=stakeholder, is_used=False).update(
        is_used=True, used_at=timezone.now()
    )

    # Try to get latest invitation
    invitation = (
        StakeholderInvitation.objects.filter(
            email=email, stakeholder_group=stakeholder.group
        )
        .order_by("-sent_at")
        .first()
    )

    # Create new token
    login_token = StakeholderLoginToken.objects.create(
        stakeholder=stakeholder,
        stakeholder_invitation=invitation,
        ip_address=get_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
    )
    user = stakeholder
    role_display = "Stakeholder"
    stakeholder_name = stakeholder.first_name or stakeholder.email.split("@")[0]
    group_name = stakeholder.group.name
    login_url = login_token.get_login_url()

    logger.info(f"Generated stakeholder login token for {email}: {login_token.token}")
    EmailService.send_login_token_email(user, login_url, role_display)
    # return login_token, stakeholder_name, login_url, group_name
