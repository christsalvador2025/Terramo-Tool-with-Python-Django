import secrets
import hashlib
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()


def get_client_ip(request):
    """
    Get client IP address from request, handling proxies and load balancers
    """
    # Check for IP in X-Forwarded-For header (common with proxies/load balancers)
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs, get the first one (original client)
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        # Check for IP in X-Real-IP header (Nginx proxy)
        x_real_ip = request.META.get('HTTP_X_REAL_IP')
        if x_real_ip:
            ip = x_real_ip.strip()
        else:
            # Fallback to REMOTE_ADDR
            ip = request.META.get('REMOTE_ADDR')
    
    # Clean up the IP address
    if ip:
        ip = ip.strip()
        # Handle IPv6 format with port (remove port if present)
        if ':' in ip and not ip.startswith('['):
            # This might be IPv4 with port, extract IP part
            parts = ip.split(':')
            if len(parts) == 2 and parts[1].isdigit():
                ip = parts[0]
    
    return ip


def create_login_token(user, expires_in_hours=1, ip_address=None, 
                      redirect_url=None, device_info=None):
    """
    Utility function to create a login token for a user
    
    Args:
        user: User instance
        expires_in_hours: Token expiration time in hours (default: 1)
        ip_address: IP address where token was requested
        redirect_url: URL to redirect after successful login
        device_info: Dictionary containing device/browser info
    
    Returns:
        tuple: (LoginToken instance, raw_token string)
    """
    from .models import AuthToken, LoginToken  # Import your token models
    
    # Revoke any existing active login tokens for this user
    AuthToken.objects.revoke_user_tokens(user, AuthToken.TokenType.LOGIN)
    
    # Create new auth token
    auth_token, raw_token = AuthToken.objects.create_token(
        user=user,
        token_type=AuthToken.TokenType.LOGIN,
        expires_in_hours=expires_in_hours,
        metadata={
            'created_for': 'login_request',
            'ip_address': ip_address,
            'device_info': device_info or {}
        }
    )
    
    # Set the IP address if provided
    if ip_address:
        auth_token.created_ip = ip_address
        auth_token.save()
    
    # Create login-specific token (if you're using the LoginToken model)
    try:
        login_token = LoginToken.objects.create(
            auth_token=auth_token,
            redirect_url=redirect_url or '',
            device_info=device_info or {},
            login_method='email_link'
        )
        return login_token, raw_token
    except Exception:
        # If LoginToken model doesn't exist or fails, just return the auth_token
        return auth_token, raw_token


def verify_login_token(raw_token, ip_address=None, user_agent=None):
    """
    Utility function to verify and use a login token
    
    Args:
        raw_token: The raw token string
        ip_address: IP address attempting to use token
        user_agent: Browser user agent string
    
    Returns:
        tuple: (User instance or None, error_message or None)
    """
    from .models import AuthToken  # Import your token model
    
    try:
        # Get valid token
        auth_token = AuthToken.objects.get_valid_token(
            raw_token=raw_token,
            token_type=AuthToken.TokenType.LOGIN
        )
        
        if not auth_token:
            return None, "Invalid or expired token"
        
        # Record the attempt
        auth_token.record_attempt(ip_address)
        
        # Check if token is still valid after recording attempt
        if not auth_token.is_valid:
            return None, "Token has been revoked due to too many attempts"
        
        # Use the token
        success = auth_token.use_token(ip_address, user_agent)
        
        if success:
            return auth_token.user, None
        else:
            return None, "Failed to use token"
            
    except Exception as e:
        # Log the error in production
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error verifying login token: {e}")
        return None, "An error occurred while verifying the token"


def generate_login_email(name, login_url, expires_in_minutes):
    """
    Generate login email content with secure URL
    
    Args:
        name: User's name for personalization
        login_url: The secure login URL
        expires_in_minutes: Minutes until token expires
    
    Returns:
        str: Email content
    """
    return f"""Hi {name},

You requested a secure login link for your client admin account.

Click the link below to log in to your account:
{login_url}

This link will expire in {expires_in_minutes} minutes for security purposes.

If you didn't request this login link, please ignore this email and contact support if you're concerned about your account security.

For security reasons, this link can only be used once.

Best regards,
Your Team"""


def generate_login_email_html(name, login_url, expires_in_minutes, company_name=None):
    """
    Generate HTML version of login email (optional - for better formatting)
    
    Args:
        name: User's name for personalization
        login_url: The secure login URL
        expires_in_minutes: Minutes until token expires
        company_name: Company name for branding
    
    Returns:
        str: HTML email content
    """
    company_display = f" - {company_name}" if company_name else ""
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Secure Login Link{company_display}</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
            .login-button {{ 
                display: inline-block; 
                background-color: #007bff; 
                color: white; 
                padding: 12px 24px; 
                text-decoration: none; 
                border-radius: 5px; 
                margin: 20px 0; 
            }}
            .footer {{ margin-top: 30px; font-size: 0.9em; color: #666; }}
            .warning {{ background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>Secure Login Request{company_display}</h2>
            </div>
            
            <p>Hi {name},</p>
            
            <p>You requested a secure login link for your client admin account.</p>
            
            <p>Click the button below to log in to your account:</p>
            
            <a href="{login_url}" class="login-button">Login to Your Account</a>
            
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; background-color: #f8f9fa; padding: 10px; border-radius: 3px;">
                {login_url}
            </p>
            
            <div class="warning">
                <strong>Important Security Information:</strong>
                <ul>
                    <li>This link will expire in <strong>{expires_in_minutes} minutes</strong></li>
                    <li>The link can only be used <strong>once</strong></li>
                    <li>If you didn't request this login, please ignore this email</li>
                </ul>
            </div>
            
            <div class="footer">
                <p>If you didn't request this login link, please ignore this email and contact support if you're concerned about your account security.</p>
                
                <p>Best regards,<br>Your Team</p>
            </div>
        </div>
    </body>
    </html>
    """


def send_login_email(user, client, login_token, raw_token):
    """
    High-level function to send login email with proper formatting
    
    Args:
        user: User instance
        client: Client instance
        login_token: LoginToken or AuthToken instance
        raw_token: Raw token string for URL generation
    
    Returns:
        bool: True if email sent successfully, False otherwise
    """
    from django.core.mail import EmailMultiAlternatives
    from django.conf import settings
    
    try:
        # Generate login URL
        login_url = f"{settings.FRONTEND_DOMAIN_URL}/auth/login-with-token/{raw_token}/"
        
        # Get user's name for personalization
        user_name = user.first_name or client.contact_person_first_name or "User"
        
        # Get expiration minutes
        if hasattr(login_token, 'auth_token'):
            expires_in_minutes = login_token.auth_token.expires_in_minutes
        else:
            expires_in_minutes = login_token.expires_in_minutes
        
        # Generate email content
        subject = f"Secure Login Link - {client.company_name}"
        text_content = generate_login_email(user_name, login_url, expires_in_minutes)
        html_content = generate_login_email_html(
            user_name, login_url, expires_in_minutes, client.company_name
        )
        
        # Create email message
        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email]
        )
        
        # Attach HTML version
        msg.attach_alternative(html_content, "text/html")
        
        # Send email
        msg.send(fail_silently=False)
        
        return True
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to send login email to {user.email}: {e}")
        return False


# Cleanup utility functions
def cleanup_expired_login_tokens():
    """
    Cleanup expired login tokens
    Should be run periodically (e.g., daily cron job)
    """
    from .models import AuthToken
    from django.utils import timezone
    from datetime import timedelta
    
    # Remove login tokens expired more than 7 days ago
    cleanup_date = timezone.now() - timedelta(days=7)
    
    deleted_count = AuthToken.objects.filter(
        token_type=AuthToken.TokenType.LOGIN,
        expires_at__lt=cleanup_date
    ).delete()[0]
    
    return deleted_count


def cleanup_expired_invitations():
    """
    Cleanup expired invitations and update their status
    Should be run periodically (e.g., daily cron job)
    """
    from .models import ClientInvitation
    from django.utils import timezone
    
    # Update expired invitations
    expired_count = ClientInvitation.objects.filter(
        expires_at__lt=timezone.now(),
        status__in=[
            ClientInvitation.InvitationStatus.PENDING,
            ClientInvitation.InvitationStatus.SENT,
            ClientInvitation.InvitationStatus.VIEWED,
            ClientInvitation.InvitationStatus.ACCEPTED,
        ]
    ).update(
        status=ClientInvitation.InvitationStatus.EXPIRED,
        is_active=False
    )
    
    return expired_count