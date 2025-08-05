from django.conf import settings
from django.core.mail import send_mail
from rest_framework.response import Response
from typing import Optional

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


def set_authentication_cookies(
    response: Response,
    access_token: str,
    refresh_token: Optional[str] = None,
) -> None:
    """
    Set JWT access and refresh tokens as HTTP-only cookies
    """
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
        refresh_token_lifetime = settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds()
        refresh_cookie_settings = cookie_settings.copy()
        refresh_cookie_settings["max_age"] = refresh_token_lifetime
        response.set_cookie("refresh", refresh_token, **refresh_cookie_settings)

    # Optional: logged_in flag (not httpOnly) for frontend
    logged_in_cookie_settings = cookie_settings.copy()
    logged_in_cookie_settings["httponly"] = False
    response.set_cookie("logged_in", "true", **logged_in_cookie_settings)