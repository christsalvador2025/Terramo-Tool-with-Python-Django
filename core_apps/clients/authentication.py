from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken, TokenError
from django.conf import settings
# from core_apps.authentication.models import ClientAdmin   
from rest_framework.response import Response 
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.authentication import JWTAuthentication

 

def clear_auth_cookies(response: Response) -> None:
    """
    Clear access, refresh, and logged_in cookies during logout
    """
    response.delete_cookie("access", path=settings.COOKIE_PATH)
    response.delete_cookie("refresh", path=settings.COOKIE_PATH)
    response.delete_cookie("logged_in", path=settings.COOKIE_PATH)
