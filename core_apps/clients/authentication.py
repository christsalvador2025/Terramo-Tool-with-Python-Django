from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken, TokenError
from django.conf import settings
from core_apps.authentication.models import ClientAdmin   
from rest_framework.response import Response 
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.authentication import JWTAuthentication

class ClientAdminJWTAuthenticationAccess(JWTAuthentication):
    def get_user(self, validated_token):
        client_admin_id = validated_token.get("client_admin_id")
        if not client_admin_id:
            raise InvalidToken("Token contained no recognizable client_admin_id")

        try:
            return ClientAdmin.objects.get(id=client_admin_id)
        except ClientAdmin.DoesNotExist:
            raise InvalidToken("ClientAdmin not found")
class ClientAdminJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        token = request.COOKIES.get("access")
        if not token:
            return None  # Let DRF try the next auth class

        try:
            validated_token = AccessToken(token)
            client_admin_id = validated_token.get("client_admin_id")
            if not client_admin_id:
                raise AuthenticationFailed("Token missing client_admin_id")

            client_admin = ClientAdmin.objects.filter(id=client_admin_id).first()
            if not client_admin:
                raise AuthenticationFailed("ClientAdmin not found")

            return (client_admin, None)
        except TokenError:
            raise AuthenticationFailed("Invalid or expired token")


def clear_auth_cookies(response: Response) -> None:
    """
    Clear access, refresh, and logged_in cookies during logout
    """
    response.delete_cookie("access", path=settings.COOKIE_PATH)
    response.delete_cookie("refresh", path=settings.COOKIE_PATH)
    response.delete_cookie("logged_in", path=settings.COOKIE_PATH)
