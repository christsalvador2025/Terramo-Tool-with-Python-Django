from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
from core_apps.authentication.models import ClientAdmin  # or wherever your model is

class ClientAdminCookieAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        client_admin_id = validated_token.get("client_admin_id")
        if not client_admin_id:
            raise InvalidToken("Token missing client_admin_id")
        return ClientAdmin.objects.get(id=client_admin_id)
