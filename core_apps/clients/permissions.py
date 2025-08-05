from rest_framework.permissions import BasePermission
from core_apps.authentication.models import ClientAdmin
# class IsAuthenticatedClientAdmin(BasePermission):
#     def has_permission(self, request, view):
#         return bool(request.user and hasattr(request.user, 'client') and request.user.is_authenticated)

class IsClientAdmin(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        token = request.auth  # this is the validated token
        print(f"AUTH---------- {request.auth} , ### COOKIES ---------- {request.COOKIES}")
        return token and token.get("role") == "client_admin"
