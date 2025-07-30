from rest_framework import permissions
from .models import LoginSession
from django.conf import settings

User = settings.AUTH_USER_MODEL
class IsTerramoAdmin(permissions.BasePermission):
    """Permission for Terramo Admin only"""
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            hasattr(request.user, 'role') and
            request.user.role == 'terramo_admin'
        )

class IsClientAdmin(permissions.BasePermission):
    """Permission for Client Admin"""
    
    def has_permission(self, request, view):
        session_key = request.COOKIES.get('session_key')
        if not session_key:
            return False
        
        try:
            session = LoginSession.objects.get(
                session_key=session_key,
                session_type='client_admin'
            )
            return session.is_valid()
        except LoginSession.DoesNotExist:
            return False

class IsStakeholder(permissions.BasePermission):
    """Permission for Stakeholder"""
    
    def has_permission(self, request, view):
        session_key = request.COOKIES.get('session_key')
        if not session_key:
            return False
        
        try:
            session = LoginSession.objects.get(
                session_key=session_key,
                session_type='stakeholder'
            )
            return session.is_valid()
        except LoginSession.DoesNotExist:
            return False