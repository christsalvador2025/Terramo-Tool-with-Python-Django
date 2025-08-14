# esg/permissions.py
from rest_framework import permissions


class ESGPermission(permissions.BasePermission):
    """
    Custom permission for ESG functionality
    """
    
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        user_role = request.user.role
        
        # Terramo admin has full access
        if user_role == 'terramo_admin':
            return True
        
        # Client admin and stakeholder have limited access
        if user_role in ['client_admin', 'stakeholder']:
            # They need to have a client
            return request.user.client is not None
        
        return False
    
    def has_object_permission(self, request, view, obj):
        if not request.user.is_authenticated:
            return False
        
        user_role = request.user.role
        
        # Terramo admin has full access
        if user_role == 'terramo_admin':
            return True
        
        # For responses, check if user can access
        if hasattr(obj, 'user'):
            if user_role == 'stakeholder':
                return obj.user == request.user
            elif user_role == 'client_admin':
                return obj.user.client == request.user.client
        
        return False


class IsStakeholder(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'stakeholder'


class IsClientAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'client_admin'


class IsTerramoAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'terramo_admin'