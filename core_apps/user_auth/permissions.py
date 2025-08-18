# accounts/permissions.py
from rest_framework import permissions

class IsTerramoAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "terramo_admin"

class IsClientAdminOrTerramoAdmin(permissions.BasePermission):
    """
    Permission that allows only client admins and terramo admins.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        return request.user.role in ['client_admin', 'terramo_admin']
    
    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Terramo admins have access to everything
        if request.user.role == 'terramo_admin':
            return True
        
        # Client admins can only access objects related to their client
        if request.user.role == 'client_admin':
            # Check based on the object type
            if hasattr(obj, 'client'):
                return obj.client == request.user.client
            elif hasattr(obj, 'group') and hasattr(obj.group, 'client'):
                return obj.group.client == request.user.client
            elif hasattr(obj, 'stakeholder_group') and hasattr(obj.stakeholder_group, 'client'):
                return obj.stakeholder_group.client == request.user.client
        
        return False
    
class IsClientAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "client_admin"

    def has_object_permission(self, request, view, obj):
        # Assuming obj is related to a Client (e.g., an Invitation or a Project)
        # Ensure the client admin can only access objects for their own client
        return request.user.client and obj.client == request.user.client