from rest_framework import permissions

class IsTerramoAdmin(permissions.BasePermission):
    """Only Super Admin can access"""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role in ['super_admin', 'terramo_admin']

class IsCompanyAdmin(permissions.BasePermission):
    """Company Admin and Super Admin can access"""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role in ['super_admin', 'company_admin']

class IsCompanyUser(permissions.BasePermission):
    """Company users (including admins) can access"""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role in ['super_admin', 'company_admin', 'company_user']

class IsOwnerOrAdmin(permissions.BasePermission):
    """Owner of the object or admin can access"""
    def has_object_permission(self, request, view, obj):
        # Super admin can access everything
        if request.user.role == 'super_admin':
            return True
        
        # Company admin can access company objects
        if request.user.role == 'company_admin':
            if hasattr(obj, 'company') and obj.company == request.user.company:
                return True
        
        # Users can access their own objects
        if hasattr(obj, 'user') and obj.user == request.user:
            return True
        
        return False

class IsSameCompany(permissions.BasePermission):
    """Users can only access data from their own company"""
    def has_object_permission(self, request, view, obj):
        if request.user.role == 'super_admin':
            return True
        
        if hasattr(obj, 'company'):
            return obj.company == request.user.company
        
        return False