# core_apps/accounts/permissions.py
from rest_framework import permissions
from django.core.exceptions import PermissionDenied

class IsTerramoAdmin(permissions.BasePermission):
    """
    Permission for Terramo Admin only
    - Has access to everything
    - Can view all clients and their data
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "terramo_admin"

class IsClientAdmin(permissions.BasePermission):
    """
    Permission for Client Admin only
    - Can only access their own client's data
    - Cannot access other clients' data
    """
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated and 
            request.user.role == "client_admin" and
            request.user.client is not None  # Must be associated with a client
        )

    def has_object_permission(self, request, view, obj):
        """Client admin can only access objects related to their client"""
        if not request.user.is_authenticated or request.user.role != "client_admin":
            return False
            
        # Must have a client
        if not request.user.client:
            return False
        
        # Check based on the object type
        if hasattr(obj, 'client'):
            return obj.client == request.user.client
        elif hasattr(obj, 'client_admin') and hasattr(obj.client_admin, 'client'):
            return obj.client_admin.client == request.user.client
        elif hasattr(obj, 'stakeholder_group') and hasattr(obj.stakeholder_group, 'client'):
            return obj.stakeholder_group.client == request.user.client
        elif hasattr(obj, 'user') and hasattr(obj.user, 'client'):
            return obj.user.client == request.user.client
        # If object is a User, check if they belong to same client
        elif hasattr(obj, 'role') and hasattr(obj, 'client'):  # obj is a User
            return obj.client == request.user.client
            
        return False

class IsStakeholder(permissions.BasePermission):
    """
    Permission for Stakeholder only
    - Can only access their own data
    - Cannot access other stakeholders' data
    - Must belong to a client
    """
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated and 
            request.user.role == "stakeholder" and
            request.user.client is not None  # Must be associated with a client
        )

    def has_object_permission(self, request, view, obj):
        """Stakeholder can only access their own data"""
        if not request.user.is_authenticated or request.user.role != "stakeholder":
            return False
            
        # Must have a client
        if not request.user.client:
            return False
        
        # Stakeholders can only access their own objects
        if hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'stakeholder'):
            return obj.stakeholder == request.user
        elif hasattr(obj, 'created_by'):
            return obj.created_by == request.user
        # If object is the User themselves
        elif obj == request.user:
            return True
            
        return False

class IsClientAdminOrTerramoAdmin(permissions.BasePermission):
    """
    Permission that allows only client admins and terramo admins.
    - Terramo admin: Full access to everything
    - Client admin: Access only to their client's data
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        if request.user.role == 'terramo_admin':
            return True
            
        if request.user.role == 'client_admin':
            return request.user.client is not None
            
        return False
    
    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Terramo admins have access to everything
        if request.user.role == 'terramo_admin':
            return True
        
        # Client admins can only access objects related to their client
        if request.user.role == 'client_admin':
            if not request.user.client:
                return False
                
            # Check based on the object type
            if hasattr(obj, 'client'):
                return obj.client == request.user.client
            elif hasattr(obj, 'client_admin') and hasattr(obj.client_admin, 'client'):
                return obj.client_admin.client == request.user.client
            elif hasattr(obj, 'stakeholder_group') and hasattr(obj.stakeholder_group, 'client'):
                return obj.stakeholder_group.client == request.user.client
            elif hasattr(obj, 'user') and hasattr(obj.user, 'client'):
                return obj.user.client == request.user.client
            # If object is a User, check if they belong to same client
            elif hasattr(obj, 'role') and hasattr(obj, 'client'):  # obj is a User
                return obj.client == request.user.client
        
        return False

class IsStakeholderOrAdmin(permissions.BasePermission):
    """
    Permission that allows stakeholders, client admins, and terramo admins
    - Terramo admin: Full access
    - Client admin: Access to their client's data
    - Stakeholder: Access to their own data only
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        return request.user.role in ['terramo_admin', 'client_admin', 'stakeholder']
    
    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Terramo admins have access to everything
        if request.user.role == 'terramo_admin':
            return True
        
        # Client admins can access objects related to their client
        if request.user.role == 'client_admin':
            if not request.user.client:
                return False
                
            if hasattr(obj, 'client'):
                return obj.client == request.user.client
            elif hasattr(obj, 'user') and hasattr(obj.user, 'client'):
                return obj.user.client == request.user.client
            elif hasattr(obj, 'role') and hasattr(obj, 'client'):  # obj is a User
                return obj.client == request.user.client
        
        # Stakeholders can only access their own data
        if request.user.role == 'stakeholder':
            if not request.user.client:
                return False
                
            if hasattr(obj, 'user'):
                return obj.user == request.user
            elif hasattr(obj, 'stakeholder'):
                return obj.stakeholder == request.user
            elif hasattr(obj, 'created_by'):
                return obj.created_by == request.user
            elif obj == request.user:
                return True
        
        return False

class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Permission that allows owners of objects or admins
    - Terramo admin: Full access
    - Client admin: Access to their client's data
    - Object owner: Access to their own objects
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        if not request.user.is_authenticated:
            return False
        
        # Terramo admins have access to everything
        if request.user.role == 'terramo_admin':
            return True
        
        # Client admins can access objects related to their client
        if request.user.role == 'client_admin' and request.user.client:
            if hasattr(obj, 'client'):
                return obj.client == request.user.client
            elif hasattr(obj, 'user') and hasattr(obj.user, 'client'):
                return obj.user.client == request.user.client
            elif hasattr(obj, 'role') and hasattr(obj, 'client'):  # obj is a User
                return obj.client == request.user.client
        
        # Check if user owns the object
        if hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'created_by'):
            return obj.created_by == request.user
        elif hasattr(obj, 'owner'):
            return obj.owner == request.user
        elif obj == request.user:
            return True
        
        return False

# ============================================================================
# PERMISSION MIXINS FOR FUNCTION-BASED VIEWS
# ============================================================================

from functools import wraps
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied

def require_terramo_admin(view_func):
    """Decorator requiring terramo_admin role"""
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        if request.user.role != 'terramo_admin':
            raise PermissionDenied("Only Terramo Admins can access this resource")
        return view_func(request, *args, **kwargs)
    return wrapper

def require_client_admin(view_func):
    """Decorator requiring client_admin role"""
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        if request.user.role != 'client_admin' or not request.user.client:
            raise PermissionDenied("Only Client Admins can access this resource")
        return view_func(request, *args, **kwargs)
    return wrapper

def require_stakeholder(view_func):
    """Decorator requiring stakeholder role"""
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        if request.user.role != 'stakeholder' or not request.user.client:
            raise PermissionDenied("Only Stakeholders can access this resource")
        return view_func(request, *args, **kwargs)
    return wrapper

def require_admin_permissions(view_func):
    """Decorator requiring either terramo_admin or client_admin role"""
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        if request.user.role not in ['terramo_admin', 'client_admin']:
            raise PermissionDenied("Admin permissions required")
        if request.user.role == 'client_admin' and not request.user.client:
            raise PermissionDenied("Client admin must be associated with a client")
        return view_func(request, *args, **kwargs)
    return wrapper

def require_any_role(view_func):
    """Decorator allowing any authenticated user with a valid role"""
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        if request.user.role not in ['terramo_admin', 'client_admin', 'stakeholder']:
            raise PermissionDenied("Valid user role required")
        if request.user.role in ['client_admin', 'stakeholder'] and not request.user.client:
            raise PermissionDenied("User must be associated with a client")
        return view_func(request, *args, **kwargs)
    return wrapper

# ============================================================================
# CLASS-BASED VIEW MIXINS
# ============================================================================

from django.contrib.auth.mixins import LoginRequiredMixin

class RoleRequiredMixin(LoginRequiredMixin):
    """Base mixin for role-based permissions"""
    required_roles = []
    
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()
            
        if request.user.role not in self.required_roles:
            raise PermissionDenied(f"Access denied. Required roles: {self.required_roles}")
        
        # Additional validation for client-based roles
        if (request.user.role in ['client_admin', 'stakeholder'] and 
            not request.user.client):
            raise PermissionDenied("User must be associated with a client")
            
        return super().dispatch(request, *args, **kwargs)

class TerramoAdminRequiredMixin(RoleRequiredMixin):
    required_roles = ['terramo_admin']

class ClientAdminRequiredMixin(RoleRequiredMixin):
    required_roles = ['client_admin']

class StakeholderRequiredMixin(RoleRequiredMixin):
    required_roles = ['stakeholder']

class AdminRequiredMixin(RoleRequiredMixin):
    required_roles = ['terramo_admin', 'client_admin']

class AnyRoleRequiredMixin(RoleRequiredMixin):
    required_roles = ['terramo_admin', 'client_admin', 'stakeholder']

# ============================================================================
# UTILITY FUNCTIONS FOR PERMISSION CHECKING
# ============================================================================

def user_can_access_client_data(user, client):
    """Check if user can access specific client's data"""
    if user.role == 'terramo_admin':
        return True
    elif user.role == 'client_admin':
        return user.client == client
    elif user.role == 'stakeholder':
        return user.client == client
    return False

def user_can_modify_object(user, obj):
    """Check if user can modify an object"""
    if user.role == 'terramo_admin':
        return True
    
    # Client admin can modify objects in their client
    if user.role == 'client_admin' and user.client:
        if hasattr(obj, 'client'):
            return obj.client == user.client
        elif hasattr(obj, 'user') and hasattr(obj.user, 'client'):
            return obj.user.client == user.client
    
    # Stakeholders can only modify their own objects
    if user.role == 'stakeholder':
        if hasattr(obj, 'user'):
            return obj.user == user
        elif hasattr(obj, 'created_by'):
            return obj.created_by == user
        elif obj == user:
            return True
    
    return False

def get_user_accessible_clients(user):
    """Get clients that user can access"""
    from core_apps.clients.models import Client
    
    if user.role == 'terramo_admin':
        return Client.objects.all()
    elif user.role in ['client_admin', 'stakeholder'] and user.client:
        return Client.objects.filter(id=user.client.id)
    else:
        return Client.objects.none()

def filter_queryset_by_user_permissions(queryset, user):
    """Filter queryset based on user permissions"""
    if user.role == 'terramo_admin':
        return queryset
    elif user.role in ['client_admin', 'stakeholder'] and user.client:
        # Filter to only objects related to user's client
        model = queryset.model
        if hasattr(model, 'client'):
            return queryset.filter(client=user.client)
        elif hasattr(model, 'user'):
            if user.role == 'client_admin':
                return queryset.filter(user__client=user.client)
            else:  # stakeholder
                return queryset.filter(user=user)
    
    return queryset.none()

# ============================================================================
# EXAMPLE USAGE IN VIEWS
# ============================================================================

"""
# Example API View usage:
from rest_framework import viewsets
from .permissions import IsStakeholderOrAdmin, IsClientAdminOrTerramoAdmin

class SomeModelViewSet(viewsets.ModelViewSet):
    permission_classes = [IsStakeholderOrAdmin]
    
    def get_queryset(self):
        return filter_queryset_by_user_permissions(
            SomeModel.objects.all(), 
            self.request.user
        )

# Example Function-based view usage:
@require_stakeholder
def stakeholder_dashboard(request):
    # Only stakeholders can access this
    pass

@require_admin_permissions  
def admin_panel(request):
    # Only terramo_admin or client_admin can access
    pass

# Example Class-based view usage:
class StakeholderDashboardView(StakeholderRequiredMixin, TemplateView):
    template_name = 'stakeholder_dashboard.html'

class AdminPanelView(AdminRequiredMixin, ListView):
    model = SomeModel
    
    def get_queryset(self):
        return filter_queryset_by_user_permissions(
            super().get_queryset(), 
            self.request.user
        )
"""