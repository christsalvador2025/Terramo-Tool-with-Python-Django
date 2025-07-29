# accounts/permissions.py
from rest_framework import permissions

class IsTerramoAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_terramo_admin

class IsClientAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_client_admin

    def has_object_permission(self, request, view, obj):
        # Assuming obj is related to a Client (e.g., an Invitation or a Project)
        # Ensure the client admin can only access objects for their own client
        return request.user.client and obj.client == request.user.client