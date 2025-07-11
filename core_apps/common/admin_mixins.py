# core_apps/common/admin_mixins.py

from django.contrib import admin

class SuperuserOnlyAdmin(admin.ModelAdmin):
    """
    Only allows superusers to view, add, edit, or delete.
    """

    def has_view_permission(self, request, obj=None):
        return request.user.is_superuser

    def has_add_permission(self, request):
        return request.user.is_superuser

    def has_change_permission(self, request, obj=None):
        return request.user.is_superuser

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser
