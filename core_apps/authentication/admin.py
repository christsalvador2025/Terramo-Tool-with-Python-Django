from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
    ClientAdmin, Stakeholder, 
    StakeholderGroup, InvitationToken, LoginSession
)
from core_apps.clients.models import Client

# @admin.register(User)
# class UserAdmin(BaseUserAdmin):
#     list_display = ('email', 'username', 'role', 'is_active', 'date_joined')
#     list_filter = ('role', 'is_active', 'is_staff')
#     search_fields = ('email', 'username')
#     ordering = ('email',)

# @admin.register(Client)
# class ClientModelAdmin(admin.ModelAdmin):
#     list_display = ('company_name', 'email', 'created_at', 'created_by')
#     list_filter = ('created_at', 'products')
#     search_fields = ('company_name', 'email', 'first_name', 'last_name')
#     readonly_fields = ('id', 'created_at', 'updated_at')

# @admin.register(InvitationTokenData)
# class InvitationTokenDataAdmin(admin.ModelAdmin):
#     list_display = ('id', 'token', 'token_type')
    # list_filter = ('is_active', 'created_at')
    # search_fields = ('email', 'first_name', 'last_name', 'client__company_name')
    # readonly_fields = ('id', 'created_at')

@admin.register(ClientAdmin)
class ClientAdminModelAdmin(admin.ModelAdmin):
    list_display = ('email', 'client', 'is_active', 'created_at', 'last_login')
    list_filter = ('is_active', 'created_at')
    search_fields = ('email', 'first_name', 'last_name', 'client__company_name')
    readonly_fields = ('id', 'created_at')

@admin.register(StakeholderGroup)
class StakeholderGroupAdmin(admin.ModelAdmin):
    list_display = ('id','name', 'client', 'created_by', 'invitation_token','invite_full_url','created_at', 'is_active')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'client__company_name')
    fieldsets = (
        
        ('None', { 
            'fields': ('id', 'name', 'is_active', 'client', 'created_by', 'invitation_token',  )
        }),

    )
    readonly_fields=['invitation_token', 'id']

    def invite_full_url(self, obj):
        return f"{obj.get_invite_full_url()}"
    invite_full_url.short_description = 'Invitation url' 
    

@admin.register(Stakeholder)
class StakeholderAdmin(admin.ModelAdmin):
    list_display = ('email', 'group', 'is_registered', 'created_at', 'last_login')
    list_filter = ('is_registered', 'created_at', 'group__client')
    search_fields = ('email', 'first_name', 'last_name', 'group__name')

@admin.register(InvitationToken)
class InvitationTokenAdmin(admin.ModelAdmin):
    list_display = ('email', 'token_type', 'created_at', 'expires_at', 'is_used')
    list_filter = ('token_type', 'is_used', 'created_at')
    search_fields = ('email', 'token')
    readonly_fields = ('token', 'created_at', 'used_at')

@admin.register(LoginSession)
class LoginSessionAdmin(admin.ModelAdmin):
    list_display = ('session_type', 'created_at', 'expires_at', 'is_active')
    list_filter = ('session_type', 'is_active', 'created_at')
    readonly_fields = ('session_key', 'created_at')