from django.contrib import admin
from cloudinary.forms import CloudinaryFileField
from django import forms
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from core_apps.common.admin_mixins import SuperuserOnlyAdmin
from .models import StakeholderGroup, StakeholderInvitation

@admin.register(StakeholderGroup)
class StakeholderGroupAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "client",
        "name",
        "unique_group_token",
        "is_active",
    ]
    list_filter = ["client", "name", "is_active"]
    readonly_fields = ["unique_group_token"]

@admin.register(StakeholderInvitation)
class StakeholderInvitationAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "stakeholder_group",
        "email",
        "invite_token",
        "status",
        "sent_at",
        "accepted_at",
        "expires_at",
    ]
    
    readonly_fields = ["invite_token"]
