from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from .models import Client, ClientProduct, Invitation
from django.utils import timezone
from django.contrib import messages
from datetime import timedelta
import uuid
from django.shortcuts import redirect
from django.utils.html import format_html
from django.urls import reverse
from django.conf import settings
from .models import Invitation, InvitationStatus, ClientInvitation
from django.template.defaultfilters import date as date_filter
 
@admin.register(ClientInvitation)
class ClientInvitation(admin.ModelAdmin):
    list_display = [
        "client",
        "token",
        "invite_url",
        "is_active",
        "email_verified",
        "is_accepted",
        # "year",
        "accepted_at"
     
    ]

    def invite_url(self, obj):
        return obj.get_invite_url()
    
    readonly_fields = ["token", "invite_url"]
@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "company_name",
        "email",
        "land",
     
    ]
    fieldsets = (
        
        ('Company Information', { 
            'fields': ('company_name', 'date',  'company_photo', 'role',)
        }),
        ('Contact Person', { 
            'fields': ('contact_person_first_name', 'contact_person_last_name', 'gender', 'year_of_birth', ),
            'description': 'Information about the primary contact for this client.', 
        }),
        ('Address Details', { 
            'fields': ('street', 'zip_code', 'location', 'landline_number', 'mobile_phone_number', 'city', 'land','email',),
            'description': 'Information about the address of the client', 
        }),
        (None, {"fields": ("is_active",'miscellaneous',)}),
    )

    readonly_fields = ["id", "invitation_token"]
    actions = ['send_invitation']
    # list_filter = ["company_name"]

    def contact_person(self, obj):
        """Display full contact person name"""
        return f"{obj.contact_person_first_name} {obj.contact_person_last_name}".strip()
    contact_person.short_description = 'Contact Person'
    def send_invitation(self, request, queryset):
        """Send invitation to selected clients"""
        count = 0
        for client in queryset:
            try:
                # Generate invitation token
                invitation_token = str(uuid.uuid4())
                expires_at = timezone.now() + timedelta(hours=24)
                
                client.invitation_token = invitation_token
                client.invitation_expires_at = expires_at
                client.save()
                
                # Here you would send the actual email
                # self._send_invitation_email(client, invitation_link)
                count += 1
                
            except Exception as e:
                messages.error(request, f"Failed to send invitation to {client.company_name}: {str(e)}")
        
        if count > 0:
            messages.success(request, f"Successfully sent {count} invitation(s)")
    send_invitation.short_description = "Send invitation to selected clients"
    

@admin.register(ClientProduct)
class ClientProductAdmin(admin.ModelAdmin):

    list_display = [
        "id",
        "client",
        "product",
        "purchased_at",
        'expires_at'

    ]
    list_filter = ["client", "product"]





"""
-----------------------------------------------------------------------------------------------------
"""
# @admin.register(Invitation)
# class InvitationAdmin(admin.ModelAdmin):
#     list_display = (
#         'email', 'client', 'invited_by', 'is_active', 'is_expired_display',
#         'expires_at', 'sent_at', 'accepted_at', 'invite_link_display',
#         'created_at'
#     )
#     list_filter = ('is_active', 'expires_at', 'client', 'invited_by')
#     search_fields = ('email', 'client__company_name')
#     readonly_fields = ('token', 'sent_at', 'accepted_at', 'created_at', 'updated_at')
#     actions = ['send_selected_invitations', 'deactivate_selected_invitations', 'activate_selected_invitations']

#     # --- Custom Column for Invite Link ---
#     @admin.display(description='Invite Link')
#     def invite_link_display(self, obj):
#         if obj.is_valid():
#             return format_html(
#                 '<input type="text" value="{}" size="50" readonly '
#                 'onclick="this.select(); document.execCommand(\'copy\'); alert(\'Link copied!\');" '
#                 'title="Click to copy link">'
#                 '<br><small>Click to copy</small>',
#                 obj.get_invite_url()
#             )
#         return "N/A (Invalid/Expired/Accepted)"

#     # --- Custom Column for Expired Status ---
#     @admin.display(boolean=True, description='Expired')
#     def is_expired_display(self, obj):
#         return obj.is_expired()
        
#     # --- Custom Admin Actions ---
#     @admin.action(description='Send selected invitations')
#     def send_selected_invitations(self, request, queryset):
#         for invitation in queryset:
#             if invitation.is_valid() and not invitation.sent_at:
#                 try:
#                     # Call your email sending function/task
#                     # send_invitation_email(invitation) 
#                     invitation.sent_at = timezone.now()
#                     invitation.save()
#                     self.message_user(request, f"Invitation sent to {invitation.email}.", messages.SUCCESS)
#                 except Exception as e:
#                     self.message_user(request, f"Failed to send invitation to {invitation.email}: {e}", messages.ERROR)
#             elif not invitation.is_valid():
#                 self.message_user(request, f"Invitation for {invitation.email} is not valid for sending.", messages.WARNING)
#             elif invitation.sent_at:
#                 self.message_user(request, f"Invitation to {invitation.email} already sent.", messages.INFO)
#         return redirect(request.get_full_path()) # Redirect back to the list view

#     @admin.action(description='Deactivate selected invitations')
#     def deactivate_selected_invitations(self, request, queryset):
#         updated = queryset.update(is_active=False)
#         self.message_user(request, f"Successfully deactivated {updated} invitations.", messages.SUCCESS)

#     @admin.action(description='Activate selected invitations')
#     def activate_selected_invitations(self, request, queryset):
#         updated = queryset.update(is_active=True)
#         self.message_user(request, f"Successfully activated {updated} invitations.", messages.SUCCESS)

#     # --- Customizing the "Add Invitation" form ---
  
#     def get_form(self, request, obj=None, **kwargs):
#         form = super().get_form(request, obj, **kwargs)
#         if not obj: # Only for new objects
#             form.base_fields['invited_by'].initial = request.user
#             # You might want to pre-fill client if the admin is associated with one
#             # if hasattr(request.user, 'client') and request.user.client:
#             #    form.base_fields['client'].initial = request.user.client
#         return form

#     # --- Customizing save_model for setting default expiration ---
#     def save_model(self, request, obj, form, change):
#         if not change and not obj.expires_at:
#             # Set a default expiration, e.g., 7 days from now
#             obj.expires_at = timezone.now() + timezone.timedelta(days=7)
#         obj.save()

#     # --- Override save_formset for inlines (if you use them) ---
#     def save_formset(self, request, form, formset, change):
#         instances = formset.save(commit=False)
#         for instance in instances:
#             if isinstance(instance, Invitation) and not instance.pk and not instance.expires_at:
#                 instance.expires_at = timezone.now() + timezone.timedelta(days=7)
#             instance.save()
#         formset.save_m2m()


"""
------------------------------------------------------------------------------------
"""

@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = (
        'email', 'client', 'invited_by', 'status_display', 'is_active', 'is_expired_display',
        'expires_at', 'sent_at', 'created_at', 'invite_link_display' # Reordered for better flow
    )
    list_filter = ('is_active', 'status', 'expires_at', 'client', 'invited_by')
    search_fields = ('email', 'client__company_name', 'invited_by__email')
    readonly_fields = ('token', 'sent_at', 'status', 'created_at', 'updated_at') # status is set by system

    actions = ['send_selected_invitations', 'deactivate_selected_invitations', 'activate_selected_invitations']

    # --- Custom Column for Invite Link ---
    @admin.display(description='Invite Link')
    def invite_link_display(self, obj):
        if obj.is_valid_for_acceptance(): # Check if valid for acceptance
            return format_html(
                '<input type="text" value="{}" size="50" readonly '
                'onclick="this.select(); document.execCommand(\'copy\'); alert(\'Link copied!\');" '
                'title="Click to copy link">'
                '<br><small style="color: grey;">Click to copy</small>',
                obj.get_invite_url()
            )
        return format_html('<span style="color: grey;">{}</span>', obj.get_status_display())

    # --- Custom Column for Expired Status ---
    @admin.display(boolean=True, description='Expired')
    def is_expired_display(self, obj):
        return obj.is_expired()
        
    # --- Custom Column for Status Display ---
    @admin.display(description='Status')
    def status_display(self, obj):
        color = 'black'
        if obj.status == InvitationStatus.NOT_ACCEPTED:
            color = 'blue'
        elif obj.status == InvitationStatus.ACCEPTED:
            color = 'orange'
        elif obj.status == InvitationStatus.REGISTERED:
            color = 'green'
        elif obj.is_expired(): # If expired, override status color
            color = 'red'
        
        return format_html('<span style="color: {}; font-weight: bold;">{}</span>', color, obj.get_status_display())

    # --- Custom Admin Actions ---
    @admin.action(description='Send selected invitations')
    def send_selected_invitations(self, request, queryset):
        sent_count = 0
        for invitation in queryset:
            # Ensure the user has permission to send this invite (Terramo Admin or Client Admin for their client)
            if not request.user.is_terramo_admin and (not request.user.is_client_admin or request.user.client != invitation.client):
                self.message_user(request, _(f"Permission denied to send invitation for {invitation.email}."), messages.ERROR)
                continue

            if invitation.is_valid_for_acceptance() and not invitation.sent_at:
                try:
                    # send_invitation_email(invitation) 
                    invitation.sent_at = timezone.now()
                    invitation.save()
                    sent_count += 1
                    self.message_user(request, _(f"Invitation sent to {invitation.email}."), messages.SUCCESS)
                except Exception as e:
                    self.message_user(request, _(f"Failed to send invitation to {invitation.email}: {e}"), messages.ERROR)
            elif not invitation.is_valid_for_acceptance():
                self.message_user(request, _(f"Invitation for {invitation.email} is not valid for sending (status: {invitation.get_status_display()}, active: {invitation.is_active}, expired: {invitation.is_expired()})."), messages.WARNING)
            elif invitation.sent_at:
                self.message_user(request, _(f"Invitation to {invitation.email} already sent at {date_filter(invitation.sent_at, 'DATETIME_FORMAT')}."), messages.INFO)
        
        if sent_count > 0:
            self.message_user(request, _(f"Successfully initiated sending for {sent_count} invitations."), messages.SUCCESS)
        return redirect(request.get_full_path()) 

    @admin.action(description='Deactivate selected invitations')
    def deactivate_selected_invitations(self, request, queryset):
        updated = 0
        for invitation in queryset:
            if not request.user.is_terramo_admin and (not request.user.is_client_admin or request.user.client != invitation.client):
                self.message_user(request, _(f"Permission denied to deactivate invitation for {invitation.email}."), messages.ERROR)
                continue
            invitation.is_active = False
            invitation.save()
            updated += 1
        self.message_user(request, _(f"Successfully deactivated {updated} invitations."), messages.SUCCESS)

    @admin.action(description='Activate selected invitations')
    def activate_selected_invitations(self, request, queryset):
        updated = 0
        for invitation in queryset:
            if not request.user.is_terramo_admin and (not request.user.is_client_admin or request.user.client != invitation.client):
                self.message_user(request, _(f"Permission denied to activate invitation for {invitation.email}."), messages.ERROR)
                continue
            invitation.is_active = True
            invitation.save()
            updated += 1
        self.message_user(request, _(f"Successfully activated {updated} invitations."), messages.SUCCESS)

    # --- Customizing the "Add Invitation" form ---
    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if not obj: # Only for new objects
            form.base_fields['invited_by'].initial = request.user
            # For Client Admins, pre-fill and restrict the client field
            if request.user.is_client_admin and request.user.client:
                form.base_fields['client'].initial = request.user.client
                form.base_fields['client'].disabled = True # Prevent changing client
            # For Terramo Admins, client field is enabled and required
            elif request.user.is_terramo_admin:
                form.base_fields['client'].required = True # Ensure client is selected
        return form

    def save_model(self, request, obj, form, change):
        # Set invited_by if not already set (e.g., if done programmatically)
        if not obj.invited_by_id:
            obj.invited_by = request.user
        
        # Set default expiration if not provided (only for new invites)
        if not change and not obj.expires_at:
            obj.expires_at = timezone.now() + timezone.timedelta(
                days=getattr(settings, 'INVITATION_EXPIRATION_DAYS', 1)
            )
        obj.save()