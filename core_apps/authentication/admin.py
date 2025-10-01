from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
     Stakeholder, 
    StakeholderGroup, InvitationToken, LoginSession, LoginToken, AuthToken, StakeholderInvitation,
    StakeholderLoginToken
   
)
from core_apps.clients.models import Client

 

@admin.register(StakeholderInvitation)
class StakeholderInvitationAdmin(admin.ModelAdmin):
    list_display = ('id','email', 'stakeholder_group', 'status','invitation_token',)

@admin.register(StakeholderLoginToken)
class StakeholderLoginTokenAdmin(admin.ModelAdmin):
    list_display = ('id','token', 'stakeholder', 'is_used','expires_at','is_expired_display',)

    @admin.display(boolean=True, description='Expired')
    def is_expired_display(self, obj):
        return obj.is_expired()


@admin.register(LoginToken)
class LoginTokenAdmin(admin.ModelAdmin):
    pass

@admin.register(AuthToken)
class AuthTokenAdmin(admin.ModelAdmin):
    pass
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

# @admin.register(ClientAdmin)
# class ClientAdminModelAdmin(admin.ModelAdmin):
#     list_display = ('email', 'client', 'is_active', 'created_at', 'last_login')
#     list_filter = ('is_active', 'created_at')
#     search_fields = ('email', 'first_name', 'last_name', 'client__company_name')
#     readonly_fields = ('id', 'created_at')

@admin.register(StakeholderGroup)
class StakeholderGroupAdmin(admin.ModelAdmin):
    list_display = ('id','name', 'client_display', 'is_global_group','show_in_table','created_by', 'invitation_token','invite_full_url','created_at', 'is_active')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'client__company_name')
    fieldsets = (
        
        ('None', { 
            'fields': ('id', 'name', 'is_active', 'client',  'is_global', 'show_in_table', 'created_by', 'invitation_token', 'disable_the_invitation', )
        }),

    )
    readonly_fields=['invitation_token', 'id']

    def invite_full_url(self, obj):
        return f"{obj.get_invite_full_url()}"
    invite_full_url.short_description = 'Invitation url' 

    def is_global_group(self, obj):
        """Custom actions column"""
        actions = []
        if obj.is_global:
            # actions.append('🌐 Global')
            return format_html(
                '<span style="color: #28a745; font-weight: bold;">🌐 Global</span>'
            )
        else:
            # actions.append('🏢 Custom')
            return format_html(
                '<span style="color: #28a745; font-weight: bold;">🏢 Custom</span>'
            )
        # if obj.get_stakeholder_count() > 0:
        #     stakeholder_url = reverse('admin:authentication_stakeholderterramo_changelist') + f'?group__id__exact={obj.id}'  # Replace 'your_app'
        #     actions.append(format_html('<a href="{}">View Stakeholders</a>', stakeholder_url))
        # return format_html(' | '.join(actions)) if actions else "No actions"
    is_global_group.short_description = "Actions"
    
    def client_display(self, obj):
        """Display client name or 'Global' for templates"""
        if obj.is_global:
            return format_html('<strong style="color: #007cba;">Global Group</strong>')
        elif obj.client:
            client_url = reverse('admin:clients_client_change', args=[obj.client.id])  
            return format_html('<a href="{}">{}</a>', client_url, obj.client.company_name)
        return "No Client"
    client_display.short_description = "Client"

@admin.register(Stakeholder)
class StakeholderAdmin(admin.ModelAdmin):
    list_display = ('id','email', 'group','client', 'is_registered', 'created_at', 'last_login')
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



"""
Django Admin Configuration for Stakeholder Management Models
Optimized for multi-tenant functionality with proper filtering and permissions
"""
from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from django.db.models import Count, Q
from django.contrib.admin import SimpleListFilter
from .models import (
    StakeholderGroupTerramo, 
    StakeholderGroupInvitationTerramo, 
    StakeholderTerramo,
    StakeholderActivityLog
)


# Custom Filters
class GroupTypeFilter(SimpleListFilter):
    """Filter stakeholder groups by type (Template, Custom, From Template)"""
    title = 'Group Type'
    parameter_name = 'group_type'

    def lookups(self, request, model_admin):
        return (
            ('template', 'Template'),
            ('custom', 'Custom'),
            ('from_template', 'From Template'),
        )

    def queryset(self, request, queryset):
        if self.value() == 'template':
            return queryset.filter(client__isnull=True, template__isnull=True)
        if self.value() == 'custom':
            return queryset.filter(client__isnull=False, template__isnull=True)
        if self.value() == 'from_template':
            return queryset.filter(template__isnull=False)
        return queryset


class ClientFilter(SimpleListFilter):
    """Filter by client with special handling for templates"""
    title = 'Client'
    parameter_name = 'client'

    def lookups(self, request, model_admin):
        # Get all clients that have stakeholder groups
        from django.apps import apps
        try:
            Client = apps.get_model('your_app', 'Client')  # Replace 'your_app' with your app name
            clients = Client.objects.filter(
                stakeholder_groups_terramo__isnull=False
            ).distinct()
            choices = [('templates', 'Templates (Global)')]
            choices.extend([(str(client.id), str(client.company_name)) for client in clients])
            return choices
        except:
            return [('templates', 'Templates (Global)')]

    def queryset(self, request, queryset):
        if self.value() == 'templates':
            return queryset.filter(client__isnull=True)
        elif self.value():
            return queryset.filter(client__id=self.value())
        return queryset


class InvitationStatusFilter(SimpleListFilter):
    """Filter invitations by status"""
    title = 'Invitation Status'
    parameter_name = 'invitation_status'

    def lookups(self, request, model_admin):
        return (
            ('active', 'Active'),
            ('expired', 'Expired'),
            ('used', 'Used'),
            ('unused', 'Unused'),
        )

    def queryset(self, request, queryset):
        now = timezone.now()
        if self.value() == 'active':
            return queryset.filter(
                is_active=True
            ).filter(
                Q(expires_at__gt=now) | Q(expires_at__isnull=True)
            )
        elif self.value() == 'expired':
            return queryset.filter(expires_at__lte=now, expires_at__isnull=False)
        elif self.value() == 'used':
            return queryset.filter(used_at__isnull=False)
        elif self.value() == 'unused':
            return queryset.filter(used_at__isnull=True)
        return queryset


# Inline Admin Classes
class StakeholderInline(admin.TabularInline):
    """Inline for stakeholders in group admin"""
    model = StakeholderTerramo
    extra = 0
    readonly_fields = ('id', 'created_at', 'last_login', 'invitation_used')
    fields = (
        'email', 'first_name', 'last_name', 'client', 'status', 
        'is_active', 'is_registered', 'created_at'
    )
    
    def has_add_permission(self, request, obj=None):
        return request.user.is_superuser or getattr(request.user, 'role', None) == 'terramo_admin'


class InvitationInline(admin.TabularInline):
    """Inline for invitations in group admin"""
    model = StakeholderGroupInvitationTerramo
    extra = 0
    readonly_fields = ('id', 'token', 'created_at', 'invitation_url_link')
    fields = (
        'created_by', 'expires_at', 'is_active', 'max_uses', 
        'current_uses', 'message', 'invitation_url_link'
    )
    
    def invitation_url_link(self, obj):
        if obj.id:
            url = obj.get_invitation_url()
            return format_html('<a href="{}" target="_blank">{}</a>', url, url)
        return "Save to generate URL"
    invitation_url_link.short_description = "Invitation URL"


# Main Admin Classes
# @admin.register(StakeholderGroupTerramo)
# class StakeholderGroupTerramoAdmin(admin.ModelAdmin):
#     list_display = [
#         'name', 'group_type_badge', 'client_display', 'stakeholder_count', 
#         'pending_invitations', 'is_active', 'created_at', 'actions_column'
#     ]
#     list_filter = [GroupTypeFilter, ClientFilter, 'is_active', 'created_at']
#     search_fields = ['name', 'description', 'client__company_name']
#     readonly_fields = ['id', 'created_at', 'updated_at', 'stakeholder_count_detailed']
#     ordering = ['sort_order', 'name']
    
#     fieldsets = (
#         ('Basic Information', {
#             'fields': ('name', 'description', 'sort_order', 'is_active')
#         }),
#         ('Relationships', {
#             'fields': ('client', 'template', 'created_by')
#         }),
#         ('Timestamps', {
#             'fields': ('id', 'created_at', 'updated_at'),
#             'classes': ('collapse',)
#         }),
#         ('Statistics', {
#             'fields': ('stakeholder_count_detailed',),
#             'classes': ('collapse',)
#         }),
#     )
    
#     inlines = [StakeholderInline, InvitationInline]
    
#     def get_queryset(self, request):
#         qs = super().get_queryset(request)
#         return qs.select_related('client', 'template', 'created_by').annotate(
#             total_stakeholders=Count('stakeholders', filter=Q(stakeholders__is_active=True)),
#             total_invitations=Count('invitations', filter=Q(
#                 invitations__is_active=True
#             ) & (Q(invitations__expires_at__gt=timezone.now()) | Q(invitations__expires_at__isnull=True)))
#         )
    
#     def group_type_badge(self, obj):
#         """Display group type with color coding"""
#         if obj.is_template:
#             return format_html(
#                 '<span style="color: #007cba; font-weight: bold;">🌐 Template</span>'
#             )
#         elif obj.is_custom:
#             return format_html(
#                 '<span style="color: #28a745; font-weight: bold;">🏢 Custom</span>'
#             )
#         elif obj.is_from_template:
#             return format_html(
#                 '<span style="color: #ffc107; font-weight: bold;">📋 From Template</span>'
#             )
#         return "Unknown"
#     group_type_badge.short_description = "Type"
#     group_type_badge.admin_order_field = 'client'
    
#     def client_display(self, obj):
#         """Display client name or 'Global' for templates"""
#         if obj.is_template:
#             return format_html('<strong style="color: #007cba;">Global Template</strong>')
#         elif obj.client:
#             client_url = reverse('admin:clients_client_change', args=[obj.client.id])  # Replace 'your_app'
#             return format_html('<a href="{}">{}</a>', client_url, obj.client.company_name)
#         return "No Client"
#     client_display.short_description = "Client"
#     client_display.admin_order_field = 'client__company_name'
    
#     def stakeholder_count(self, obj):
#         """Display stakeholder count"""
#         count = getattr(obj, 'total_stakeholders', 0)
#         if count > 0:
#             return format_html(
#                 '<span style="color: #28a745; font-weight: bold;">{}</span>', count
#             )
#         return count
#     stakeholder_count.short_description = "Stakeholders"
#     stakeholder_count.admin_order_field = 'total_stakeholders'
    
#     def pending_invitations(self, obj):
#         """Display pending invitations count"""
#         count = getattr(obj, 'total_invitations', 0)
#         if count > 0:
#             return format_html(
#                 '<span style="color: #ffc107; font-weight: bold;">{}</span>', count
#             )
#         return count
#     pending_invitations.short_description = "Pending Invites"
#     pending_invitations.admin_order_field = 'total_invitations'
    
#     def stakeholder_count_detailed(self, obj):
#         """Detailed stakeholder statistics"""
#         if obj.id:
#             if obj.is_template:
#                 # For templates, show count per client
#                 clients = obj.stakeholders.values('client__company_name').annotate(
#                     count=Count('id', filter=Q(is_active=True))
#                 ).order_by('client__company_name')
                
#                 stats = []
#                 for client in clients:
#                     if client['count'] > 0:
#                         stats.append(f"{client['client__company_name']}: {client['count']}")
                
#                 if stats:
#                     return format_html('<br>'.join(stats))
#                 return "No stakeholders yet"
#             else:
#                 return f"Total active stakeholders: {obj.get_stakeholder_count()}"
#         return "Save to see statistics"
#     stakeholder_count_detailed.short_description = "Detailed Statistics"
    
#     def actions_column(self, obj):
#         """Custom actions column"""
#         actions = []
#         if obj.is_template:
#             actions.append('🌐 Global')
#         if obj.get_stakeholder_count() > 0:
#             stakeholder_url = reverse('admin:authentication_stakeholderterramo_changelist') + f'?group__id__exact={obj.id}'  # Replace 'your_app'
#             actions.append(format_html('<a href="{}">View Stakeholders</a>', stakeholder_url))
#         return format_html(' | '.join(actions)) if actions else "No actions"
#     actions_column.short_description = "Actions"
    
#     def has_delete_permission(self, request, obj=None):
#         if obj and obj.stakeholders.exists():
#             return False
#         return super().has_delete_permission(request, obj)
    
#     def save_model(self, request, obj, form, change):
#         if not change:  # New object
#             obj.created_by = request.user
#         super().save_model(request, obj, form, change)


# @admin.register(StakeholderGroupInvitationTerramo)
# class StakeholderGroupInvitationTerramoAdmin(admin.ModelAdmin):
#     list_display = ['pk',
#         'stakeholder_group', 'status_badge', 'created_by', 'expires_at', 
#         'usage_info', 'created_at', 'invitation_link'
#     ]
#     list_filter = [InvitationStatusFilter, 'is_active', 'created_at', 'expires_at']
#     search_fields = [
#         'stakeholder_group__name', 'created_by__username', 
#         'used_by_email', 'message'
#     ]
#     readonly_fields = [
#         'id', 'token', 'created_at', 'invitation_url_display', 
#         'usage_stats', 'time_remaining'
#     ]
#     ordering = ['-created_at']
    
#     fieldsets = (
#         ('Invitation Details', {
#             'fields': ('stakeholder_group', 'created_by', 'message', )
#         }),
#         ('Configuration', {
#             'fields': ('expires_at', 'max_uses', 'is_active', 'days_to_expire',)
#         }),
#         ('Usage Tracking', {
#             'fields': ('current_uses', 'used_at', 'used_by_email'),
#             'classes': ('collapse',)
#         }),
#         ('System Information', {
#             'fields': ('id', 'token', 'created_at', 'invitation_url_display', 'usage_stats', 'time_remaining'),
#             'classes': ('collapse',)
#         }),
#     )
    
#     def get_queryset(self, request):
#         return super().get_queryset(request).select_related(
#             'stakeholder_group', 'created_by', 'stakeholder_group__client'
#         )
    
#     def status_badge(self, obj):
#         """Display invitation status with color coding"""
#         if not obj.is_active:
#             return format_html('<span style="color: #dc3545;">❌ Inactive</span>')
#         elif not obj.expires_at:
#             return format_html('<span style="color: #6c757d;">⚠️ No Expiry</span>')
#         elif obj.is_expired:
#             return format_html('<span style="color: #6c757d;">⏰ Expired</span>')
#         elif obj.used_at:
#             return format_html('<span style="color: #28a745;">✅ Used</span>')
#         else:
#             return format_html('<span style="color: #007cba;">🔗 Active</span>')
#     status_badge.short_description = "Status"
    
#     def usage_info(self, obj):
#         """Display usage information"""
#         if obj.max_uses == 0:
#             return f"Used {obj.current_uses} times (unlimited)"
#         else:
#             remaining = obj.remaining_uses
#             color = "#28a745" if remaining > 0 else "#dc3545"
#             return format_html(
#                 '<span style="color: {};">{}/{} uses ({} remaining)</span>',
#                 color, obj.current_uses, obj.max_uses, remaining
#             )
#     usage_info.short_description = "Usage"
    
#     def invitation_link(self, obj):
#         """Clickable invitation link"""
#         if obj.is_valid:
#             url = obj.get_invitation_url()
#             return format_html(
#                 '<a href="{}" target="_blank" title="{}">🔗 Open</a>', 
#                 url, url
#             )
#         return "Invalid"
#     invitation_link.short_description = "Link"
    
#     def invitation_url_display(self, obj):
#         """Full invitation URL for display"""
#         if obj.id:
#             url = obj.get_invitation_url()
#             return format_html(
#                 '<a href="{}" target="_blank">{}</a><br>'
#                 '<small>Click to test invitation</small>', 
#                 url, url
#             )
#         return "Save to generate URL"
#     invitation_url_display.short_description = "Invitation URL"
    
#     def usage_stats(self, obj):
#         """Detailed usage statistics"""
#         if obj.id:
#             stats = [
#                 f"Created: {obj.created_at.strftime('%Y-%m-%d %H:%M') if obj.created_at else 'Unknown'}",
#                 f"Expires: {obj.expires_at.strftime('%Y-%m-%d %H:%M') if obj.expires_at else 'No expiry set'}",
#                 f"Usage: {obj.current_uses}/{obj.max_uses if obj.max_uses > 0 else '∞'}",
#             ]
#             if obj.used_at:
#                 stats.append(f"First used: {obj.used_at.strftime('%Y-%m-%d %H:%M')}")
#             if obj.used_by_email:
#                 stats.append(f"Used by: {obj.used_by_email}")
#             return format_html('<br>'.join(stats))
#         return "Save to see statistics"
#     usage_stats.short_description = "Statistics"
    
#     def time_remaining(self, obj):
#         """Show time remaining until expiry"""
#         if obj.id and obj.expires_at:
#             now = timezone.now()
#             if obj.expires_at > now:
#                 delta = obj.expires_at - now
#                 if delta.days > 0:
#                     return f"{delta.days} days, {delta.seconds // 3600} hours"
#                 else:
#                     return f"{delta.seconds // 3600} hours, {(delta.seconds % 3600) // 60} minutes"
#             else:
#                 return format_html('<span style="color: #dc3545;">Expired</span>')
#         elif obj.id and not obj.expires_at:
#             return format_html('<span style="color: #6c757d;">No expiry set</span>')
#         return "Not saved yet"
#     time_remaining.short_description = "Time Remaining"
    
#     def save_model(self, request, obj, form, change):
#         if not change:  # New object
#             obj.created_by = request.user
#         super().save_model(request, obj, form, change)
    
#     actions = ['cleanup_expired_invitations']
    
#     def cleanup_expired_invitations(self, request, queryset):
#         """Admin action to cleanup expired invitations"""
#         count = StakeholderGroupInvitationTerramo.cleanup_expired()
#         self.message_user(request, f'Cleaned up {count} expired invitations.')
#     cleanup_expired_invitations.short_description = "Cleanup expired invitations"


# @admin.register(StakeholderTerramo)
# class StakeholderTerramoAdmin(admin.ModelAdmin):
#     list_display = [
#         'email', 'full_name', 'group', 'client_display', 'status_badge', 
#         'is_registered', 'created_at', 'last_login', 'actions_column'
#     ]
#     list_filter = [
#         'status', 'is_registered', 'is_active', 'group', 'client', 
#         'created_at', 'last_login'
#     ]
#     search_fields = [
#         'email', 'first_name', 'last_name', 'organization', 
#         'group__name', 'client__company_name'
#     ]
#     readonly_fields = [
#         'id', 'created_at', 'updated_at', 'last_login', 
#         'invitation_used', 'user_link'
#     ]
#     ordering = ['-created_at']
    
#     fieldsets = (
#         ('Personal Information', {
#             'fields': ('email', 'first_name', 'last_name', 'phone')
#         }),
#         ('Organization', {
#             'fields': ('organization', 'role_in_organization')
#         }),
#         ('Assignment', {
#             'fields': ('group', 'client', 'status', 'is_active')
#         }),
#         ('Registration', {
#             'fields': ('is_registered', 'user_link')
#         }),
#         ('Tracking', {
#             'fields': ('invitation_used', 'created_at', 'updated_at', 'last_login'),
#             'classes': ('collapse',)
#         }),
#         ('System', {
#             'fields': ('id',),
#             'classes': ('collapse',)
#         }),
#     )
    
#     def get_queryset(self, request):
#         return super().get_queryset(request).select_related(
#             'group', 'client', 'user', 'invitation_used'
#         )
    
#     def client_display(self, obj):
#         """Display client with link"""
#         if obj.client:
#             try:
#                 client_url = reverse('admin:clients_client_change', args=[obj.client.id])  # Replace 'your_app'
#                 return format_html('<a href="{}">{}</a>', client_url, obj.client.company_name)
#             except:
#                 return obj.client.company_name
#         return "No Client"
#     client_display.short_description = "Client"
#     client_display.admin_order_field = 'client__company_name'
    
#     def status_badge(self, obj):
#         """Display status with color coding"""
#         colors = {
#             'pending': '#ffc107',
#             'invited': '#17a2b8',
#             'approved': '#28a745',
#             'rejected': '#dc3545',
#             'inactive': '#6c757d',
#         }
#         color = colors.get(obj.status, '#6c757d')
#         return format_html(
#             '<span style="color: {}; font-weight: bold;">{}</span>',
#             color, obj.get_status_display()
#         )
#     status_badge.short_description = "Status"
#     status_badge.admin_order_field = 'status'
    
#     def user_link(self, obj):
#         """Link to associated user account"""
#         if obj.user:
#             try:
#                 user_url = reverse('admin:auth_user_change', args=[obj.user.id])
#                 return format_html(
#                     '<a href="{}">{} ({})</a>', 
#                     user_url, obj.user.get_full_name() or obj.user.username, obj.user.username
#                 )
#             except:
#                 return str(obj.user)
#         return "No user account"
#     user_link.short_description = "User Account"
    
#     def actions_column(self, obj):
#         """Custom actions"""
#         actions = []
#         if obj.status == 'pending':
#             actions.append('⏳ Pending approval')
#         elif obj.status == 'approved' and not obj.is_registered:
#             actions.append('📧 Send invitation')
        
#         if obj.invitation_used:
#             actions.append('✅ Via invitation')
            
#         return ' | '.join(actions) if actions else "No actions"
#     actions_column.short_description = "Actions"
    
#     actions = ['approve_stakeholders', 'reject_stakeholders', 'send_invitations']
    
#     def approve_stakeholders(self, request, queryset):
#         """Bulk approve stakeholders"""
#         updated = queryset.filter(status='pending').update(status='approved')
#         self.message_user(request, f'{updated} stakeholders were approved.')
#     approve_stakeholders.short_description = "Approve selected stakeholders"
    
#     def reject_stakeholders(self, request, queryset):
#         """Bulk reject stakeholders"""
#         updated = queryset.filter(status='pending').update(status='rejected')
#         self.message_user(request, f'{updated} stakeholders were rejected.')
#     reject_stakeholders.short_description = "Reject selected stakeholders"
    
#     def send_invitations(self, request, queryset):
#         """Send invitations to approved stakeholders"""
#         count = 0
#         for stakeholder in queryset.filter(status='approved', is_registered=False):
#             # Here you would implement your invitation sending logic
#             count += 1
#         self.message_user(request, f'Invitations sent to {count} stakeholders.')
#     send_invitations.short_description = "Send invitations to selected stakeholders"


@admin.register(StakeholderActivityLog)
class StakeholderActivityLogAdmin(admin.ModelAdmin):
    list_display = [
        'stakeholder', 'action', 'performed_by', 'timestamp', 'ip_address'
    ]
    list_filter = ['action', 'timestamp', 'performed_by']
    search_fields = [
        'stakeholder__email', 'action', 'description', 
        'performed_by__username'
    ]
    readonly_fields = ['timestamp']
    ordering = ['-timestamp']
    
    def has_add_permission(self, request):
        return False  # Logs should be created programmatically
    
    def has_change_permission(self, request, obj=None):
        return False  # Logs should be immutable
    
    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser  # Only superusers can delete logs


# Custom Admin Site (Optional)
class StakeholderAdminSite(admin.AdminSite):
    """Custom admin site for stakeholder management"""
    site_header = "Stakeholder Management System"
    site_title = "Stakeholder Admin"
    index_title = "Welcome to Stakeholder Management"
    
    def get_app_list(self, request):
        """Customize the admin index page"""
        app_list = super().get_app_list(request)
        
        # Add custom dashboard statistics here if needed
        return app_list


# If you want to use the custom admin site, uncomment these lines:
# stakeholder_admin_site = StakeholderAdminSite(name='stakeholder_admin')
# stakeholder_admin_site.register(StakeholderGroupTerramo, StakeholderGroupTerramoAdmin)
# stakeholder_admin_site.register(StakeholderGroupInvitationTerramo, StakeholderGroupInvitationTerramoAdmin)
# stakeholder_admin_site.register(StakeholderTerramo, StakeholderTerramoAdmin)
# stakeholder_admin_site.register(StakeholderActivityLog, StakeholderActivityLogAdmin)