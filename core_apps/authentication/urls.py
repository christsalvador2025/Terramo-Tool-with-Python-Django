from django.urls import path, include
from .views import (
    TerramoAdminLoginView,
    ClientAdminInvitationAcceptView, ClientAdminLoginView, 
    ClientAdminTokenLoginView, StakeholderGroupCreateView,
    StakeholderCreateView, StakeholderInvitationAcceptView,
    StakeholderLoginView, StakeholderRegisterView,
    StakeholderTokenLoginView, LogoutView, StakeholderGroupInvitationAcceptView,
    StakeholderGroupListCreateView, StakeholderGroupDetailView, StakeholderListView,SendStakeholderInvitationView, InvitationListView,ApproveStakeholderView, RejectStakeholderView, ProcessInvitationView, VerifyEmailView, StakeholderRegistrationView, GetInvitationLinkView
)

app_name = 'authentication'

urlpatterns = [
    # Terramo Admin URLs
    path('admin/login/', TerramoAdminLoginView.as_view(), name='admin_login'),
#     path('admin/clients/create/', ClientCreateView.as_view(), name='client_create'),
    
    # Client Admin URLs
    path('client-admin/accept-invitation/<str:token>/', 
         ClientAdminInvitationAcceptView.as_view(), name='client_admin_accept_invitation'),
     # new path
#     path('client-admin/accept-invite/<uuid:token>/', ClientAdminAcceptInviteView.as_view(), name='client-admin-accept-invite'),
#     path('client-admin/auth/login/', ClientAdminLoginAuthView.as_view(), name='client-admin-login'),
#     path('client-admin/auth/logout/', LogoutViewData.as_view(), name='logout'),


    path('client-admin/login/', ClientAdminLoginView.as_view(), name='client_admin_login'),
    path('client-admin/login/<str:token>/', 
         ClientAdminTokenLoginView.as_view(), name='client_admin_token_login'),
    
    # Stakeholder Group URLs (Client Admin)
    path('client-admin/groups/create/', 
         StakeholderGroupCreateView.as_view(), name='stakeholder_group_create'),
    path('client-admin/groups/<uuid:group_id>/stakeholders/create/',  # create stakeholder in a stakeholder groups
         StakeholderCreateView.as_view(), name='stakeholder_create'),
    
    # Stakeholder URLs
    path('stakeholder/accept-invitation/<str:token>/', 
         StakeholderInvitationAcceptView.as_view(), name='stakeholder_accept_invitation'),
    path('stakeholder-group/accept-invitation/<str:token>/', 
         StakeholderGroupInvitationAcceptView.as_view(), name='stakeholdergroup_accept_invitation'),
    path('stakeholder/login/', StakeholderLoginView.as_view(), name='stakeholder_login'),
    path('stakeholder/register/', StakeholderRegisterView.as_view(), name='stakeholder_register'),
    path('stakeholder/login/<str:token>/', 
         StakeholderTokenLoginView.as_view(), name='stakeholder_token_login'),
    
    # Universal logout
    path('logout/', LogoutView.as_view(), name='universal-logout'),


    # Updated url path for stakeholders
    # Client Admin URLs
    # Client Admin endpoints
    
    path('client-admin/stakeholders/groups/', StakeholderGroupListCreateView.as_view(), name='group-list-create'),
    path('client-admin/stakeholders/groups/<uuid:pk>/', StakeholderGroupDetailView.as_view(), name='group-detail'),
    path('client-admin/stakeholders/groups/<uuid:group_id>/stakeholders/', StakeholderListView.as_view(), name='stakeholder-list'),
    path('client-admin/stakeholders/groups/<uuid:group_id>/invite/', SendStakeholderInvitationView.as_view(), name='send-invitation'),
    path('client-admin/stakeholders/invitations/', InvitationListView.as_view(), name='invitation-list'),
    path('client-admin/stakeholders/invitations/<uuid:pk>/approve/', ApproveStakeholderView.as_view(), name='approve-stakeholder'),
    path('client-admin/stakeholders/invitations/<uuid:pk>/reject/', RejectStakeholderView.as_view(), name='reject-stakeholder'),
    
    # Public invitation endpoints (no auth required)
    path('stakeholder/invite/<uuid:token>/', ProcessInvitationView.as_view(), name='process-invitation'),
    path('stakeholder/verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('stakeholder/register/', StakeholderRegistrationView.as_view(), name='register'),
    
    # Utility endpoints
    path('stakeholder/groups/<uuid:group_id>/invitation-link/', GetInvitationLinkView.as_view(), name='get-invitation-link')
]