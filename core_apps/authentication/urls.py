from django.urls import path, include
from .views import (
    TerramoAdminLoginView,
    ClientAdminInvitationAcceptView, ClientAdminLoginView, 
    ClientAdminTokenLoginView, StakeholderGroupCreateView,
    StakeholderCreateView, StakeholderInvitationAcceptView,
    StakeholderLoginView, StakeholderRegisterView,
    StakeholderTokenLoginView, LogoutView, StakeholderGroupInvitationAcceptView
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
    path('logout/', LogoutView.as_view(), name='logout'),
]