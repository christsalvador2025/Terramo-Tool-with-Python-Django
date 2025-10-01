from django.urls import path, include
from .views import (
    TerramoAdminLoginView, StakeholderGroupCreateView,
    StakeholderCreateView, StakeholderInvitationAcceptView,
    StakeholderLoginView, StakeholderRegisterView,
    StakeholderTokenLoginView, LogoutView, StakeholderGroupInvitationAcceptView,
    StakeholderGroupListCreateView, StakeholderGroupDetailView, StakeholderListView,SendStakeholderInvitationView, InvitationListView,ApproveStakeholderView, RejectStakeholderView, ProcessInvitationView, VerifyEmailView, StakeholderRegistrationView, GetInvitationLinkView,ValidateInvitationView,SubmitEmailView, StakeholderApprovalView, PendingStakeholdersView, StakeholderDetailView, StakeholderLoginStatusView, StakeholderLoginRequestView, StakeholderUserTokenLoginView, CreateStakeholderView, RemoveStakeholderView,StakeholderGroupListView, UpdatedStakeholderListView, StakeholderApprovalViewSet, StakeholderGroupTerramoListCreateView,
    invitation_detail_public,accept_invitation,
    StakeholderGroupInvitationDetailView, StakeholderUserRegistrationView
)

app_name = 'authentication'

urlpatterns = [
    # Terramo Admin URLs
    path('admin/login/', TerramoAdminLoginView.as_view(), name='admin_login'),
#     path('admin/clients/create/', ClientCreateView.as_view(), name='client_create'),
    
    # Client Admin URLs
#     path('client-admin/accept-invitation/<str:token>/', 
#          ClientAdminInvitationAcceptView.as_view(), name='client_admin_accept_invitation'),
     # new path
#     path('client-admin/accept-invite/<uuid:token>/', ClientAdminAcceptInviteView.as_view(), name='client-admin-accept-invite'),
#     path('client-admin/auth/login/', ClientAdminLoginAuthView.as_view(), name='client-admin-login'),
#     path('client-admin/auth/logout/', LogoutViewData.as_view(), name='logout'),


#     path('client-admin/login/', ClientAdminLoginView.as_view(), name='client_admin_login'),
#     path('client-admin/login/<str:token>/', 
#          ClientAdminTokenLoginView.as_view(), name='client_admin_token_login'),
    
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
    path('stakeholder/invite/<str:token>/', ProcessInvitationView.as_view(), name='process-invitation'),
    path('stakeholder/verify-email/', VerifyEmailView.as_view(), name='verify-email'),
#     path('stakeholder/register/', StakeholderRegistrationView.as_view(), name='register'),
    
    # Utility endpoints
    path('stakeholder/groups/<str:group_id>/invitation-link/', GetInvitationLinkView.as_view(), name='get-invitation-link'),

#     path('stakeholder/invitations/validate/', ValidateInvitationView.as_view(), name='validate-invitation'),
#     path('stakeholder/invitations/verify-email/', VerifyEmailInvitationView.as_view(), name='verify-invitation-email'),

#      path('invitation/stakeholder/validate/<uuid:token>/', validate_invitation_token, name='validate_invitation'),
#     path('invitation/stakeholder/verify-email/', verify_email, name='verify_email'),
      # Invitation flow URLs
     
     # *
    path('stakeholder/validate-invitation/', ValidateInvitationView.as_view(), name='validate_invitation'),
    path('stakeholder/submit-email/', SubmitEmailView.as_view(), name='submit_email'),
    # *
    path('stakeholder/register-user/', StakeholderRegistrationView.as_view(), name='stakeholder-register'),
    path('stakeholder/register-stakeholders/', StakeholderUserRegistrationView.as_view(), name='stakeholder-user-register'),
    # Admin management URLs
#     path('stakeholder/approve/<str:id>/', StakeholderApprovalView.as_view(), name='approve_stakeholder'),
     
#     path('stakeholder/approved/', ApprovedStakeholdersView.as_view(), name='approved_stakeholders'),
    path('pending/', PendingStakeholdersView.as_view(), name='pending_stakeholders'),
    path('detail/<uuid:stakeholder_id>/', StakeholderDetailView.as_view(), name='stakeholder_detail'),
    
     # stakeholder request login

    # Stakeholder status URLs
    path('update-login-status/', StakeholderLoginStatusView.as_view(), name='update_login_status'),

    # updated authentication for stakeholders
    # **
    path('stakeholder/request-login/', StakeholderLoginRequestView.as_view(), name='stakeholder-request-login'),
     path('stakeholder/approve-status/<uuid:stakeholder_id>/', StakeholderApprovalView.as_view(), name='approve_stakeholder'),
    path('stakeholder/login-user/<uuid:token>/', StakeholderUserTokenLoginView.as_view(), name='stakeholder-token-login'),

    # ---- updated --- create stakeholders
    path('groups/<uuid:group_id>/stakeholders/', 
         UpdatedStakeholderListView.as_view(), 
         name='stakeholder-list'),
     # create
    path('groups/<uuid:group_id>/stakeholders/create/', 
         CreateStakeholderView.as_view(), name='create-stakeholder'),

     path('stakeholders/<uuid:stakeholder_id>/remove/', 
         RemoveStakeholderView.as_view(), name='remove-stakeholder'),
    
    # Get current user's stakeholder groups
    path('stakeholder-groups/', 
         StakeholderGroupListView.as_view(), 
         name='stakeholder-groups'),

     # -------------------------- START: stakeholders approval, pending, and reject --------------
     
     # Stakeholder approval endpoints | client_lists_stakeholders
     path(
          'stakeholders/lists/', 
          StakeholderApprovalViewSet.as_view({'get': 'client_lists_stakeholders'}), 
          name='client-lists-stakeholders'
     ),
     path(
          'stakeholders/pending/', 
          StakeholderApprovalViewSet.as_view({'get': 'list_pending_stakeholders'}), 
          name='list-pending-stakeholders'
     ),
     path(
          'stakeholders/<uuid:stakeholder_id>/approve/', 
          StakeholderApprovalViewSet.as_view({'post': 'approve_stakeholder'}), 
          name='approve-stakeholder'
     ),
     path(
          'stakeholders/<uuid:stakeholder_id>/reject/', 
          StakeholderApprovalViewSet.as_view({'post': 'reject_stakeholder'}), 
          name='reject-stakeholder'
     ),
     path(
          'stakeholders/<uuid:stakeholder_id>/resend-invitation/', 
          StakeholderApprovalViewSet.as_view({'post': 'resend_invitation'}), 
          name='resend-stakeholder-invitation'
     ),
     
     # -------------------------- END: stakeholders approval, pending, and reject --------------

    # =======================================================================================================
    # |     START: UPDATED OPTIMIZED STAKEHOLDER GROUPS VIEWS                                              |
    # =======================================================================================================
     path('terramo-stakeholder-groups/', StakeholderGroupTerramoListCreateView.as_view(), name='group-list-create'),
#     path('groups/<uuid:pk>/', views.StakeholderGroupDetailView.as_view(), name='group-detail'),
    
#     # Stakeholders
#     path('stakeholders/', views.StakeholderListCreateView.as_view(), name='stakeholder-list-create'),
#     path('stakeholders/<uuid:pk>/', views.StakeholderDetailView.as_view(), name='stakeholder-detail'),
    
#     # Invitations (Admin)
#     path('invitations/', views.StakeholderGroupInvitationListCreateView.as_view(), name='invitation-list-create'),
    path('invitations/<uuid:pk>/', StakeholderGroupInvitationDetailView.as_view(), name='invitation-detail'),
    
#     # Public invitation endpoints (no auth required)
    path('public/invitation/<uuid:token>/', invitation_detail_public, name='invitation-public-detail'),
    path('public/invitation/<uuid:token>/accept/', accept_invitation, name='invitation-accept'),
    
#     # Dashboard and Statistics
#     path('dashboard/stats/', views.dashboard_stats, name='dashboard-stats'),
    
#     # Bulk Operations
#     path('bulk/approve-stakeholders/', views.bulk_approve_stakeholders, name='bulk-approve-stakeholders'),
#     path('bulk/cleanup-invitations/', views.cleanup_expired_invitations, name='cleanup-invitations'),
    # =======================================================================================================
    # |     END: UPDATED OPTIMIZED STAKEHOLDER GROUPS VIEWS                                              |
    # =======================================================================================================
]