from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    ClientInvitationView,
    ClientLoginView,
    GenerateLoginLinkView,
    StakeholderInvitationView,
    StakeholderLoginView,
    UserProfileView,
    LogoutView,
    dashboard_view,
    # StakeholderGroupViewSet,
    # ClientManagementViewSet,
    # InvitationManagementViewSet,
    BulkStakeholderInvitationView,
    DashboardStatsView,
    ResendInvitationView,
    # CancelInvitationView,
    ValidateInvitationView,
    CustomTokenCreateView,
    LoginView,
    CustomTokenRefreshView
)

app_name = 'auth'

# Router for ViewSets
# router = DefaultRouter()
# router.register(r'stakeholder-groups', StakeholderGroupViewSet, basename='stakeholder-groups')
# router.register(r'clients', ClientManagementViewSet, basename='clients')
# router.register(r'invitations', InvitationManagementViewSet, basename='invitations')
"""
urlpatterns = [
    path("login/", CustomTokenCreateView.as_view(), name="login"),
    path("verify-otp/", OTPVerifyView.as_view(), name="verify_otp"),
    path("refresh/", CustomTokenRefreshView.as_view(), name="refresh"),
    path("logout/", LogoutAPIView.as_view(), name="logout"),
]

"""
urlpatterns = [
    # Authentication URLs
    path('client-invitation/', ClientInvitationView.as_view(), name='client-invitation'),
    path('client-login/<uuid:invitation_token>/', ClientLoginView.as_view(), name='client-login'),
    path('generate-login-link/', GenerateLoginLinkView.as_view(), name='generate-login-link'),
    path('stakeholder-invitation/', StakeholderInvitationView.as_view(), name='stakeholder-invitation'),
    path('stakeholder-login/<uuid:invite_token>/', StakeholderLoginView.as_view(), name='stakeholder-login'),
    path('bulk-stakeholder-invitation/', BulkStakeholderInvitationView.as_view(), name='bulk-stakeholder-invitation'),
    
    # User Management URLs
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    # path('logout/', LogoutView.as_view(), name='logout'),
    
    # Dashboard URLs
    path('dashboard/', dashboard_view, name='dashboard'),
    path('dashboard/stats/', DashboardStatsView.as_view(), name='dashboard-stats'),
    
    # Token Management URLs
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    
    # Invitation Management URLs
    path('invitation/validate/<uuid:token>/', ValidateInvitationView.as_view(), name='validate-invitation'),
    path('invitation/resend/<uuid:invitation_id>/', ResendInvitationView.as_view(), name='resend-invitation'),
    # path('invitation/cancel/<uuid:invitation_id>/', CancelInvitationView.as_view(), name='cancel-invitation'),
    
    path("login/", LoginView.as_view(), name="login"),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token-refresh'),
    # Include ViewSet URLs
    # path('', include(router.urls)),
]

# Additional URL patterns for specific use cases
# client_admin_patterns = [
#     path('my-stakeholder-groups/', StakeholderGroupViewSet.as_view({'get': 'my_groups'}), name='my-stakeholder-groups'),
#     path('my-invitations/', InvitationManagementViewSet.as_view({'get': 'my_invitations'}), name='my-invitations'),
#     path('stakeholder-groups/<uuid:group_id>/members/', StakeholderGroupViewSet.as_view({'get': 'members'}), name='group-members'),
# ]

# super_admin_patterns = [
#     path('all-clients/', ClientManagementViewSet.as_view({'get': 'list'}), name='all-clients'),
#     path('client/<uuid:client_id>/groups/', ClientManagementViewSet.as_view({'get': 'client_groups'}), name='client-groups'),
#     path('client/<uuid:client_id>/stats/', ClientManagementViewSet.as_view({'get': 'client_stats'}), name='client-stats'),
#     path('system-stats/', DashboardStatsView.as_view(), name='system-stats'),
# ]

# Add role-specific patterns
# urlpatterns += [
#     path('client-admin/', include(client_admin_patterns)),
#     path('super-admin/', include(super_admin_patterns)),
# ]

