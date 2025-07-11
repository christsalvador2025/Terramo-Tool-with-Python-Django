# core_app/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views # Import all views from the same directory
# from .views import StakeholderUserViewSet,StakeholderInvitationViewSet
# Initialize DefaultRouter for ViewSets
router = DefaultRouter()
router.register(r'companies', views.CompanyViewSet)
router.register(r'stakeholder-groups', views.StakeholderGroupViewSet)

router.register(r'stakeholder-invitations', views.StakeholderInvitationViewSet, basename='stakeholder-invitation')
router.register(r'stakeholder-users', views.StakeholderUserViewSet)
router.register(r'esg-questions', views.ESGQuestionViewSet)
router.register(r'esg-responses', views.ESGResponseViewSet)
# router.register(r'stakeholder-groups-gemini', views.StakeholderGroupViewSet)

# Define URL patterns
urlpatterns = [
    # 1. API URLs managed by Django REST Framework Router
    path('api/', include(router.urls)),

    # 2. Authentication API (for JWT token generation)
    path('api/auth/token/', views.CustomAuthToken.as_view(), name='api_token_obtain_pair'),

    # 3. Stakeholder-facing URLs for invitation and registration flows
    #    a. General Group Invitation Link (less secure, public group join link)
    path('join-group/<uuid:token>/', views.StakeholderGroupJoinHandler.as_view(), name='stakeholder_group_join_handler'),

    #    b. NEW: Individual Email Invitation Link (more secure, unique token per email)
    path('invite/<uuid:token>/', views.StakeholderIndividualInvitationHandler.as_view(), name='stakeholder_individual_invitation_handler'),

    #    c. Unified Stakeholder Registration/Login Page
    #       This view will handle both new registrations and logins,
    #       and will accept either 'group_id' or 'invitation_token' as query parameters.
    path('stakeholder/access/', views.StakeholderRegistrationLoginView.as_view(), name='stakeholder_registration_login'),
    



    #    d. Magic Link Login Flow (for existing stakeholders to log in passwordless)
    path('stakeholder/magic-login-request/', views.StakeholderMagicLoginRequest.as_view(), name='stakeholder_magic_login_request'),
    path('stakeholder/magic-login/authenticate/<uidb64>/<token>/', views.StakeholderMagicLoginAuthenticate.as_view(), name='stakeholder_magic_login_authenticate'),

    #    e. Stakeholder ESG Survey Endpoints
    #       (Assuming a frontend will direct the logged-in stakeholder here)
    path('api/stakeholder/survey/', views.StakeholderESGSurveyView.as_view(), name='stakeholder_survey'),

    #    f. Bulk Invitations API Endpoint
    #       This API receives a list of emails and sends individual invitation emails.
    path('api/stakeholder-groups/bulk-invite/', views.BulkStakeholderInvitationView.as_view(), name='bulk_stakeholder_invite'),

    # Placeholder for a stakeholder dashboard (to be implemented in frontend/another view if needed)
    # This URL is used for redirects after successful login/registration.
    path('stakeholder/dashboard/', lambda request: Response({"detail": "Stakeholder Dashboard - Coming Soon!"}), name='stakeholder_dashboard'),
]