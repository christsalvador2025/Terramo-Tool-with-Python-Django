from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import InvitationAcceptView, ClientViewSet, GetInvitationFormView, ClientViewDataSet, InvitationAcceptDataView, ClientAdminAcceptInvitationView, ClientAdminLogoutView, ClientAdminCustomLogoutView, ClientAdminVerifyInvitationtokenView
router = DefaultRouter()
app_name = 'clients'
 

# router.register(r'', ClientViewDataSet, basename='clients')
router.register(r'', ClientViewDataSet, basename='clients')
# router.register(r'clients', ClientViewSet) 
urlpatterns = [
    path('', include(router.urls)),
    
    # Additional endpoints
  
    # path('invitations/accept/<uuid:token>/', InvitationAcceptView.as_view(), name='api_accept_invite'),
    path('invitation/form/', GetInvitationFormView.as_view(), name='get-invitation-form'),
    path("invitations/accept/<uuid:token>/", InvitationAcceptDataView.as_view(), name='api_accept_invite'),

    # client admin
    path('client-admin/accept-invite/<uuid:token>/', ClientAdminAcceptInvitationView.as_view(), name='client-admin-accept-invite'),
    # path('/accept-invitation/<uuid:token>/', GetInvitationFormView.as_view(), name='get-invitation-form'),
    # path('create-client/', ClientViewSet, name='create_client'),
    # Client Admin Authentication
    path("logout-client/", ClientAdminCustomLogoutView.as_view(), name="client_admin_logout"),

    # invitations final
    path("verify-login-token/", ClientAdminVerifyInvitationtokenView.as_view(), name="verify_otp"),
   
]