from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import InvitationAcceptView, ClientViewSet, GetInvitationFormView, ClientViewDataSet, InvitationAcceptDataView
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
    # path('create-client/', ClientViewSet, name='create_client'),
    
]