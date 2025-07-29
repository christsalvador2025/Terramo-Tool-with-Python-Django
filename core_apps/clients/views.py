from django.shortcuts import render
from rest_framework import viewsets, status, permissions, filters, generics
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db import transaction
from django.contrib.auth import authenticate, get_user_model
from .models import Invitation, Client, InvitationStatus
from .serializers import ClientSerializer, ClientCreateDataSerializer, ClientDetailSerializer, ClientListSerializer, InvitationDataSerializer
from django.conf import settings
from core_apps.user_auth.permissions import IsTerramoAdmin
import secrets
import string
import uuid
from rest_framework.views import APIView
from .serializers import StakeholderRegistrationSerializer, InvitationSerializer
from core_apps.common.permissions import IsTerramoAdmin
User = get_user_model()

class ClientViewSet(viewsets.ModelViewSet):
    queryset = Client.objects.all()
    serializer_class = ClientSerializer
    permission_classes = [IsAuthenticated, IsTerramoAdmin] # Only Terramo Admins can manage clients

    def perform_create(self, serializer):
        # The serializer's create method handles creating the StakeholderGroup and Invitation
        serializer.save()
        # After saving, the client and invitation are created.
        # The Terramo admin can then copy the invite link from the admin or API response.

    def perform_update(self, serializer):
        serializer.save()

    def perform_destroy(self, instance):
        # You might want to add logic here to deactivate related users/invitations
        # or handle soft deletes if that's your policy.
        instance.delete()


# Create your views here.
class InvitationAcceptView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, token):
        try:
            invitation = Invitation.objects.get(token=token)
        except Invitation.DoesNotExist:
            return Response({'detail': 'Invalid or non-existent invitation token.'}, status=status.HTTP_404_NOT_FOUND)

        if not invitation.is_valid_for_acceptance():
            return Response({'detail': 'This invitation link is no longer valid, expired, or has already been used.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if a user with this email already exists for the same client
        existing_user = User.objects.filter(
            email__iexact=invitation.email,
            client=invitation.client
        ).first()

        if existing_user:
            return Response({'detail': 'A user with this email already exists for this client. Please log in.'}, status=status.HTTP_400_BAD_REQUEST)

        # Pass email and client from invitation to the serializer context
        serializer = StakeholderRegistrationSerializer(
            data=request.data,
            context={'email': invitation.email, 'client': invitation.client}
        )

        if serializer.is_valid():
            with transaction.atomic():
                user = serializer.save() # User is created, email, client, role are set

                # Mark invitation as accepted
                invitation.mark_as_accepted(user)

                # Optional: Automatically log in the user after registration
                # This requires you to set up DRF's authentication classes (e.g., TokenAuthentication)
                # and return an auth token to the frontend.
                # If using TokenAuthentication:
                # from rest_framework.authtoken.models import Token
                # token, created = Token.objects.get_or_create(user=user)
                # return Response({'detail': 'Account created and user logged in.', 'token': token.key}, status=status.HTTP_201_CREATED)
                
                return Response({'detail': 'Account created successfully. Please log in.'}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



def generate_secure_token(length=32):

    """Generate a cryptographically secure token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

 
class GetInvitationFormView(APIView):
    # permission_classes = [permissions.AllowAny]
    permission_classes = [IsAuthenticated, IsTerramoAdmin]
    def get(self, request):
        raw_token = generate_secure_token(32)  # 32 character token
        # or
        raw_token = secrets.token_urlsafe(32)  # URL-safe base64 token
        
        return Response({
            "invite_token": f"{settings.DOMAIN}/invitation/client-admin/{raw_token}", "raw_token": raw_token})
    





"""
-----------------------------------------------------------------------------------------
UPDATED views.py
-----------------------------------------------------------------------------------------
"""
from rest_framework.viewsets import ModelViewSet
from rest_framework.throttling import UserRateThrottle
from django_filters.rest_framework import DjangoFilterBackend
from loguru import logger
from core_apps.products.serializers import ProductSerializer
from core_apps.products.models import Product
from django.db.models import Q, Count
from rest_framework.parsers import MultiPartParser, FormParser

class ClientViewDataSet(ModelViewSet):
    """
    ViewSet for managing clients
    Provides CRUD operations for clients with products and invitations
    """
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated, IsTerramoAdmin]
    queryset = Client.objects.select_related('created_by').prefetch_related(
        'clientproduct_set__product',
        'invitations'
    ).all()
    
    
    throttle_classes = [UserRateThrottle]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['is_active', 'role', 'gender', 'land', 'city']
    search_fields = ['company_name', 'email', 'contact_person_first_name', 'contact_person_last_name']
    ordering_fields = ['company_name', 'email', 'created_at']
    ordering = ['-created_at']
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'list':
            return ClientListSerializer
        elif self.action == 'create':
            return ClientCreateDataSerializer
        elif self.action in ['retrieve', 'update', 'partial_update']:
            return ClientDetailSerializer
        return ClientCreateDataSerializer
    
    def get_queryset(self):
        """Filter queryset based on user permissions"""
        queryset = super().get_queryset()
        
        # If you want to filter by created_by user (optional)
        # queryset = queryset.filter(created_by=self.request.user)
        
        return queryset
    
    def perform_create(self, serializer):
        """Set created_by when creating a client"""
        serializer.save()
        logger.info(f"Client created: {serializer.instance.company_name} by {self.request.user}")
    
    def perform_update(self, serializer):
        """Log client updates"""
        serializer.save()
        logger.info(f"Client updated: {serializer.instance.company_name} by {self.request.user}")
    
    @action(detail=True, methods=['post'], url_path='resend-invitation')
    def resend_invitation(self, request, pk=None):
        """Resend invitation to client"""
        client = self.get_object()
        
        try:
            # Check if there's an existing active invitation
            existing_invitation = client.invitations.filter(
                is_active=True,
                status__in=[InvitationStatus.NOT_ACCEPTED, InvitationStatus.ACCEPTED]
            ).first()
            
            if existing_invitation and not existing_invitation.is_expired():
                return Response({
                    'message': 'An active invitation already exists for this client',
                    'invitation_url': existing_invitation.get_invite_url()
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Create new invitation
            expires_at = timezone.now() + timezone.timedelta(days=30)
            new_invitation = Invitation.objects.create(
                client=client,
                email=client.email,
                invited_by=request.user,
                expires_at=expires_at,
                sent_at=timezone.now(),
                status=InvitationStatus.NOT_ACCEPTED
            )
            
            # Deactivate old invitations
            client.invitations.exclude(id=new_invitation.id).update(is_active=False)
            
            logger.info(f"Invitation resent for client: {client.company_name}")
            
            return Response({
                'message': 'Invitation sent successfully',
                'invitation_url': new_invitation.get_invite_url(),
                'expires_at': new_invitation.expires_at
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error resending invitation for client {client.id}: {e}")
            return Response({
                'error': 'Failed to send invitation'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=True, methods=['get'], url_path='products')
    def client_products(self, request, pk=None):
        """Get all products associated with a client"""
        client = self.get_object()
        client_products = client.clientproduct_set.select_related('product').all()
        
        data = []
        for cp in client_products:
            data.append({
                'id': cp.id,
                'product': ProductSerializer(cp.product).data,
                'purchased_at': cp.purchased_at,
                'expires_at': cp.expires_at,
                'is_active': cp.is_active
            })
        
        return Response(data, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['get'], url_path='statistics')
    def statistics(self, request):
        """Get client statistics"""
        queryset = self.get_queryset()
        
        stats = {
            'total_clients': queryset.count(),
            'active_clients': queryset.filter(is_active=True).count(),
            'inactive_clients': queryset.filter(is_active=False).count(),
            'clients_by_role': dict(queryset.values_list('role').annotate(Count('role'))),
            'clients_by_gender': dict(queryset.values_list('gender').annotate(Count('gender'))),
            'recent_clients': queryset.filter(
                created_at__gte=timezone.now() - timezone.timedelta(days=30)
            ).count()
        }
        
        return Response(stats, status=status.HTTP_200_OK)


class ProductListView(generics.ListAPIView):
    """List all available products for client creation"""
    queryset = Product.objects.filter(is_active=True)  # Assuming Product has is_active field
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering = ['name']

"""
INVITE LINKS ---------------------------
"""
class InvitationAcceptDataView(APIView):
    """
    API endpoint for accepting a client invitation.
    Clients click a link with a token, which hits this endpoint.
    It validates the token, marks the invitation as accepted,
    and returns relevant information.
    """
    permission_classes = [] # No authentication needed for this endpoint

    def get(self, request, token, *args, **kwargs):
        """Handles GET request to accept invitation via token in URL."""
        # try:
        #     # Validate token format
        #     uuid.UUID(token)
        # except ValueError:
        #     return Response(
        #         {"detail": "Invalid invitation token format."},
        #         status=status.HTTP_400_BAD_REQUEST
        #     )
        try:
            invitation = get_object_or_404(Invitation, token=token)
        except Invitation.DoesNotExist: # Use a more specific exception for clarity
            return Response(
                {"detail": "Invitation not found or invalid token."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e: # Catch any other unexpected database query errors
            logger.error(f"Error retrieving invitation for token {token}: {e}")
            return Response(
                {"detail": "Not valid invitation."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        try:
            invitation = get_object_or_404(Invitation, token=token)
        except Exception:
            return Response(
                {"detail": "Invitation not found or invalid token."},
                status=status.HTTP_404_NOT_FOUND
            )

        if not invitation.is_valid_for_acceptance():
            if invitation.is_expired():
                return Response(
                    {"detail": "Invitation link has expired."},
                    status=status.HTTP_410_GONE # 410 Gone for expired resources
                )
            elif invitation.status == InvitationStatus.REGISTERED:
                return Response(
                    {"detail": "Invitation has already been used to register an account."},
                    status=status.HTTP_409_CONFLICT # 409 Conflict for already processed
                )
            else: # e.g., already accepted, or inactive for other reasons
                return Response(
                    {"detail": "Invitation is no longer active or valid for acceptance."},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Mark the invitation as accepted
        invitation.accepted_at = timezone.now()
        invitation.status = InvitationStatus.ACCEPTED
        invitation.save()

        # Log the acceptance
        logger.info(f"Invitation token {token} accepted for client {invitation.client.company_name} ({invitation.email})")

        # You can return the serialized invitation data or a simple success message
        serializer = InvitationDataSerializer(invitation) # Use the new serializer
        return Response(
            {
                "message": "Invitation accepted successfully. You can now proceed to registration.",
                "invitation_details": serializer.data
            },
            status=status.HTTP_200_OK
        )
