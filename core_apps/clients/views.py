from django.shortcuts import render
from rest_framework import viewsets, status, permissions, filters, generics
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db import transaction
from django.contrib.auth import authenticate, get_user_model
from .models import Invitation, Client, InvitationStatus, ClientInvitation
from .serializers import ClientSerializer, ClientCreateDataSerializer, ClientDetailSerializer, ClientListSerializer, InvitationDataSerializer
from django.conf import settings
from core_apps.user_auth.permissions import IsClientAdmin
import secrets
import string
import uuid
from rest_framework.views import APIView
from .serializers import StakeholderRegistrationSerializer, InvitationSerializer, AcceptInvitationWithEmailSerializer
from core_apps.common.permissions import IsTerramoAdmin
User = get_user_model()
from core_apps.authentication.models import ClientAdmin, StakeholderGroup, InvitationToken, LoginSession
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
from .utils import generate_invitation_email, generate_login_email
from core_apps.user_auth.views import set_auth_cookies
from django.core.mail import send_mail
from core_apps.clients.permissions import IsClientAdmin
from django.contrib.auth.hashers import make_password
from django.utils.crypto import get_random_string
from core_apps.user_auth.models import User

class ClientViewDataSet(ModelViewSet):
    """
    ViewSet for managing clients
    Provides CRUD operations for clients with products and invitations
    """
    # parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsTerramoAdmin]
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
    
    # def perform_create(self, serializer):
    #     """Set created_by when creating a client"""
    #     serializer.save()
    #     logger.info(f"Client created: {serializer.instance.company_name} by {self.request.user}")
    @transaction.atomic
    def perform_create(self, serializer):
        # Create client
        # client = serializer.save(created_by=self.request.user)
        data = serializer.validated_data
        email = serializer.validated_data['email']
        first_name = serializer.validated_data['contact_person_first_name']
        last_name = serializer.validated_data['contact_person_last_name']
        # company_name = serializer.validated_data['company_name']
        # land = serializer.validated_data['land']
        
        
        email, company_name, land = data["email"], data["company_name"], data["land"]

        if User.objects.filter(email=email).exists():
            return Response(
                {'error': 'A user with this email already exists'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        if Client.objects.filter(company_name=company_name, land=land).exists():
            return Response(
                {'error': 'A client with this company name already exists in this country'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        # ----- 1. SAVE CLIENT --------------------------------------------
        client: Client = serializer.save(created_by=self.request.user)
        # ----- 3. CREATE CLIENT-ADMIN USER -------------------------------
        auto_pwd   = get_random_string(32)
        auto_user  = f"T-{data['contact_person_first_name']}-{get_random_string(6)}"
        user_obj   = User.objects.create_user(
            # username=auto_user,
            email=email,
            first_name=data["contact_person_first_name"],
            last_name=data["contact_person_last_name"],
            password=auto_pwd,
            role="client_admin",
            is_active=True,
        )
        # Create client admin
        # client_admin = ClientAdmin.objects.create(
        #     client=client,
        #     email=client.email,
        #     first_name=client.contact_person_first_name,
        #     last_name=client.contact_person_last_name
        # )

        # if User.objects.filter(email=email,).exists():
        #     return Response(
        #         {'error': 'A user with this email already exists'}, 
        #         status=status.HTTP_400_BAD_REQUEST
        #     )
            
        # # Check if client with same company name and country already exists
        # if Client.objects.filter(company_name=company_name, land=land).exists():
        #     return Response(
        #         {'error': 'A client with this company name already exists in this country'}, 
        #         status=status.HTTP_400_BAD_REQUEST
        #     )
        # Create default "Management" stakeholder group
        StakeholderGroup.objects.create(
            name="Management",
            client=client,
            created_by=self.request.user
        )
        # invitation_raw_token = serializer.validated_data.get('raw_token')
        invitation_raw_token = serializer.validated_data.get('raw_token')
        # Generate invitation token for client admin
        # invitation_token = InvitationToken.objects.create(
        #     token=invitation_token,
        #     token_type='client_admin_invite',
        #     client_admin=client_admin,
        #     email=client_admin.email
        # )
        
        # Create client invitations
        invitation_token = ClientInvitation.objects.create(
            token = invitation_raw_token,
            client=client
        )
        # auto_password = get_random_string(32)
        # auto_suffix_username = get_random_string(6)
       
        # user_obj = User.objects.create(
        #     username=f"T-{first_name}-{auto_suffix_username}",
        #     email=client.email,
        #     first_name=first_name,
        #     last_name=last_name,
        #     password=make_password(auto_password),   
        #     role='client_admin',   
        #     is_active=True,
        #     is_staff=False,  
        #     is_superuser=False,
        #     account_status=User.AccountStatus.ACTIVE,
        # )
        
        

        # Send invitation email
        self.send_invitation_email(client, invitation_token)
        logger.info(f"Client created: {serializer.instance.company_name} by {self.request.user}")
        return client
    def send_invitation_email(self, client, invitation_token):
        """Send invitation email to client admin"""
        subject = f"Invitation to Terramo System - {client.company_name}"
        # invitation_link = f"{settings.DOMAIN}/api/v1/authentication/client-admin/accept-invitation/{invitation_token.token}"
        invitation_link = f"{settings.FRONTEND_DOMAIN_URL}/client-admin/accept-invitation/{invitation_token.token}"
        message = generate_invitation_email(
            client.contact_person_first_name,
            client.company_name,
            invitation_link
        )
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[client.email],
                fail_silently=False,
            )
        except Exception as e:
            logger.error(f"Failed to send invitation email to {client.email}: {e}")
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

from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from .serializers import AcceptInvitationSerializer
from .utils import set_authentication_cookies
from rest_framework_simplejwt.tokens import RefreshToken
"""
Remarks: Final Approach for Cliend Admin accept invitation
"""
@method_decorator(never_cache, name='dispatch')
class ClientAdminAcceptInvitationView(APIView):
    """Handle invitation acceptance"""
    
    permission_classes = [permissions.AllowAny]
    throttle_classes = [AnonRateThrottle]
    
    def get(self, request, token):
        """Handle invitation link click - Initial token verification"""
        try:
            invitation = ClientInvitation.objects.select_related('client').get(
                token=token,
                is_active=True
            )
            
            # Check if already accepted and verified
            if invitation.is_accepted and invitation.email_verified:
                # Already fully processed
                redirect_url = f"{settings.FRONTEND_DOMAIN_URL}/{settings.FRONTEND_CLIENT_LOGIN_ENDPOINT}"
                return Response({
                    "message": "Invitation already accepted. Please login using your email.",
                    "message_stat": "accepted_and_verified",
                    "redirect_url": redirect_url
                }, status=status.HTTP_200_OK)
            
            # Mark as accepted if not already
            if not invitation.is_accepted:
                invitation.is_accepted = True
                invitation.accepted_at = timezone.now()
                invitation.save(update_fields=['is_accepted', 'accepted_at'])

            return Response({
                "message": "Invitation accepted. Please verify your email address to continue.",
                "message_stat": "accepted_and_for_verification",
                "redirect_url": None
            }, status=status.HTTP_200_OK)
            
        except ClientInvitation.DoesNotExist:
            return Response({
                "message": "Invitation not found or has expired.",
                "message_stat": "invitation_not_found",
                "redirect_url": None
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error in GET accept invitation: {e}")
            return Response({
                "message": "An error occurred while processing the invitation.",
                "message_stat": "error",
                "redirect_url": None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request, token):
        """API endpoint for email verification and authentication"""
        try:
            # Get the invitation
            invitation = ClientInvitation.objects.select_related('client').get(
                token=token,
                is_active=True
            )
            
            # Get email from request
            email = request.data.get('email', '').lower().strip()
            
            if not email:
                return Response({
                    "error": "Email is required"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate email format (basic validation)
            if '@' not in email:
                return Response({
                    "error": "Please enter a valid email address"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if invitation is already verified
            if invitation.email_verified and invitation.is_active and invitation.is_accepted:
                # Send login email again
                subject = f"Login Token for - {invitation.client.company_name}"
                message = generate_login_email(
                    invitation.client.contact_person_first_name,
                    invitation.get_invite_url()
                )
                
                try:
                    send_mail(
                        subject=subject,
                        message=message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[invitation.client.email],
                        fail_silently=False,
                    )
                except Exception as e:
                    logger.error(f"Failed to send invitation email to {invitation.client.email}: {e}")
                
                return Response({
                    'message': 'Email already verified. Login email sent. Please check your email and click the login link.',
                    'message_stat': 'email_verified'
                }, status=status.HTTP_200_OK)

            if not invitation.is_accepted:
                return Response({
                    'message': 'Please check your email to accept the invitation first.',
                    'message_stat': 'not_accepted'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Verify the email matches the invited email
            if email != invitation.client.email.lower().strip():
                return Response({
                    "error": "Email does not match the invitation recipient"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Find the user and authenticate
            try:
                user = User.objects.get(email=email, is_active=True)
                
                # Mark invitation as email verified
                invitation.email_verified = True
                invitation.save(update_fields=['email_verified'])
                
                logger.info(f"User found and invitation verified: {user.email}")
                
            except User.DoesNotExist:
                return Response({
                    "error": "User account not found. Please contact support."
                }, status=status.HTTP_404_NOT_FOUND)

            # Check if user is locked out (if you have this functionality)
            # if hasattr(user, 'is_locked_out') and user.is_locked_out:
            #     return Response({
            #         "error": f"Account is locked due to multiple failed login attempts."
            #     }, status=status.HTTP_403_FORBIDDEN)

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            
            # Update last login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            # Prepare response data
            response_data = {
                'message': 'Login successful',
                'message_stat': 'email_verified',
                'access': access_token,
                'refresh': refresh_token,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'first_name': getattr(user, 'first_name', ''),
                    'last_name': getattr(user, 'last_name', ''),
                    'is_active': user.is_active,
                    'last_login': user.last_login.isoformat() if user.last_login else None,
                }
            }
            
            response = Response(response_data, status=status.HTTP_200_OK)
            
            # Set authentication cookies (if you have this function)
            try:
                set_auth_cookies(response, access_token, refresh_token)
            except NameError:
                # If set_auth_cookies function doesn't exist, skip it
                pass
            
            logger.info(f"User {user.email} logged in successfully via invitation")
            
            return response
            
        except ClientInvitation.DoesNotExist:
            return Response({
                "error": "Invitation not found or has expired."
            }, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            logger.error(f"Error in POST accept invitation: {e}")
            return Response({
                "error": "An error occurred during authentication. Please try again."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
# class ClientAdminAcceptInvitationView(APIView):
#     """Handle invitation acceptance"""
    
#     permission_classes = [permissions.AllowAny]
#     throttle_classes = [AnonRateThrottle]
    
#     def get(self, request, token):
#         """Handle invitation link click"""
#         try:
#             invitation = ClientInvitation.objects.select_related('client').get(
#                 token=token,
#                 is_active=True
#             )
            
#             # Check if already accepted and verified
#             if invitation.is_accepted and invitation.email_verified:
#                 # Redirect to login page
#                 redirect_url = f"{settings.FRONTEND_DOMAIN_URL}/{settings.FRONTEND_CLIENT_LOGIN_ENDPOINT}"
#                 # return redirect(redirect_url)
#                 return Response({
#                     "message": "Invitation already accepted. Please login using your email.",
#                     "message_stat" : "accepted_and_verified",
#                     "redirect_url": redirect_url
#                 }, status=status.HTTP_200_OK)
            
#             # Mark as accepted if not already
#             if not invitation.is_accepted:
#                 invitation.is_accepted = True
#                 invitation.accepted_at = timezone.now()
#                 invitation.save(update_fields=['is_accepted', 'accepted_at'])

#                 return Response({
#                     "message": "Invitation Accepted. Please verify, enter again your email who received the invitation",
#                     "message_stat" : "accepted_and_for_verification",
#                     "redirect_url": None
#                 }, status=status.HTTP_200_OK)
            
            
#         except ClientInvitation.DoesNotExist:
       
#             return Response({
#                 "message": "Invitation not found",
#                 "message_stat" : "invitation_not_found",
#                 "redirect_url": None
#             }, status=status.HTTP_404_NOT_FOUND)
    
#     def post(self, request, token):
#         """API endpoint for invitation acceptance status"""
#         serializer = AcceptInvitationWithEmailSerializer(data=request.data)
#         print(f"request.data: {request.data}")
#         if serializer.is_valid():
#             invitation = serializer.context['invitation']
            
#             ## Check if invitation is already registered
#             if invitation.email_verified and invitation.is_active and invitation.is_accepted:
#                 subject = f"Login Token for - {invitation.client.company_name}"
#                 message = generate_login_email(
#                     invitation.client.contact_person_first_name,
#                     invitation.get_invite_url()
#                 )
                
#                 try:
#                     send_mail(
#                         subject=subject,
#                         message=message,
#                         from_email=settings.DEFAULT_FROM_EMAIL,
#                         recipient_list=[invitation.client.email],
#                         fail_silently=False,
#                     )
#                 except Exception as e:
#                     logger.error(f"Failed to send invitation email to {invitation.client.email}: {e}")
#                 return Response({
#                     'message': 'Email already verified, Login email sent. Please check your email and click the login link.'
#                 })

#             if not invitation.is_accepted:
#                 return Response({
#                     'message': 'Please check your email to accept the invitation first.'
#                 })

#             # Mark invitation as registered for new users
            
            
#             # return Response({
#             #     'message': 'Successfully verified',
#             #     'email': invitation.client.email,
#             #     'action': 'email_verified',
#             #     'status': 'newly_registered',
#             #     'redirect_url': '/client-admin/dashboard/'
#             # }, status=status.HTTP_200_OK)
#             # -----------------
#             try:
               
#                 # client_admin = ClientAdmin.objects.get(email=invitation.client.email, is_active=True)
#                 # login_token = InvitationToken.objects.create(
#                 #     token_type='login_token',
#                 #     client_admin=client_admin,
#                 #     email=invitation.client.email
#                 # )
#                 # login_token.mark_as_used()
                
#                 # # Create login session
#                 # login_session = LoginSession.objects.create(
#                 #     session_type='client_admin',
#                 #     client_admin=client_admin
#                 # )
                
#                 # # Update last login
#                 # client_admin.last_login = timezone.now()
#                 # client_admin.save(update_fields=['last_login'])
                
#                 # response_data = {
#                 #     'message': 'Login successful',
#                 #     'session_key': login_session.session_key,
#                 #     'user': {
#                 #         'id': str(client_admin.id),
#                 #         'email': client_admin.email,
#                 #         'first_name': client_admin.first_name,
#                 #         'last_name': client_admin.last_name,
#                 #         'role': 'client_admin',
#                 #         'client_company': client_admin.client.company_name,
#                 #     }
#                 # }
                
#                 # response = Response(response_data, status=status.HTTP_200_OK)
                
#                 # # Set session cookie
#                 # response.set_cookie(
#                 #     'session_key',
#                 #     login_session.session_key,
#                 #     max_age=60*60*24*30,  # 30 days
#                 #     httponly=True,
#                 #     secure=settings.COOKIE_SECURE,
#                 #     samesite=settings.COOKIE_SAMESITE
#                 # )
#                 email = serializer.validated_data["email"].lower().strip()
#                 try:
                    
#                     user = User.objects.get(email=email)
#                     invitation.email_verified = True
#                     invitation.save()
#                     logger.info(f"Successful ------------------ try {user}")
#                 except User.DoesNotExist:
#                     return Response({"error": "User not found"}, status=404)

#                 # Generate tokens
#                 # user = User.objects.filter(email=email)
#                 if not user:
#                     return Response(
#                         {"error": "Invalid exiting user with that client"},
#                         status=status.HTTP_400_BAD_REQUEST,
#                     )
#                 # if user.is_locked_out:
#                 #     return Response(
#                 #         {
#                 #             "error": f"Account is locked due to multiple failed login attempts. "
#                 #             f"Please try again after "
#                 #             f"{settings.LOCKOUT_DURATION.total_seconds() / 60} minutes "
#                 #         },
#                 #         status=status.HTTP_403_FORBIDDEN,
#                 #     )

              

#                 refresh = RefreshToken.for_user(user)
#                 access_token = str(refresh.access_token)
#                 refresh_token = str(refresh)
#                 logger.info(f"Successful ------------------ after token")
#                 print(f"user -----{user}")
#                 # Update last login
#                 user.last_login = timezone.now()
#                 user.save(update_fields=['last_login'])
                
#                 # Prepare response data
#                 response_data = {
#                     'message': 'Login successful',
#                     'access': access_token,
#                     'refresh': refresh_token,
#                     'user': {
#                         'id': user.id,
#                         'email': user.email,
#                         'first_name': getattr(user, 'first_name', ''),
#                         'last_name': getattr(user, 'last_name', ''),
#                         'is_active': user.is_active,
#                         'last_login': user.last_login.isoformat() if user.last_login else None,
#                     }
#                 }
                
#                 response = Response(response_data, status=status.HTTP_200_OK)
                
#                 # Set authentication cookies
#                 set_auth_cookies(response, access_token, refresh_token)
                
#                 logger.info(f"User {user.email} logged in successfully")
                
#                 return response
                
#             except Exception as e:
#                 logger.error(f"Error {e}")
#                 print(f"Error: {e}")
#                 return Response(
#                     {"error": f"Error: {e}"},
#                     status=status.HTTP_400_BAD_REQUEST
#                 )
            
#             # ----------------------------
          
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
@method_decorator(never_cache, name='dispatch')
class ClientAdminAcceptInvite(APIView):
    permission_classes = [] # No authentication needed for this endpoint

    def get(self, request, token, *args, **kwargs):
        """Handles GET request to accept invitation via token in URL."""
  
        try:
            invitation = get_object_or_404(ClientInvitation, token=token, is_active=True)
        except Invitation.DoesNotExist:  
            return Response(
                {"detail": "Invitation not found or invalid token."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e: 
            logger.error(f"Error retrieving invitation for token {token}: {e}")
            return Response(
                {"detail": "Not valid invitation."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        try:
            invitation = get_object_or_404(ClientInvitation, token=token)
        except Exception:
            return Response(
                {"detail": "Invitation not found"},
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
    


from .authentication import clear_auth_cookies
# class ClientAdminLogoutView(APIView):
#     def post(self, request):
#         # ... handle blacklisting ...
#         response = Response({"message": "Logout successful"}, status=200)
#         clear_auth_cookies(response)
#         return response


from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

class ClientAdminLogoutView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        refresh_token = request.data.get("refresh") or request.COOKIES.get("refresh")
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except (TokenError, InvalidToken):
                pass

        response = Response({"message": "Logged out"}, status=status.HTTP_200_OK)
        response.delete_cookie("access")
        response.delete_cookie("refresh")
        response.delete_cookie("logged_in")
        return response



class ClientAdminCustomLogoutView(APIView):
    authentication_classes = []  # disable auth for this view
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        refresh_token = request.COOKIES.get("refresh")
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except TokenError:
                pass  # Don't break logout even if token is invalid

        response = Response({"message": "Logout successful"}, status=status.HTTP_200_OK)

        # Clear auth cookies
        response.delete_cookie("access", path=settings.COOKIE_PATH)
        response.delete_cookie("refresh", path=settings.COOKIE_PATH)
        response.delete_cookie("logged_in", path=settings.COOKIE_PATH)

        return response


@method_decorator(never_cache, name='dispatch')
class ClientAdminVerifyInvitationtokenView(APIView):
    """Handle invitation acceptance"""
    
    permission_classes = [permissions.AllowAny]
    throttle_classes = [AnonRateThrottle]
    
    
    def get(self, request):
        serializer = AcceptInvitationWithEmailSerializer(data=request.data)
        print(f"request.data: {request.data}")
        if serializer.is_valid():
            invitation = serializer.context['invitation']
            
            ## Check if invitation is already registered
            if invitation.email_verified and invitation.is_active and invitation.is_accepted:
                subject = f"Login Token for - {invitation.client.company_name}"
                message = generate_login_email(
                    invitation.client.contact_person_first_name,
                    invitation.get_invite_url()
                )
                
                try:
                    send_mail(
                        subject=subject,
                        message=message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[invitation.client.email],
                        fail_silently=False,
                    )
                except Exception as e:
                    logger.error(f"Failed to send invitation email to {invitation.client.email}: {e}")
                return Response({
                    'message': 'Email already verified, Login email sent. Please check your email and click the login link.'
                })

        # token = request.data.get("token")

        # if not token:
        #     return Response(
        #         {"error": "Token is required"},
        #         status=status.HTTP_400_BAD_REQUEST,
        #     )
        # # user = User.objects.filter(otp=otp, otp_expiry_time__gt=timezone.now()).first()
        # client_invitation = ClientInvitation.objects.filter(token=token)
        # if not client_invitation:
        #     return Response(
        #         {"error": "No Invitation Exist."},
        #         status=status.HTTP_400_BAD_REQUEST,
        #     )
        # user = User.objects.filter(email=client_invitation.client.email)
        # if not user:
        #     return Response(
        #         {"error": "Invalid exiting user with that client"},
        #         status=status.HTTP_400_BAD_REQUEST,
        #     )
        # if user.is_locked_out:
        #     return Response(
        #         {
        #             "error": f"Account is locked due to multiple failed login attempts. "
        #             f"Please try again after "
        #             f"{settings.LOCKOUT_DURATION.total_seconds() / 60} minutes "
        #         },
        #         status=status.HTTP_403_FORBIDDEN,
        #     )

        # # user.verify_otp(otp)

        # refresh = RefreshToken.for_user(user)
        # access_token = str(refresh.access_token)
        # refresh_token = str(refresh)

        # response = Response(
        #     {
        #         "success": "Login successful. Now add your profile information, "
        #         "so that we can create an account for you"
        #     },
        #     status=status.HTTP_200_OK,
        # )
        # set_auth_cookies(response, access_token, refresh_token)
        # logger.info(f"Successful login with OTP: {user.email}")
        # return response

# class ClientAdminVerifyView(APIView):
#     permission_classes = [permissions.AllowAny]

#     def get(self, request):
#         token = request.data.get("token")

#         if not token:
#             return Response(
#                 {"error": "Token is required"},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
#         # user = User.objects.filter(otp=otp, otp_expiry_time__gt=timezone.now()).first()
#         client_invitation = ClientInvitation.objects.filter(token=token)
#         if not client_invitation:
#             return Response(
#                 {"error": "No Invitation Exist."},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
#         user = User.objects.filter(email=client_invitation.client.email)
#         if not user:
#             return Response(
#                 {"error": "Invalid exiting user with that client"},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
#         if user.is_locked_out:
#             return Response(
#                 {
#                     "error": f"Account is locked due to multiple failed login attempts. "
#                     f"Please try again after "
#                     f"{settings.LOCKOUT_DURATION.total_seconds() / 60} minutes "
#                 },
#                 status=status.HTTP_403_FORBIDDEN,
#             )

#         # user.verify_otp(otp)

#         refresh = RefreshToken.for_user(user)
#         access_token = str(refresh.access_token)
#         refresh_token = str(refresh)

#         response = Response(
#             {
#                 "success": "Login successful. Now add your profile information, "
#                 "so that we can create an account for you"
#             },
#             status=status.HTTP_200_OK,
#         )
#         set_auth_cookies(response, access_token, refresh_token)
#         logger.info(f"Successful login with OTP: {user.email}")
#         return response
