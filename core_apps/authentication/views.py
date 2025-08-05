from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.db import transaction
import logging
from core_apps.clients.models import Client, ClientInvitation
from .models import (
    ClientAdmin, Stakeholder, 
    StakeholderGroup, InvitationToken, LoginSession
)
from .serializers import (
     ClientAdminCreateSerializer,
    StakeholderGroupSerializer, StakeholderCreateSerializer,
    StakeholderRegistrationSerializer, EmailLoginSerializer,
    InvitationTokenSerializer, ClientAdminDetailSerializer,
    StakeholderDetailSerializer
)
from .permissions import IsTerramoAdmin, IsClientAdmin, IsStakeholder
from .utils import generate_invitation_email, generate_login_email, set_auth_cookies
from rest_framework.permissions import AllowAny, IsAuthenticated



logger = logging.getLogger(__name__)

class TerramoAdminLoginView(APIView):
    """Login view for Terramo Admin (actual Django users)"""
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password:
            return Response(
                {'error': 'Email and password are required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = authenticate(request, username=email, password=password)
        
        if user is None:
            return Response(
                {'error': 'Invalid credentials'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        if not user.is_active:
            return Response(
                {'error': 'User account is disabled'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        
        # Update last login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        response_data = {
            'message': 'Login successful',
            'access': access_token,
            'refresh': refresh_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'role': user.role,
                'first_name': user.first_name,
                'last_name': user.last_name,
            }
        }
        
        response = Response(response_data, status=status.HTTP_200_OK)
        set_auth_cookies(response, access_token, refresh_token)
        
        return response

# class ClientCreateView(generics.CreateAPIView):
#     """Create client and client admin by Terramo Admin"""
#     serializer_class = ClientCreateSerializer
#     permission_classes = [IsTerramoAdmin]
    
#     @transaction.atomic
#     def perform_create(self, serializer):
#         # Create client
#         client = serializer.save(created_by=self.request.user)
        
#         # Create client admin
#         client_admin = ClientAdmin.objects.create(
#             client=client,
#             email=client.email,
#             first_name=client.first_name,
#             last_name=client.last_name
#         )
        
#         # Create default "Management" stakeholder group
#         StakeholderGroup.objects.create(
#             name="Management",
#             client=client,
#             created_by=client_admin
#         )
        
#         # Generate invitation token for client admin
#         invitation_token = InvitationToken.objects.create(
#             token_type='client_admin_invite',
#             client_admin=client_admin,
#             email=client_admin.email
#         )
        
#         # Send invitation email
#         self.send_invitation_email(client_admin, invitation_token)
        
#         return client
    
#     def send_invitation_email(self, client_admin, invitation_token):
#         """Send invitation email to client admin"""
#         subject = f"Invitation to Terramo System - {client_admin.client.company_name}"
#         invitation_link = f"{settings.DOMAIN}/api/v1/authentication/client-admin/accept-invitation/{invitation_token.token}"
        
#         message = generate_invitation_email(
#             client_admin.first_name,
#             client_admin.client.company_name,
#             invitation_link
#         )
        
#         try:
#             send_mail(
#                 subject=subject,
#                 message=message,
#                 from_email=settings.DEFAULT_FROM_EMAIL,
#                 recipient_list=[client_admin.email],
#                 fail_silently=False,
#             )
#         except Exception as e:
#             logger.error(f"Failed to send invitation email to {client_admin.email}: {e}")

class ClientAdminInvitationAcceptView(APIView):
    """Accept client admin invitation"""
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, token):
        """Validate invitation token and redirect to login"""
        try:
            invitation = get_object_or_404(
                InvitationToken, 
                token=token, 
                token_type='client_admin_invite'
            )
            
            if not invitation.is_valid():
                return Response(
                    {'error': 'Invalid or expired invitation token'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Mark invitation as used
            invitation.mark_as_used()
            
            return Response({
                'message': 'Invitation accepted. Please login with your email.',
                'email': invitation.email,
                'redirect_url': f"{settings.DOMAIN}/api/v1/authentication/client-admin/login"
            })
            
        except Exception as e:
            logger.error(f"Error accepting invitation: {e}")
            return Response(
                {'error': 'Invalid invitation'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

class ClientAcceptInviteVerifiedLogin(APIView):
    """FINAL: Client Accepted the Invite, verified email and log them in"""
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = EmailLoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid input', 'details': serializer.errors}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        email = serializer.validated_data['email']
        
        try:
            client_admin = ClientAdmin.objects.get(email=email, is_active=True)

        except ClientAdmin.DoesNotExist:
            return Response(
                {'error': 'Client admin not found or inactive'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if there's a valid existing invitation
        accepted_invitation = ClientInvitation.objects.filter(
            email=email,
            token_type='client_admin_invite',
            is_used=True
        ).first()
        
        if not accepted_invitation:
            return Response(
                {'error': 'No valid invitation found. Please contact Terramo admin.'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Generate login token
        login_token = InvitationToken.objects.create(
            token_type='login_token',
            client_admin=client_admin,
            email=email
        )
        
        # Send login email
        self.send_login_email(client_admin, login_token)
        
        return Response({
            'message': 'Login email sent. Please check your email and click the login link.'
        })
    
    def send_login_email(self, client_admin, login_token):
        """Send login email to client admin"""
        subject = "Login to Terramo System"
        login_link = f"{settings.DOMAIN}/api/v1/authentication/client-admin/login/{login_token.token}"
        
        message = generate_login_email(
            client_admin.first_name,
            login_link
        )
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[client_admin.email],
                fail_silently=False,
            )
        except Exception as e:
            logger.error(f"Failed to send login email to {client_admin.email}: {e}")

class ClientAdminLoginView(APIView):
    """Login view for Client Admin (email only)"""
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = EmailLoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid input', 'details': serializer.errors}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        email = serializer.validated_data['email']
        
        try:
            client_admin = ClientAdmin.objects.get(email=email, is_active=True)
        except ClientAdmin.DoesNotExist:
            return Response(
                {'error': 'Client admin not found or inactive'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if there's a valid existing invitation
        existing_invitation = InvitationToken.objects.filter(
            email=email,
            token_type='client_admin_invite',
            is_used=True
        ).first()
        
        if not existing_invitation:
            return Response(
                {'error': 'No valid invitation found. Please contact Terramo admin.'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Generate login token
        login_token = InvitationToken.objects.create(
            token_type='login_token',
            client_admin=client_admin,
            email=email
        )
        
        # Send login email
        self.send_login_email(client_admin, login_token)
        
        return Response({
            'message': 'Login email sent. Please check your email and click the login link.'
        })
    
    def send_login_email(self, client_admin, login_token):
        """Send login email to client admin"""
        subject = "Login to Terramo System"
        login_link = f"{settings.DOMAIN}/api/v1/authentication/client-admin/login/{login_token.token}"
        
        message = generate_login_email(
            client_admin.first_name,
            login_link
        )
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[client_admin.email],
                fail_silently=False,
            )
        except Exception as e:
            logger.error(f"Failed to send login email to {client_admin.email}: {e}")

class ClientAdminTokenLoginView(APIView):
    """Token-based login for client admin"""
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, token):
        """Login client admin using token"""
        try:
            # check if there is login token available
            login_token = get_object_or_404(
                InvitationToken,
                token=token,
                token_type='login_token'
            )
            
            if not login_token.is_valid():
                return Response(
                    {'error': 'Invalid or expired login token'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            client_admin = login_token.client_admin
            if not client_admin or not client_admin.is_active:
                return Response(
                    {'error': 'Client admin not found or inactive'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Mark token as used
            login_token.mark_as_used()
            
            # Create login session
            login_session = LoginSession.objects.create(
                session_type='client_admin',
                client_admin=client_admin
            )
            
            # Update last login
            client_admin.last_login = timezone.now()
            client_admin.save(update_fields=['last_login'])
            
            response_data = {
                'message': 'Login successful',
                'session_key': login_session.session_key,
                'user': {
                    'id': str(client_admin.id),
                    'email': client_admin.email,
                    'first_name': client_admin.first_name,
                    'last_name': client_admin.last_name,
                    'role': 'client_admin',
                    'client_company': client_admin.client.company_name,
                }
            }
            
            response = Response(response_data, status=status.HTTP_200_OK)
            
            # Set session cookie
            response.set_cookie(
                'session_key',
                login_session.session_key,
                max_age=60*60*24*30,  # 30 days
                httponly=True,
                secure=settings.COOKIE_SECURE,
                samesite=settings.COOKIE_SAMESITE
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Error in token login: {e}")
            return Response(
                {'error': 'Invalid login token'}, 
                status=status.HTTP_400_BAD_REQUEST
            )




class StakeholderGroupCreateView(generics.CreateAPIView):
    """Create stakeholder group by Client Admin"""
    serializer_class = StakeholderGroupSerializer
    permission_classes = [IsClientAdmin]
    
    def perform_create(self, serializer):
        # Get client admin from session
        client_admin = self.get_client_admin()
        serializer.save(
            client=client_admin.client,
            created_by=client_admin
        )
    
    def get_client_admin(self):
        session_key = self.request.COOKIES.get('session_key')
        if not session_key:
            raise permissions.PermissionDenied("No valid session")
        
        try:
            session = LoginSession.objects.get(
                session_key=session_key,
                session_type='client_admin'
            )
            if not session.is_valid():
                raise permissions.PermissionDenied("Session expired")
            return session.client_admin
        except LoginSession.DoesNotExist:
            raise permissions.PermissionDenied("Invalid session")

# class StakeholderCreateView(generics.CreateAPIView):
#     """Create stakeholder by Client Admin"""
#     serializer_class = StakeholderCreateSerializer
#     permission_classes = [IsClientAdmin]
    
#     @transaction.atomic
#     def perform_create(self, serializer):
#         group_id = self.kwargs.get('group_id')
#         client_admin = self.get_client_admin()
        
#         # Get stakeholder group
#         group = get_object_or_404(
#             StakeholderGroup,
#             id=group_id,
#             client=client_admin.client
#         )
        
#         # Create stakeholder
#         stakeholder = serializer.save(group=group)
        
#         # Generate invitation token
#         invitation_token = InvitationToken.objects.create(
#             token_type='stakeholder_invite',
#             stakeholder=stakeholder,
#             email=stakeholder.email
#         )
        
#         return {
#             'stakeholder': stakeholder,
#             'invitation_token': invitation_token.token
#         }
    
#     def create(self, request, *args, **kwargs):
#         result = self.perform_create(self.get_serializer(data=request.data))
        
#         return Response({
#             'message': 'Stakeholder created successfully',
#             'stakeholder': StakeholderDetailSerializer(result['stakeholder']).data,
#             'invitation_token': result['invitation_token']
#         }, status=status.HTTP_201_CREATED)
    
#     def get_client_admin(self):
#         session_key = self.request.COOKIES.get('session_key')
#         if not session_key:
#             raise permissions.PermissionDenied("No valid session")
        
#         try:
#             session = LoginSession.objects.get(
#                 session_key=session_key,
#                 session_type='client_admin'
#             )
#             if not session.is_valid():
#                 raise permissions.PermissionDenied("Session expired")
#             return session.client_admin
#         except LoginSession.DoesNotExist:
#             raise permissions.PermissionDenied("Invalid session")

class StakeholderCreateView(generics.CreateAPIView):
    """Create stakeholder by Client Admin"""
    serializer_class = StakeholderCreateSerializer
    permission_classes = [IsClientAdmin]

    def get_client_admin(self):
        session_key = self.request.COOKIES.get('session_key')
        if not session_key:
            raise permissions.PermissionDenied("No valid session")

        try:
            session = LoginSession.objects.get(
                session_key=session_key,
                session_type='client_admin'
            )
            if not session.is_valid():
                raise permissions.PermissionDenied("Session expired")
            return session.client_admin
        except LoginSession.DoesNotExist:
            raise permissions.PermissionDenied("Invalid session")

    def get_serializer_context(self):
        context = super().get_serializer_context()
        group_id = self.kwargs.get('group_id')
        client_admin = self.get_client_admin()
        group = get_object_or_404(StakeholderGroup, id=group_id, client=client_admin.client)
        context['group'] = group
        return context

    @transaction.atomic
    def perform_create(self, serializer):
        group = self.get_serializer_context()['group']
        stakeholder = serializer.save(group=group, is_registered=True)

        # Generate invitation token
        invitation_token = InvitationToken.objects.create(
            token_type='stakeholder_invite',
            stakeholder=stakeholder,
            email=stakeholder.email
        )

        return {
            'stakeholder': stakeholder,
            'invitation_token': invitation_token.token
        }

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)  
        result = self.perform_create(serializer)

        return Response({
            'message': 'Stakeholder created successfully',
            'stakeholder': StakeholderDetailSerializer(result['stakeholder']).data,
            'invitation_token': result['invitation_token']
        }, status=status.HTTP_201_CREATED)
    
class StakeholderInvitationAcceptView(APIView):
    """Accept stakeholder invitation"""
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, token):
        """Validate invitation token"""
        try:
            invitation = get_object_or_404(
                InvitationToken,
                token=token,
                token_type='stakeholder_invite'
            )
            
            if not invitation.is_valid():
                return Response(
                    {'error': 'Invalid or expired invitation token'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            stakeholder = invitation.stakeholder
            
            return Response({
                'message': 'Valid invitation token',
                'email': invitation.email,
                'group_name': stakeholder.group.name,
                'company_name': stakeholder.group.client.company_name,
                'is_registered': stakeholder.is_registered,
                'redirect_url': f"{settings.DOMAIN}/api/v1/authentication/stakeholder/login" if stakeholder.is_registered else f"{settings.DOMAIN}/api/v1/authentication/stakeholder/register"
            })
            
        except Exception as e:
            logger.error(f"Error accepting stakeholder invitation: {e}")
            return Response(
                {'error': 'Invalid invitation'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

"""
------- invitation token: 
"""
class StakeholderGroupInvitationAcceptView(APIView):
    """Accept stakeholder invitation using invitation token"""
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, token):
        """Validate invitation token"""
        try:
            stakeholder_invitation = get_object_or_404(
                StakeholderGroup,
                invitation_token=token
            )
            
            
            # get_invite_full_url
            return Response({
                'message': 'Stakeholder Group: Valid invitation token',
                'group_name': stakeholder_invitation.name,
                'group_id': stakeholder_invitation.id,
                'invitation_token': stakeholder_invitation.invitation_token,
                'company_info': {
                    "id" : stakeholder_invitation.client.id,
                    "name" : stakeholder_invitation.client.company_name
                } ,
            })
            
        except Exception as e:
            logger.error(f"Error accepting stakeholder group invitation: {e}")
            return Response(
                {'error': 'Invalid Stakeholder Group invitation'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

class StakeholderLoginView(APIView):
    """Login view for Stakeholder (email only)"""
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = EmailLoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid input', 'details': serializer.errors}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        email = serializer.validated_data['email']
        
        try:
            stakeholder = Stakeholder.objects.get(email=email)
        except Stakeholder.DoesNotExist:
            return Response(
                {'error': 'Stakeholder not found. Please check your email or contact your administrator.'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        if not stakeholder.is_registered:
            return Response(
                {'error': 'Please complete your registration first.'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Generate login token
        login_token = InvitationToken.objects.create(
            token_type='login_token',
            stakeholder=stakeholder,
            email=email
        )
        
        # Send login email
        self.send_login_email(stakeholder, login_token)
        
        return Response({
            'message': 'Login email sent. Please check your email and click the login link.'
        })
    
    def send_login_email(self, stakeholder, login_token):
        """Send login email to stakeholder"""
        subject = "Login to Terramo System"
        login_link = f"{settings.DOMAIN}/api/v1/authentication/stakeholder/login/{login_token.token}"
        
        message = generate_login_email(
            stakeholder.first_name or "Stakeholder",
            login_link
        )
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[stakeholder.email],
                fail_silently=False,
            )
        except Exception as e:
            logger.error(f"Failed to send login email to {stakeholder.email}: {e}")

"""
UPDATED CODE FOR STAKEHOLDER GROUPS: ------ after accept invites
"""
class StakeholderCheckEmailView(APIView):
    """Login view for Stakeholder (email only)"""
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, token):
        serializer = EmailLoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid input', 'details': serializer.errors}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        email = serializer.validated_data['email']
        
        try:
            stakeholder = Stakeholder.objects.get(email=email)

        except Stakeholder.DoesNotExist:
            return Response(
                {'error': 'Stakeholder not found. Please check your email or contact your administrator.'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        if not stakeholder.is_registered:
            return Response(
                {'error': 'Please complete your registration first.'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Generate login token
        login_token = InvitationToken.objects.create(
            token_type='login_token',
            stakeholder=stakeholder,
            email=email
        )
        
        # Send login email
        self.send_login_email(stakeholder, login_token)
        
        return Response({
            'message': 'Login email sent. Please check your email and click the login link.'
        })
    
    def send_login_email(self, stakeholder, login_token):
        """Send login email to stakeholder"""
        subject = "Login to Terramo System"
        login_link = f"{settings.DOMAIN}/api/v1/authentication/stakeholder/login/{login_token.token}"
        
        message = generate_login_email(
            stakeholder.first_name or "Stakeholder",
            login_link
        )
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[stakeholder.email],
                fail_silently=False,
            )
        except Exception as e:
            logger.error(f"Failed to send login email to {stakeholder.email}: {e}")

class StakeholderRegisterView(APIView):
    """Register stakeholder after invitation"""
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        
        if not email:
            return Response(
                {'error': 'Email is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            stakeholder = Stakeholder.objects.get(email=email)
        except Stakeholder.DoesNotExist:
            return Response(
                {'error': 'Stakeholder not found. Please check your invitation.'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        if stakeholder.is_registered:
            return Response(
                {'error': 'Stakeholder already registered. Please login instead.'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update stakeholder details
        serializer = StakeholderRegistrationSerializer(stakeholder, data=request.data, partial=True)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid input', 'details': serializer.errors}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Mark as registered and save
        stakeholder = serializer.save(is_registered=True)
        
        # Generate login token
        login_token = InvitationToken.objects.create(
            token_type='login_token',
            stakeholder=stakeholder,
            email=stakeholder.email
        )
        
        # Create login session
        login_session = LoginSession.objects.create(
            session_type='stakeholder',
            stakeholder=stakeholder
        )
        
        response_data = {
            'message': 'Registration successful',
            'session_key': login_session.session_key,
            'user': {
                'id': str(stakeholder.id),
                'email': stakeholder.email,
                'first_name': stakeholder.first_name,
                'last_name': stakeholder.last_name,
                'role': 'stakeholder',
                'group_name': stakeholder.group.name,
                'company_name': stakeholder.group.client.company_name,
            }
        }
        
        response = Response(response_data, status=status.HTTP_201_CREATED)
        
        # Set session cookie
        response.set_cookie(
            'session_key',
            login_session.session_key,
            max_age=60*60*24*30,  # 30 days
            httponly=True,
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE
        )
        
        return response

class StakeholderTokenLoginView(APIView):
    """Token-based login for stakeholder"""
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, token):
        """Login stakeholder using token"""
        try:
            login_token = get_object_or_404(
                InvitationToken,
                token=token,
                token_type='login_token'
            )
            
            if not login_token.is_valid():
                return Response(
                    {'error': 'Invalid or expired login token'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            stakeholder = login_token.stakeholder
            if not stakeholder or not stakeholder.is_registered:
                return Response(
                    {'error': 'Stakeholder not found or not registered'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Mark token as used
            login_token.mark_as_used()
            
            # Create login session
            login_session = LoginSession.objects.create(
                session_type='stakeholder',
                stakeholder=stakeholder
            )
            
            # Update last login
            stakeholder.last_login = timezone.now()
            stakeholder.save(update_fields=['last_login'])
            
            response_data = {
                'message': 'Login successful',
                'session_key': login_session.session_key,
                'user': {
                    'id': str(stakeholder.id),
                    'email': stakeholder.email,
                    'first_name': stakeholder.first_name,
                    'last_name': stakeholder.last_name,
                    'role': 'stakeholder',
                    'group_name': stakeholder.group.name,
                    'company_name': stakeholder.group.client.company_name,
                }
            }
            
            response = Response(response_data, status=status.HTTP_200_OK)
            
            # Set session cookie
            response.set_cookie(
                'session_key',
                login_session.session_key,
                max_age=60*60*24*30,  # 30 days
                httponly=True,
                secure=settings.COOKIE_SECURE,
                samesite=settings.COOKIE_SAMESITE
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Error in stakeholder token login: {e}")
            return Response(
                {'error': 'Invalid login token'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

class LogoutView(APIView):
    """Universal logout view"""
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        session_key = request.COOKIES.get('session_key')
        logger.info(f"session_key {session_key}")
        print(f"session_key {session_key}")
        if session_key:
            try:
                # Deactivate session
                login_session = LoginSession.objects.get(session_key=session_key)
                login_session.is_active = False
                login_session.save()
            except LoginSession.DoesNotExist:
                pass
        
        # For Terramo Admin JWT logout
        refresh_token = request.data.get('refresh_token') or request.COOKIES.get('refresh')
        print(f"refresh -- token {refresh_token}")
        if refresh_token:
            try:
                from rest_framework_simplejwt.tokens import RefreshToken
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception as e:
                logger.warning(f"Error blacklisting token during logout: {e}")
        
        response = Response(
            {'message': 'Logout successful'}, 
            status=status.HTTP_200_OK
        )
        
        # Clear all cookies
        response.delete_cookie('access', path=settings.COOKIE_PATH)
        response.delete_cookie('refresh', path=settings.COOKIE_PATH)
        response.delete_cookie('logged_in', path=settings.COOKIE_PATH)
        response.delete_cookie('session_key', path=settings.COOKIE_PATH)
        
        return response


"""
Final: v2
"""
