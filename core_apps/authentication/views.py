from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView, UpdateAPIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import get_object_or_404, redirect
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
    StakeholderDetailSerializer, CreateStakeholderSerializer
)
from .permissions import IsTerramoAdmin, IsClientAdmin, IsStakeholder
from .utils import generate_invitation_email, generate_login_email, set_auth_cookies
from rest_framework.permissions import AllowAny, IsAuthenticated

from core_apps.user_auth.models import User as UserData

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
        serializer = StakeholderRegistrationDataSerializer(stakeholder, data=request.data, partial=True)
        
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
        response.delete_cookie('user_role', path=settings.COOKIE_PATH)
        response.delete_cookie('session_key', path=settings.COOKIE_PATH)
        
        return response


"""
TOKEN BASED AUTHENTICATION: --------]
"""
from django.views.decorators.cache import never_cache
from django.utils.decorators import method_decorator
from rest_framework.throttling import AnonRateThrottle
from django.contrib.auth.models import User
from .models import AuthToken, LoginToken, create_login_token, verify_login_token


logger = logging.getLogger(__name__)


def generate_login_email(name, login_url, expires_in_minutes):
    """Generate login email content with secure URL"""
    return f"""
    Hi {name},
    
    You requested a secure login link for your client admin account.
    
    Click the link below to log in to your account:
    {login_url}
    
    This link will expire in {expires_in_minutes} minutes for security purposes.
    
    If you didn't request this login link, please ignore this email and contact support if you're concerned about your account security.
    
    For security reasons, this link can only be used once.
    
    Best regards,
    Your Team
    """


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@method_decorator(never_cache, name='dispatch')
class ClientAdminRequestLoginView(APIView):
    """Handle login link requests for existing client admins"""
    
    permission_classes = [permissions.AllowAny]
    throttle_classes = [AnonRateThrottle]
    
    def post(self, request):
        """Send secure login link to registered client admin"""
        try:
            # Get email from request
            email = request.data.get('email', '').lower().strip()
            ip_address = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            
            logger.info(f"Login request received for email: {email} from IP: {ip_address}")
            
            if not email:
                return Response({
                    "error": "Email is required"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Basic email validation
            if '@' not in email:
                return Response({
                    "error": "Please enter a valid email address"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check if client invitation exists for this email
            try:
                invitation = ClientInvitation.objects.get(
                    client__email=email,
                    is_active=True
                )
                # logger.info(f"Found invitation for {email}: status={invitation.status}")
                
                client = invitation.client
                
                # Check if user can request login link using the new property
                if not invitation.can_send_login_link:
                    # Determine specific reason based on invitation status
                    if invitation.status == ClientInvitation.InvitationStatus.PENDING:
                        return Response({
                            "error": "Your account setup is not complete. Please check your email for the invitation link or contact your administrator.",
                            "status": "invitation_pending"
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                    elif invitation.status == ClientInvitation.InvitationStatus.SENT:
                        return Response({
                            "error": "Please check your email and click the invitation link to complete your account setup first.",
                            "status": "invitation_not_accepted"
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                    elif invitation.status == ClientInvitation.InvitationStatus.VIEWED:
                        return Response({
                            "error": "Please complete your account registration by accepting the terms in your invitation email.",
                            "status": "registration_incomplete"
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                    elif invitation.status == ClientInvitation.InvitationStatus.ACCEPTED:
                        return Response({
                            "error": "Please complete your account registration process.",
                            "status": "registration_incomplete"
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                    elif invitation.status == ClientInvitation.InvitationStatus.EXPIRED:
                        return Response({
                            "error": "Your invitation has expired. Please contact your administrator for a new invitation.",
                            "status": "invitation_expired"
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                    elif invitation.status == ClientInvitation.InvitationStatus.REVOKED:
                        return Response({
                            "error": "Your invitation has been revoked. Please contact your administrator.",
                            "status": "invitation_revoked"
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                    else:
                        return Response({
                            "error": "Account not ready for login. Please contact your administrator.",
                            "status": "account_not_ready"
                        }, status=status.HTTP_400_BAD_REQUEST)

                # Check if user account exists
                try:
                    user = User.objects.get(email=email, is_active=True)
                    logger.info(f"User account found for {email}")
                except User.DoesNotExist:
                    logger.error(f"User account not found for {email}")
                    return Response({
                        "error": "User account not found. Please complete your registration first or contact your administrator.",
                        "status": "user_not_found"
                    }, status=status.HTTP_404_NOT_FOUND)

                # Create secure login token
                try:
                    device_info = {
                        'user_agent': user_agent,
                        'ip_address': ip_address,
                        'requested_at': timezone.now().isoformat()
                    }
                    
                    login_token, raw_token = create_login_token(
                        user=user,
                        expires_in_hours=1,  # 1 hour expiration
                        ip_address=ip_address,
                        device_info=device_info
                    )
                    
                    logger.info(f"Created login token for {email}")
                    
                    # Generate secure login URL
                    login_url = f"{settings.FRONTEND_DOMAIN_URL}/auth/login-with-token/{raw_token}/"
                    
                    # Get user's name for personalized email
                    user_name = user.first_name or client.contact_person_first_name or "User"
                    
                    # Generate login email
                    subject = f"Secure Login Link - {client.company_name}"
                    message = generate_login_email(
                        user_name, 
                        login_url, 
                        login_token.auth_token.expires_in_minutes
                    )
                    
                    # Send email
                    send_mail(
                        subject=subject,
                        message=message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[email],
                        fail_silently=False,
                    )
                    
                    logger.info(f"Secure login link sent successfully to {email}")
                    
                    return Response({
                        "message": f"A secure login link has been sent to your email address. The link will expire in {login_token.auth_token.expires_in_minutes} minutes.",
                        "success": True,
                        "status": "login_link_sent",
                        "expires_in_minutes": login_token.auth_token.expires_in_minutes
                    }, status=status.HTTP_200_OK)
                    
                except Exception as e:
                    logger.error(f"Failed to send login email to {email}: {e}")
                    return Response({
                        "error": "Failed to send email. Please try again later.",
                        "status": "email_send_failed"
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
            except ClientInvitation.DoesNotExist:
                logger.warning(f"No invitation found for {email}")
                return Response({
                    "error": "No invitation found for this email address. Please contact your administrator to get invited.",
                    "status": "invitation_not_found"
                }, status=status.HTTP_404_NOT_FOUND)
                
            except Exception as invitation_error:
                logger.error(f"Error finding invitation for {email}: {invitation_error}")
                return Response({
                    "error": "Error processing your request. Please try again later.",
                    "status": "invitation_error"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as e:
            logger.error(f"Unexpected error in request login for {request.data.get('email', 'unknown')}: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return Response({
                "error": "An unexpected error occurred while processing your request. Please try again later.",
                "status": "server_error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(never_cache, name='dispatch')
class LoginWithTokenView(APIView):
    """Handle login via secure token"""
    
    permission_classes = [permissions.AllowAny]
    throttle_classes = [AnonRateThrottle]
    
    def get(self, request, token):
        """Process login token and authenticate user"""
        try:
            ip_address = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            
            logger.info(f"Login attempt with token from IP: {ip_address}")
            
            # Verify and use the token
            # from accounts.models import verify_login_token
            # from .models import verify_login_token
            user, error = verify_login_token(
                raw_token=token,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            if error:
                logger.warning(f"Token verification failed: {error}")
                return Response({
                    "error": error,
                    "status": "token_invalid"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if not user:
                logger.warning(f"No user found for token")
                return Response({
                    "error": "Invalid login token",
                    "status": "token_invalid"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Here you would typically create a session or return JWT tokens
            # For now, we'll just return success
            logger.info(f"Successful login for user: {user.email}")
            
            return Response({
                "message": "Login successful",
                "success": True,
                "user": {
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                },
                "status": "login_success"
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error in token login: {e}")
            return Response({
                "error": "An error occurred during login. Please try again.",
                "status": "login_error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



"""
Updated: Stakeholders Aug. 07, 2025 -- START --
"""
from rest_framework.exceptions import ValidationError, NotFound, PermissionDenied
from .serializers import StakeholderSerializer, SendInvitationSerializer, StakeholderInvitation, StakeholderGroupDataSerializer, StakeholderInvitationSerializer, EmailVerificationSerializer, StakeholderRegistrationDataSerializer, ApproveRejectSerializer
from datetime import timedelta

class StakeholderGroupListCreateView(generics.ListCreateAPIView):
    """List and create stakeholder groups - Client Admin only"""
    serializer_class = StakeholderGroupDataSerializer
    permission_classes = [IsClientAdmin]
    
    def get_queryset(self):
        return StakeholderGroup.objects.filter(
            client=self.request.user.client,
            is_active=True
        ).order_by('-created_at')
    
    def perform_create(self, serializer):
        try:
            serializer.save(
                client=self.request.user.client,
                created_by=self.request.user
            )
            logger.info(
                f"Stakeholder group '{serializer.instance.name}' created by "
                f"{self.request.user.email} for client {self.request.user.client.id}"
            )
        except Exception as e:
            logger.error(f"Failed to create stakeholder group: {str(e)}")
            raise ValidationError("Failed to create stakeholder group. Please try again.")

class StakeholderGroupDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, delete stakeholder group - Client Admin only"""
    serializer_class = StakeholderGroupDataSerializer
    permission_classes = [IsClientAdmin]
    
    def get_queryset(self):
        return StakeholderGroup.objects.filter(client=self.request.user.client)
    
    def perform_destroy(self, instance):
        """Soft delete by setting is_active to False"""
        instance.is_active = False
        instance.save()
        logger.info(
            f"Stakeholder group '{instance.name}' deactivated by "
            f"{self.request.user.email}"
        )



class SendStakeholderInvitationView(APIView):
    """Send stakeholder invitation - Client Admin only"""
    permission_classes = [IsClientAdmin]
    
    def post(self, request, group_id):
        try:
            # Validate group ownership
            group = get_object_or_404(
                StakeholderGroup,
                id=group_id,
                client=request.user.client,
                is_active=True
            )
            
            serializer = SendInvitationSerializer(
                data=request.data,
                context={'group_id': group_id}
            )
            serializer.is_valid(raise_exception=True)
            
            email = serializer.validated_data['email']
            send_email = serializer.validated_data['send_email']
            
            with transaction.atomic():
                # Create invitation
                invitation = StakeholderInvitation.objects.create(
                    stakeholder_group=group,
                    email=email,
                    sent_by=request.user,
                    expires_at=timezone.now() + timedelta(days=7)  # 7 days expiry
                )
                
                # Send email if requested
                if send_email:
                    self._send_invitation_email(invitation)
                
                logger.info(
                    f"Invitation created for {email} to group '{group.name}' "
                    f"by {request.user.email}. Email sent: {send_email}"
                )
            
            return Response({
                'message': 'Invitation created successfully',
                'invitation_id': invitation.id,
                'invitation_url': invitation.get_invitation_url(),
                'email_sent': send_email
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Failed to send invitation: {str(e)}")
            return Response(
                {'error': 'Failed to send invitation. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _send_invitation_email(self, invitation):
        """Send invitation email"""
        try:
            subject = f"Invitation to join {invitation.stakeholder_group.name}"
            message = (
                f"You have been invited to join the stakeholder group "
                f"'{invitation.stakeholder_group.name}' at {invitation.stakeholder_group.client.company_name}.\n\n"
                f"Click the following link to accept your invitation:\n"
                f"{invitation.get_invitation_url()}\n\n"
                f"This invitation will expire on {invitation.expires_at.strftime('%B %d, %Y at %I:%M %p')}.\n\n"
                f"If you did not expect this invitation, please ignore this email."
            )
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[invitation.email],
                fail_silently=False
            )
            
            invitation.email_status = 'delivered'
            invitation.save(update_fields=['email_status'])
            
        except Exception as e:
            logger.error(f"Failed to send email to {invitation.email}: {str(e)}")
            invitation.email_status = 'failed'
            invitation.save(update_fields=['email_status'])
            raise

class InvitationListView(generics.ListAPIView):
    """List invitations - Client Admin only"""
    serializer_class = StakeholderInvitationSerializer
    permission_classes = [IsClientAdmin]
    
    def get_queryset(self):
        return StakeholderInvitation.objects.filter(
            stakeholder_group__client=self.request.user.client
        ).order_by('-sent_at')

class GetInvitationLinkView(APIView):
    """Get invitation link for a group - Client Admin only"""
    permission_classes = [IsClientAdmin]
    
    def get(self, request, group_id):
        group = get_object_or_404(
            StakeholderGroup,
            id=group_id,
            client=request.user.client,
            is_active=True
        )
        
        return Response({
            'invitation_url': group.get_invite_full_url(),
            'group_name': group.name,
            'invitation_token': group.invitation_token
        })

# Public Views (No authentication required)

class ProcessInvitationView(APIView):
    """Process invitation link click - Public endpoint"""
    authentication_classes = []  # Disable JWT/session authentication
    permission_classes = [permissions.AllowAny]

    def get(self, request, token):  # Matches <str:token> in urls.py
        try:
            # Try to find invitation by token
            try:
                invitation = StakeholderInvitation.objects.get(invitation_token=token)
            except StakeholderInvitation.DoesNotExist:
                # Try group invitation
                try:
                    group = StakeholderGroup.objects.get(invitation_token=token, is_active=True)
                    return Response({
                        'type': 'group_invitation',
                        'group_id': group.id,
                        'group_name': group.name,
                        'company_name': group.client.company_name,
                        'requires_email': True,
                        'token': str(token)
                    })
                except StakeholderGroup.DoesNotExist:
                    raise NotFound("Invalid invitation link")

            # Check expiration
            if invitation.is_expired:
                return Response(
                    {'error': 'This invitation has expired'},
                    status=status.HTTP_410_GONE
                )

            # Update status if first click
            if invitation.status == 'sent':
                invitation.status = 'clicked'
                invitation.clicked_at = timezone.now()
                invitation.save(update_fields=['status', 'clicked_at'])

            # Return response based on current status
            if invitation.status == 'clicked':
                return Response({
                    'type': 'email_verification',
                    'group_name': invitation.stakeholder_group.name,
                    'company_name': invitation.stakeholder_group.client.company_name,
                    'token': str(token)
                })
            elif invitation.status == 'email_verified':
                return Response({
                    'type': 'registration',
                    'group_name': invitation.stakeholder_group.name,
                    'company_name': invitation.stakeholder_group.client.company_name,
                    'email': invitation.email,
                    'token': str(token)
                })
            elif invitation.status == 'completed':
                return Response({
                    'type': 'completed',
                    'message': 'Registration already completed for this invitation'
                })

        except NotFound:
            raise
        except Exception as e:
            logger.error(f"Error processing invitation {token}: {str(e)}", exc_info=True)
            return Response(
                {'error': 'Failed to process invitation'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class VerifyEmailView(APIView):
    """Verify email for invitation - Public endpoint"""
    authentication_classes = [] 
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        invitation = serializer.validated_data['invitation']
        
        # Update invitation status
        invitation.status = 'email_verified'
        invitation.email_verified_at = timezone.now()
        invitation.save(update_fields=['status', 'email_verified_at'])
        
        return Response({
            'message': 'Email verified successfully',
            'next_step': 'registration',
            'token': str(invitation.invitation_token)
        })

# class StakeholderRegistrationView(APIView):
#     """Complete stakeholder registration - Public endpoint"""
#     permission_classes = [permissions.AllowAny]
    
#     def post(self, request):
#         serializer = StakeholderRegistrationDataSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
        
#         invitation = serializer.validated_data['invitation']
        
#         try:
#             with transaction.atomic():
#                 # Create or update stakeholder
#                 stakeholder, created = Stakeholder.objects.get_or_create(
#                     email=invitation.email,
#                     group=invitation.stakeholder_group,
#                     defaults={
#                         'first_name': serializer.validated_data['first_name'],
#                         'last_name': serializer.validated_data['last_name'],
#                         'is_registered': True,
#                         'status': 'pending'  # Pending client admin approval
#                     }
#                 )
                
#                 if not created:
#                     # Update existing stakeholder
#                     stakeholder.first_name = serializer.validated_data['first_name']
#                     stakeholder.last_name = serializer.validated_data['last_name']
#                     stakeholder.is_registered = True
#                     stakeholder.status = 'pending'
#                     stakeholder.save()
                
#                 # Update invitation
#                 invitation.status = 'completed'
#                 invitation.completed_at = timezone.now()
#                 invitation.stakeholder = stakeholder
#                 invitation.save(update_fields=['status', 'completed_at', 'stakeholder'])
                
#                 logger.info(
#                     f"Stakeholder registration completed: {stakeholder.email} "
#                     f"for group '{invitation.stakeholder_group.name}'"
#                 )
        
#         except Exception as e:
#             logger.error(f"Registration failed for {invitation.email}: {str(e)}")
#             return Response(
#                 {'error': 'Registration failed. Please try again.'},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )
        
#         return Response({
#             'message': 'Registration completed successfully',
#             'status': 'pending_approval',
#             'stakeholder_id': stakeholder.id
#         }, status=status.HTTP_201_CREATED)

# Client Admin Approval Views

class ApproveStakeholderView(APIView):
    """Approve stakeholder - Client Admin only"""
    permission_classes = [IsClientAdmin]
    
    def post(self, request, pk):
        invitation = get_object_or_404(
            StakeholderInvitation,
            pk=pk,
            stakeholder_group__client=request.user.client,
            stakeholder__isnull=False
        )
        
        stakeholder = invitation.stakeholder
        if stakeholder.status != 'pending':
            return Response(
                {'error': 'Stakeholder is not in pending status'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        stakeholder.status = 'approved'
        stakeholder.save(update_fields=['status'])
        
        logger.info(
            f"Stakeholder {stakeholder.email} approved by {request.user.email} "
            f"for group '{invitation.stakeholder_group.name}'"
        )
        
        return Response({'message': 'Stakeholder approved successfully'})

class RejectStakeholderView(APIView):
    """Reject stakeholder - Client Admin only"""
    permission_classes = [IsClientAdmin]
    
    def post(self, request, pk):
        serializer = ApproveRejectSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        invitation = get_object_or_404(
            StakeholderInvitation,
            pk=pk,
            stakeholder_group__client=request.user.client,
            stakeholder__isnull=False
        )
        
        stakeholder = invitation.stakeholder
        if stakeholder.status != 'pending':
            return Response(
                {'error': 'Stakeholder is not in pending status'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        stakeholder.status = 'rejected'
        stakeholder.save(update_fields=['status'])
        
        logger.info(
            f"Stakeholder {stakeholder.email} rejected by {request.user.email} "
            f"for group '{invitation.stakeholder_group.name}'. "
            f"Reason: {serializer.validated_data.get('reason', 'No reason provided')}"
        )
        
        return Response({'message': 'Stakeholder rejected successfully'})
"""
Updated: Stakeholders Aug. 07, 2025 -- END --
"""
# from .serializers import InvitationValidateSerializer, EmailRequestVerificationSerializer
# class ValidateInvitationView(generics.GenericAPIView):
#     serializer_class = InvitationValidateSerializer
#     permission_classes = [AllowAny]

#     def post(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)

#         invitation = serializer.validated_data['invitation']
#         data = {
#             "type": "group_invitation",
#             "group_id": str(invitation.stakeholder_group.id),
#             "group_name": invitation.stakeholder_group.name,
#             "company_name": invitation.stakeholder_group.company.name,
#             "requires_email": True,  # Could be dynamic
#             "token": str(invitation.invitation_token)
#         }
#         return Response(data)


# class VerifyEmailInvitationView(generics.GenericAPIView):
#     serializer_class = EmailRequestVerificationSerializer
#     permission_classes = [AllowAny]

#     def post(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         stakeholder = serializer.save()

#         if stakeholder.is_registered and stakeholder.user:
#             # Auto-login
#             login(request, stakeholder.user)
#             return Response({"detail": "Login successful"}, status=status.HTTP_200_OK)

#         return Response({
#             "detail": "Email verified, proceed to registration",
#             "stakeholder_id": stakeholder.id
#         }, status=status.HTTP_200_OK)


# class StakeholderInvitationValidateView(APIView):
#     def get(self, request, token):
#         invitation = get_object_or_404(StakeholderInvitation, invitation_token=token)
        
#         if invitation.is_expired:
#             return Response({"error": "Invitation expired."}, status=status.HTTP_400_BAD_REQUEST)

#         return Response({
#             "type": "group_invitation",
#             "group_id": invitation.stakeholder_group.id,
#             "group_name": invitation.stakeholder_group.name,
#             "company_name": invitation.stakeholder_group.company.name,
#             "requires_email": True,
#             "token": str(invitation.invitation_token)
#         })

from .serializers import InvitationValidationSerializer, EmailSubmissionSerializer, UpdatedStakeholderSerializer, StakeholderApprovalSerializer
class ValidateInvitationView(APIView):
    """Validate invitation token and return group details"""
    authentication_classes = []
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = InvitationValidationSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            
            try:
                stakeholder_group = StakeholderGroup.objects.get(
                    invitation_token=token,
                    is_active=True
                )
                
                response_data = {
                    "type": "group_invitation",
                    "group_id": str(stakeholder_group.id),
                    "group_name": stakeholder_group.name,
                    "company_name": stakeholder_group.client.company_name,
                    "requires_email": True,
                    "token": str(token)
                }
                
                return Response(response_data, status=status.HTTP_200_OK)
            
            except StakeholderGroup.DoesNotExist:
                return Response(
                    {"error": "Invalid or expired invitation token"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            except Exception as e:
                # Log the error for debugging
                import logging
                logger = logging.getLogger(__name__)
                logger.exception("Unexpected error while validating invitation token")
                
                return Response(
                    {"error": "An unexpected error occurred. Please try again later."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
import uuid
def _unique_invitation_token():
    """Generate a unique token if invitation_token is unique=True."""
    from core_apps.authentication.models import StakeholderInvitation
    while True:
        tok = uuid.uuid4()
        if not StakeholderInvitation.objects.filter(invitation_token=tok).exists():
            return tok
        
from django.db import transaction, IntegrityError
class SubmitEmailView(APIView):
    """Handle email submission for invitation"""
    authentication_classes = []
    permission_classes = [AllowAny]
    
    # def post(self, request):
    #     serializer = EmailSubmissionSerializer(data=request.data)
    #     if serializer.is_valid():
    #         email = serializer.validated_data['email']
    #         stakeholder_group = serializer.validated_data['stakeholder_group']
    #         existing_stakeholder = serializer.validated_data['existing_stakeholder']
            
    #         if existing_stakeholder:
    #             if existing_stakeholder.is_registered:
    #                 # Stakeholder exists and is registered - auto login
    #                 if existing_stakeholder.user:
    #                     # Update last login
    #                     existing_stakeholder.last_login = timezone.now()
    #                     existing_stakeholder.save()
                        
    #                     return Response({
    #                         "action": "auto_login",
    #                         "message": "Welcome back! You have been logged in automatically.",
    #                         "stakeholder_id": str(existing_stakeholder.id),
    #                         "redirect_url": "/stakeholder/dashboard/"
    #                     }, status=status.HTTP_200_OK)
    #             else:
    #                 # Stakeholder exists but not registered - redirect to registration
    #                 return Response({
    #                     "action": "complete_registration",
    #                     "message": "Please complete your registration.",
    #                     "email": email,
    #                     "token": str(serializer.validated_data['token']),
    #                     "redirect_url": "/stakeholder/register/"
    #                 }, status=status.HTTP_200_OK)
    #         else:
    #             # New stakeholder - create and redirect to registration
    #             stakeholder = Stakeholder.objects.create(
    #                 email=email,
    #                 group=stakeholder_group,
    #                 is_registered=False,
    #                 status='pending'
    #             )
                
    #             # Create or update stakeholder invitation
    #             invitation, created = StakeholderInvitation.objects.get_or_create(
    #                 email=email,
    #                 stakeholder_group=stakeholder_group,
    #                 defaults={
    #                     'invitation_token': serializer.validated_data['token'],
    #                     'status': 'clicked',
    #                     'clicked_at': timezone.now(),
    #                     'expires_at': timezone.now() + timezone.timedelta(days=7),
    #                     'sent_by': stakeholder_group.created_by,
    #                     'stakeholder': stakeholder
    #                 }
    #             )
                
    #             if not created:
    #                 invitation.status = 'clicked'
    #                 invitation.clicked_at = timezone.now()
    #                 invitation.stakeholder = stakeholder
    #                 invitation.save()
                
    #             return Response({
    #                 "action": "register",
    #                 "message": "Please complete your registration.",
    #                 "email": email,
    #                 # "token": str(serializer.validated_data['token']),
    #                 "token" : str(stakeholder.id),
    #                 "redirect_url": "/stakeholder/register/"
    #             }, status=status.HTTP_201_CREATED)
        
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def post(self, request, *args, **kwargs):
        try:
            serializer = EmailSubmissionSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            email = serializer.validated_data["email"]
            group = serializer.validated_data["stakeholder_group"]
            existing_stakeholder = serializer.validated_data["existing_stakeholder"]
            existing_invitation = serializer.validated_data["existing_invitation"]

            # 1) Stakeholder already exists in this group
            if existing_stakeholder:
                if existing_stakeholder.is_registered and existing_stakeholder.user:
                    existing_stakeholder.last_login = timezone.now()
                    existing_stakeholder.save(update_fields=["last_login"])
                    return Response(
                        {
                            "action": "auto_login",
                            "message": "Welcome back! You have been logged in automatically.",
                            "stakeholder_id": str(existing_stakeholder.id),
                            "redirect_url": "/stakeholder/dashboard/",
                        },
                        status=status.HTTP_200_OK,
                    )
                # not registered yet → complete registration
                return Response(
                    {
                        "action": "complete_registration",
                        "message": "Please complete your registration.",
                        "email": email,
                        "token": str(existing_stakeholder.id),  # you use stakeholder.id at /register
                        "redirect_url": "/stakeholder/register/",
                    },
                    status=status.HTTP_200_OK,
                )

            # 2) Invitation already exists in this group for this email
            if existing_invitation:
                with transaction.atomic():
                    # ensure invitation is linked to a stakeholder
                    if not existing_invitation.stakeholder:
                        st, _ = Stakeholder.objects.get_or_create(
                            email=email,
                            group=group,
                            defaults={"is_registered": False, "status": "pending"},
                        )
                        existing_invitation.stakeholder = st
                    # mark clicked
                    existing_invitation.status = "clicked"
                    existing_invitation.clicked_at = timezone.now()
                    existing_invitation.save(update_fields=["stakeholder", "status", "clicked_at"])

                st = existing_invitation.stakeholder
                if st and st.is_registered and st.user:
                    st.last_login = timezone.now()
                    st.save(update_fields=["last_login"])
                    return Response(
                        {
                            "action": "auto_login",
                            "message": "Welcome back! You have been logged in automatically.",
                            "stakeholder_id": str(st.id),
                            "redirect_url": "/stakeholder/dashboard/",
                        },
                        status=status.HTTP_200_OK,
                    )
                return Response(
                    {
                        "action": "complete_registration",
                        "message": "Please complete your registration.",
                        "email": email,
                        "token": str(st.id) if st else "",
                        "redirect_url": "/stakeholder/register/",
                    },
                    status=status.HTTP_200_OK,
                )

            # 3) Nothing exists → create Stakeholder + Invitation
            with transaction.atomic():
                stakeholder, _ = Stakeholder.objects.get_or_create(
                    email=email,
                    group=group,
                    defaults={"is_registered": False, "status": "pending"},
                )

                # Create/update invitation (idempotent)
                StakeholderInvitation.objects.update_or_create(
                    email=email,
                    stakeholder_group=group,
                    defaults={
                        "invitation_token": uuid.uuid4(),  # your model has unique=True
                        "status": "clicked",
                        "clicked_at": timezone.now(),
                        "expires_at": timezone.now() + timezone.timedelta(days=7),
                        "sent_by": group.created_by,
                        "stakeholder": stakeholder,
                    },
                )

            return Response(
                {
                    "action": "register",
                    "message": "Please complete your registration.",
                    "email": email,
                    "token": str(stakeholder.id),  # used by your /register flow
                    "redirect_url": "/stakeholder/register/",
                },
                status=status.HTTP_201_CREATED,
            )

        except ValidationError as exc:
            return Response(exc.detail, status=status.HTTP_400_BAD_REQUEST)
        except IntegrityError as ie:
            logger.exception("IntegrityError in EmailSubmitView for %s", request.data.get("email"))
            return Response({"detail": "Integrity error", "db_error": str(ie)}, status=status.HTTP_409_CONFLICT)
        except Exception:
            logger.exception("Unhandled error in EmailSubmitView")
            return Response({"detail": "Unexpected server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# class StakeholderRegistrationView(APIView):
#     """Handle stakeholder registration"""
#     authentication_classes = []
#     permission_classes = [AllowAny]
    
#     def post(self, request):
#         serializer = StakeholderRegistrationSerializer(data=request.data)
#         if serializer.is_valid():
#             stakeholder = serializer.save()
            
#             return Response({
#                 "message": "Registration completed successfully. Please wait for admin approval.",
#                 "stakeholder_id": str(stakeholder.id),
#                 "status": "pending_approval",
#                 "redirect_url": "/stakeholder/pending/"
#             }, status=status.HTTP_201_CREATED)
        
#         print(f"serializer.errors - {serializer.errors}")
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class StakeholderRegistrationView(APIView):
    """Handle stakeholder registration via invitation link."""
    authentication_classes = []
    permission_classes = [AllowAny]
    print(f"---- hit ---")
    def post(self, request):
        serializer = StakeholderRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            stakeholder = serializer.save()
            return Response({
                "message": "Registration completed successfully. Please wait for admin approval.",
                "stakeholder_id": str(stakeholder.id),
                "status": "pending_approval",
                "redirect_url": "/stakeholder/pending/"
            }, status=status.HTTP_201_CREATED)
        print(f"request.data -> {request.data}")
        return Response({
            "errorssss": "Invalid input",
            "detailssss": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
# class StakeholderApprovalView(UpdateAPIView):
#     """Client admin approval of stakeholders"""
#     permission_classes = [IsAuthenticated]
#     queryset = Stakeholder.objects.all()
#     serializer_class = StakeholderApprovalSerializer
    
#     lookup_field = 'id'
    
#     def get_queryset(self):
#         # Filter stakeholders based on client admin's client
#         user = self.request.user
#         if hasattr(user, 'client') and user.client:
#             return Stakeholder.objects.filter(group__client=user.client)
#         return Stakeholder.objects.none()
    
#     def update(self, request, *args, **kwargs):
#         response = super().update(request, *args, **kwargs)
        
#         if response.status_code == status.HTTP_200_OK:
#             stakeholder = self.get_object()
#             action = request.data.get('status')
            
#             if action == 'approved':
#                 # You might want to send approval email here
#                 response.data.update({
#                     "message": f"Stakeholder {stakeholder.email} has been approved and can now access the system.",
#                     "user_created": True
#                 })
#             else:
#                 response.data.update({
#                     "message": f"Stakeholder {stakeholder.email} has been rejected."
#                 })
        
#         return response
# class StakeholderApprovalView(UpdateAPIView):
#     """Client admin approval of stakeholders"""
#     queryset = Stakeholder.objects.all()
#     serializer_class = StakeholderApprovalSerializer
#     permission_classes = [IsAuthenticated]
#     lookup_field = 'id'
    
#     def get_queryset(self):
#         # Filter stakeholders based on client admin's client
#         user = self.request.user
#         if hasattr(user, 'client') and user.client:
#             return Stakeholder.objects.filter(group__client=user.client)
#         return Stakeholder.objects.none()
    
#     def update(self, request, *args, **kwargs):
#         response = super().update(request, *args, **kwargs)
        
#         if response.status_code == status.HTTP_200_OK:
#             stakeholder = self.get_object()
#             action = request.data.get('status')
            
#             if action == 'approved':
#                 # Count ESG responses created
#                 esg_count = 0
#                 if stakeholder.user:
#                     esg_count = stakeholder.user.user_esg_responses.count()
                
#                 response.data.update({
#                     "message": f"Stakeholder {stakeholder.email} has been approved and can now access the system.",
#                     "user_created": True,
#                     "esg_responses_created": esg_count
#                 })
#             else:
#                 response.data.update({
#                     "message": f"Stakeholder {stakeholder.email} has been rejected."
#                 })
        
#         return response
from django.utils.crypto import get_random_string
from core_apps.esg.models import ESGQuestion, ESGQuestionResponse, ESGYear
class StakeholderApprovalView(APIView):
    """Handle approval of a pending stakeholder."""
    
    
    permission_classes = [IsAuthenticated]

    def create_esg_responses_for_user(self, user):
        """
        Create ESGQuestionResponse records for a client admin user
        """
        # Get current ESG year
        current_year = ESGYear.get_current_year()
        
        if not current_year:
            logger.warning("No current ESG year found, skipping ESG response creation")
            return
        
        # Get all active ESG questions for the current year
        active_questions = ESGQuestion.objects.filter(
            year=current_year,
            is_active=True
        ).select_related('category')
        
        if not active_questions.exists():
            logger.warning(f"No active ESG questions found for year {current_year.year}")
            return
        
        # Create ESGQuestionResponse records
        responses_to_create = []
        for question in active_questions:
            response = ESGQuestionResponse(
                question=question,
                user=user,
                questionnaire_type='stakeholder',
                status='draft'
            )
            responses_to_create.append(response)
        
        # Bulk create for better performance
        created_responses = ESGQuestionResponse.objects.bulk_create(
            responses_to_create, 
            ignore_conflicts=True
        )
        print(f"Created {len(responses_to_create)} ESG question responses for {user.email}")
        logger.info(f"Created {len(responses_to_create)} ESG question responses for {user.email}")
        return created_responses
    
    def post(self, request, stakeholder_id):
        # try:
        #     # Fetch the stakeholder by ID
        #     stakeholder = Stakeholder.objects.get(id=stakeholder_id)
            
        #     # Ensure the stakeholder is in 'pending' status
        #     if stakeholder.status != 'pending':
        #         return Response(
        #             {"detail": "Stakeholder is not in pending status."},
        #             status=status.HTTP_400_BAD_REQUEST
        #         )
            
        #     # Update the stakeholder status to 'approved'
        #     stakeholder.status = 'approved'
        #     stakeholder.save(update_fields=["status"])

        #     auto_pwd  = get_random_string(32)
        #     try:
        #         user_obj   = User.objects.create_user(
        #             # username=auto_user,
        #             email=stakeholder.email,
        #             first_name=stakeholder.first_name,
        #             last_name=stakeholder.last_name,
        #             password=auto_pwd,
        #             role="stakeholder",
        #             client=stakeholder.group.client,
        #             is_active=True,
        #         )
        #         stakeholder.user = user_obj
        #         stakeholder.save()
        #         self.create_esg_responses_for_user(user_obj)
        #     except Exception as e:
        #         logger.error(f"Failed to create ESG responses for {user_obj.email}: {e}")
        #     return Response(
        #         {
        #             "message": f"Stakeholder {stakeholder.email} has been approved successfully.",
        #             "stakeholder_id": str(stakeholder.id),
        #         },
        #         status=status.HTTP_200_OK
        #     )
        
        # except Stakeholder.DoesNotExist:
        #     return Response(
        #         {"detail": "Stakeholder not found."},
        #         status=status.HTTP_404_NOT_FOUND
        #     )
        # except Exception as e:
        #     return Response(
        #         {"detail": f"An error occurred: {str(e)}"},
        #         status=status.HTTP_500_INTERNAL_SERVER_ERROR
        #     )
        try:
            # Fetch the stakeholder by ID
            stakeholder = Stakeholder.objects.get(id=stakeholder_id)
            
            # Ensure the stakeholder is in 'pending' status
            if stakeholder.status != 'pending':
                return Response(
                    {"detail": "Stakeholder is not in pending status."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Update the stakeholder status to 'approved'
            stakeholder.status = 'approved'
            stakeholder.save(update_fields=["status"])

            auto_pwd = get_random_string(32)  # Generate a random password

            try:
                # Create the user associated with the stakeholder
                
                user_obj = UserData.objects.create_user(
                    email=stakeholder.email,
                    first_name=stakeholder.first_name,
                    last_name=stakeholder.last_name,
                    password=auto_pwd,
                    role="stakeholder",   
                    client=stakeholder.group.client,
                    is_active=True,
                )

                # After user creation, associate the user with the stakeholder
                stakeholder.user = user_obj
                stakeholder.save()

                # Optionally, create ESG responses for the user (if necessary)
                self.create_esg_responses_for_user(user_obj)

                # Return success response
                return Response(
                    {
                        "message": f"Stakeholder {stakeholder.email} has been approved successfully.",
                        "stakeholder_id": str(stakeholder.id),
                    },
                    status=status.HTTP_200_OK
                )
            except Exception as e:
                # Log error details for user creation or other issues
                logger.error(f"Error creating user for stakeholder {stakeholder.email}: {e}")

                # Rollback the status change if user creation fails
                stakeholder.status = 'pending'  # Revert the status back to 'pending'
                stakeholder.save(update_fields=["status"])

                return Response(
                    {"detail": f"An error occurred while creating the user: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except Stakeholder.DoesNotExist:
            return Response(
                {"detail": "Stakeholder not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return Response(
                {"detail": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
class PendingStakeholdersView(ListAPIView):
    """List pending stakeholders for client admin approval"""
    serializer_class = UpdatedStakeholderSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'client') and user.client:
            return Stakeholder.objects.filter(
                group__client=user.client,
                status='pending',
                is_registered=False
            ).order_by('-created_at')
        return Stakeholder.objects.none()


class StakeholderDetailView(APIView):
    """Get stakeholder details"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, stakeholder_id):
        try:
            stakeholder = Stakeholder.objects.get(id=stakeholder_id)
            
            # Check if user has permission to view this stakeholder
            if hasattr(request.user, 'client') and request.user.client:
                if stakeholder.group.client != request.user.client:
                    return Response(
                        {"error": "Permission denied"}, 
                        status=status.HTTP_403_FORBIDDEN
                    )
            
            serializer = UpdatedStakeholderSerializer(stakeholder)
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except Stakeholder.DoesNotExist:
            return Response(
                {"error": "Stakeholder not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )


class StakeholderLoginStatusView(APIView):
    """Update stakeholder login status"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        if hasattr(request.user, 'stakeholder'):
            stakeholder = request.user.stakeholder
            stakeholder.last_login = timezone.now()
            stakeholder.save()
            
            return Response({
                "message": "Login status updated",
                "last_login": stakeholder.last_login
            }, status=status.HTTP_200_OK)
        
        return Response(
            {"error": "User is not associated with a stakeholder"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    

from core_apps.authentication.models import StakeholderInvitation
@method_decorator(never_cache, name='dispatch')
class StakeholderRequestLoginView(APIView):
    """Handle login link requests for existing stakeholders"""
    
    permission_classes = [permissions.AllowAny]
    throttle_classes = [AnonRateThrottle]
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def post(self, request):
        """Send login link to registered client admin"""
        try:
            # Get email from request
            email = request.data.get('email', '').lower().strip()
            
            logger.info(f"Login request received for email: {email}")
            
            if not email:
                return Response({
                    "error": "Email is required"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Basic email validation
            if '@' not in email:
                return Response({
                    "error": "Please enter a valid email address"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if client invitation exists for this email
            try:
                invitation = StakeholderInvitation.objects.get(
                    email=email,
               
                )
                 
                
                client = invitation.client
                
                # Check registration and acceptance status
                invitation_status = invitation.status
                is_accepted = invitation.is_accepted
                
                # Check registration and acceptance status
                if invitation_status != 'completed':
                    if is_accepted:
                        logger.info(f"Email verification required for {email}")
                        return Response({
                            "error": "Please verify your email first. Click the invitation link sent to your email to complete registration.",
                            "status": "email_verification_required"
                        }, status=status.HTTP_400_BAD_REQUEST)
                    else:
                        logger.info(f"Invitation pending for {email}")
                        return Response({
                            "error": "Please check your email for the invitation link or contact your administrator if you haven't received it.",
                            "status": "invitation_pending"
                        }, status=status.HTTP_400_BAD_REQUEST)
                
                elif not is_accepted:
                    logger.info(f"Acceptance pending for {email}")
                    return Response({
                        "error": "Please check your email for the invitation link and accept it to complete your account setup.",
                        "status": "acceptance_pending"
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # User is both email_verified and is_accepted - proceed with login
                elif email_verified and is_accepted:
                    logger.info(f"Proceeding with login for {email}")
                    
                    # Check if user account exists
                    try:
                        user = User.objects.get(email=email, is_active=True)
                        logger.info(f"User account found for {email}")
                    except User.DoesNotExist:
                        logger.error(f"User account not found for {email}")
                        return Response({
                            "error": "User account not found. Please contact your administrator.",
                            "status": "user_not_found"
                        }, status=status.HTTP_404_NOT_FOUND)
                    
                    # Invalidate any existing unused tokens for this user (optional security measure)
                    ClientAdminLoginToken.objects.filter(
                        user=user,
                        is_used=False
                    ).update(is_used=True, used_at=timezone.now())
                    
                    # Create new login token
                    login_token_obj = ClientAdminLoginToken.objects.create(
                        user=user,
                        client_invitation=invitation,
                        ip_address=self.get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]  # Limit length
                    )
                    
                    login_url = login_token_obj.get_login_url()
                    logger.info(f"Generated login token for {email}: {login_token_obj.token}")
                    
                    # Get user's name for email
                    user_name = user.first_name or client.contact_person_first_name
                    
                    # Generate login email
                    subject = f"Login Link - {client.company_name}"
                    message = generate_login_email(user_name, login_url)
                    
                    # Send email
                    try:
                        send_mail(
                            subject=subject,
                            message=message,
                            from_email=settings.DEFAULT_FROM_EMAIL,
                            recipient_list=[email],
                            fail_silently=False,
                        )
                        
                        logger.info(f"Login link sent successfully to {email}")
                        
                        return Response({
                            "message": "Login link has been sent to your email address. Please check your email and click the link to access your account. The link will expire in 1 hour.",
                            "success": True,
                            "status": "login_link_sent"
                        }, status=status.HTTP_200_OK)
                        
                    except Exception as e:
                        logger.error(f"Failed to send login email to {email}: {e}")
                        # Mark token as used since email failed
                        login_token_obj.mark_as_used()
                        return Response({
                            "error": "Failed to send email. Please try again later.",
                            "status": "email_send_failed"
                        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
                else:
                    logger.error(f"Unexpected state for {email}: verified={email_verified}, accepted={is_accepted}")
                    return Response({
                        "error": "Account status unclear. Please contact your administrator.",
                        "status": "status_unclear"
                    }, status=status.HTTP_400_BAD_REQUEST)
                
            except ClientInvitation.DoesNotExist:
                logger.warning(f"No invitation found for {email}")
                return Response({
                    "error": "No invitation found for this email address. Please contact your administrator.",
                    "status": "invitation_not_found"
                }, status=status.HTTP_404_NOT_FOUND)
            except Exception as invitation_error:
                logger.error(f"Error finding invitation for {email}: {invitation_error}")
                print(f"invitation_error => {invitation_error}")
                return Response({
                    "error": "Error processing your request. Please try again later. yow?",
                    "status": "invitation_error"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as e:
            logger.error(f"Unexpected error in request login for {request.data.get('email', 'unknown')}: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return Response({
                "error": "An unexpected error occurred while processing your request. Please try again later.",
                "status": "server_error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


"""
AUTHENTICATION FOR STAKEHOLDER
"""
def generate_stakeholder_login_email(stakeholder_name, login_url, group_name):
    """Generate email content for stakeholder login"""
    return f"""
Hello {stakeholder_name},

You've requested a login link for your stakeholder account in {group_name}.

Click the link below to access your account:
{login_url}

This link will expire in 1 hour for security purposes.

If you didn't request this login link, please ignore this email.

Best regards,
Terramo Team
    """.strip()

from .models import StakeholderLoginToken

@method_decorator(never_cache, name='dispatch')
class StakeholderLoginRequestView(APIView):
    """Handle login link requests for stakeholders"""
    authentication_classes = []
    permission_classes = [permissions.AllowAny]
    throttle_classes = [AnonRateThrottle]
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def post(self, request):
        """Send login link to registered stakeholder"""
        try:
            # Get email from request
            email = request.data.get('email', '').lower().strip()
            
            logger.info(f"Stakeholder login request received for email: {email}")
            
            if not email:
                return Response({
                    "error": "Email is required"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Basic email validation
            if '@' not in email:
                return Response({
                    "error": "Please enter a valid email address"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if stakeholder exists
            try:
                stakeholder = Stakeholder.objects.select_related('group').get(
                    email=email,
                    status='approved',  # Only approved stakeholders can login
                    is_registered=True  # Only registered stakeholders can login
                )
                
                logger.info(f"Found stakeholder for {email}: group={stakeholder.group.name}")
                
                # Check if stakeholder has a User account (if using User model)
                if stakeholder.user and not stakeholder.user.is_active:
                    logger.warning(f"User account inactive for {email}")
                    return Response({
                        "error": "Your account is inactive. Please contact your administrator.",
                        "status": "account_inactive"
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Invalidate any existing unused tokens for this stakeholder
                StakeholderLoginToken.objects.filter(
                    stakeholder=stakeholder,
                    is_used=False
                ).update(is_used=True, used_at=timezone.now())
                
                # Get the latest invitation for this stakeholder (optional)
                stakeholder_invitation = None
                try:
                    stakeholder_invitation = StakeholderInvitation.objects.filter(
                        email=email,
                        stakeholder_group=stakeholder.group
                    ).order_by('-sent_at').first()
                except StakeholderInvitation.DoesNotExist:
                    pass
                
                # Create new login token
                login_token_obj = StakeholderLoginToken.objects.create(
                    stakeholder=stakeholder,
                    stakeholder_invitation=stakeholder_invitation,
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
                )
                
                login_url = login_token_obj.get_login_url()
                logger.info(f"Generated login token for {email}: {login_token_obj.token}")
                
                # Get stakeholder's name for email
                stakeholder_name = stakeholder.first_name or stakeholder.email.split('@')[0]
                group_name = stakeholder.group.name
                
                # Generate login email
                subject = f"Login Link - {group_name}"
                message = generate_stakeholder_login_email(stakeholder_name, login_url, group_name)
                
                # Send email
                try:
                    send_mail(
                        subject=subject,
                        message=message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[email],
                        fail_silently=False,
                    )
                    
                    logger.info(f"Login link sent successfully to {email}")
                    
                    return Response({
                        "message": "Login link has been sent to your email address. Please check your email and click the link to access your account. The link will expire in 1 hour.",
                        "success": True,
                        "status": "login_link_sent"
                    }, status=status.HTTP_200_OK)
                    
                except Exception as e:
                    logger.error(f"Failed to send login email to {email}: {e}")
                    # Mark token as used since email failed
                    login_token_obj.mark_as_used()
                    return Response({
                        "error": "Failed to send email. Please try again later.",
                        "status": "email_send_failed"
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
            except Stakeholder.DoesNotExist:
                logger.warning(f"No approved/registered stakeholder found for {email}")
                return Response({
                    "error": "No registered stakeholder account found for this email address. Please contact your administrator or check if you need to complete your registration first.",
                    "status": "stakeholder_not_found"
                }, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            logger.error(f"Unexpected error in stakeholder login request for {request.data.get('email', 'unknown')}: {e}")
            print(f"last except - {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return Response({
                "error": "An unexpected error occurred while processing your request. Please try again later.",
                "status": "server_error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

"""
Verify the Stakeholder token
"""

@method_decorator(never_cache, name='dispatch')
class StakeholderUserTokenLoginView(APIView):
    """Handle stakeholder login via token"""
    authentication_classes = []
    permission_classes = [permissions.AllowAny]
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def post(self, request, token):
        """Verify token and log in stakeholder"""
        try:
            logger.info(f"Token login attempt: {token}")
            
            # Get the token
            login_token = StakeholderLoginToken.get_valid_token(token)
            
            if not login_token:
                logger.warning(f"Invalid or expired token: {token}")
                return Response({
                    "error": "Invalid or expired login link. Please request a new login link.",
                    "status": "invalid_token"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            stakeholder = login_token.stakeholder
            
            # Check if stakeholder is still active and approved
            if stakeholder.status != 'approved' or not stakeholder.is_registered:
                logger.warning(f"Stakeholder status invalid: {stakeholder.email}")
                login_token.mark_as_used()
                return Response({
                    "error": "Your account status has changed. Please contact your administrator.",
                    "status": "account_status_changed"
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Mark token as used
            login_token.mark_as_used(
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
            )
            
            # Update last login
            stakeholder.last_login = timezone.now()
            stakeholder.save(update_fields=['last_login'])
            
            logger.info(f"Successful token login for: {stakeholder.email}")
            
            # If you're using JWT tokens, generate one here
            # from rest_framework_simplejwt.tokens import RefreshToken
            # refresh = RefreshToken()
            # refresh['stakeholder_id'] = str(stakeholder.id)
            # refresh['email'] = stakeholder.email
            # refresh['group_id'] = str(stakeholder.group.id)
            user_info = UserData.objects.get(email=stakeholder.email, is_active=True)
            refresh = RefreshToken.for_user(user_info)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            response_data = {
                'message': 'Login successful',
                'message_stat': 'login_successful',
                'access': access_token,
                'refresh': refresh_token,
                "user": {
                    "id": str(stakeholder.id),
                    "email": stakeholder.email,
                    "role": "stakeholder",
                    "first_name": stakeholder.first_name,
                    "last_name": stakeholder.last_name,
                    "group_name": stakeholder.group.name,
                    "group_id": str(stakeholder.group.id),
                },
              
            }
            response = Response(response_data, status=status.HTTP_200_OK)
                
            # Set authentication cookies (if you have this function)
            try:
                set_auth_cookies(response, access_token, refresh_token)
            except NameError:
                # If set_auth_cookies function doesn't exist, skip it
                print(f"NameError - {NameError}")
                pass
            
            logger.info(f"User {stakeholder.email} logged in successfully via token")
            
            return response
            # return Response({
            #     "message": "Login successful",
            #     "success": True,
            #     "status": "login_successful",
            #     "stakeholder": {
            #         "id": str(stakeholder.id),
            #         "email": stakeholder.email,
            #         "first_name": stakeholder.first_name,
            #         "last_name": stakeholder.last_name,
            #         "group_name": stakeholder.group.name,
            #         "group_id": str(stakeholder.group.id),
            #     }
            #     # Add JWT tokens here if using them:
            #     # "access": str(refresh.access_token),
            #     # "refresh": str(refresh),
            # }, status=status.HTTP_200_OK)


            """
            user_info = User.objects.get(email=user.email, is_active=True)

            print(f"generating----tokens")
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user_info)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            
            # Update last login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            print(f'user email = {user.email}')
            logger.info(f"Successful token login for user: {user_info.email}")
            
            # Prepare response data
            response_data = {
                'message': 'Login successful',
                'message_stat': 'login_successful',
                'access': access_token,
                'refresh': refresh_token,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'first_name': getattr(user, 'first_name', ''),
                    'last_name': getattr(user, 'last_name', ''),
                    'is_active': user.is_active,
                    'last_login': user.last_login.isoformat() if user.last_login else None,
                },
                'client': {
                    'id': invitation.client.id,
                    'company_name': invitation.client.company_name,
                    'email': invitation.client.email,
                }
            }
            
            # return Response(response_data, status=status.HTTP_200_OK)
            response = Response(response_data, status=status.HTTP_200_OK)
                
            # Set authentication cookies (if you have this function)
            try:
                set_auth_cookies(response, access_token, refresh_token)
            except NameError:
                # If set_auth_cookies function doesn't exist, skip it
                print(f"NameError - {NameError}")
                pass
            
            logger.info(f"User {user.email} logged in successfully via token")
            
            return response
            """
            
        except Exception as e:
            logger.error(f"Unexpected error in token login for token {token}: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return Response({
                "error": "An unexpected error occurred during login. Please try again.",
                "status": "server_error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


# ------------------ updated views -------------------------
from core_apps.user_auth.permissions import IsClientAdminOrTerramoAdmin
from .serializers import UpdatedStakeholderGroupSerializer, UpdatedStakeholderSerializer

class CreateStakeholderView(generics.CreateAPIView):
    """Create a single stakeholder"""
    serializer_class = CreateStakeholderSerializer
    permission_classes = [IsAuthenticated, IsClientAdminOrTerramoAdmin]
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['group_id'] = self.kwargs.get('group_id')
        return context
    
    def perform_create(self, serializer):
        group_id = self.kwargs.get('group_id')
        group = get_object_or_404(StakeholderGroup, id=group_id)
        
        # Verify user has access to this group
        if self.request.user.role != 'terramo_admin' and group.client != self.request.user.client:
            raise PermissionError("You don't have permission to create stakeholders in this group.")
        

        # -------------- login token start --------------
        
            
        stakeholder = serializer.save()
        
        # Send email notification if invitation was created
        if serializer.validated_data.get('send_invitation', True):
            self.send_stakeholder_creation_email(stakeholder)


    
    def send_stakeholder_creation_email(self, stakeholder):
        """Send email to newly created stakeholder"""
        invitation = StakeholderInvitation.objects.filter(
            email=stakeholder.email,
            stakeholder_group=stakeholder.group
        ).first()
        
        if invitation:
            invitation_url = invitation.get_invitation_url()
            subject = f"Invitation to join {stakeholder.group.client.company_name}"
            message = f"""
            Hi {stakeholder.first_name or 'there'},
            
            You have been invited to join the stakeholder group '{stakeholder.group.name}' 
            for {stakeholder.group.client.company_name}.
            
            Click the link below to complete your registration:
            {invitation_url}
            
            This invitation will expire in 7 days.
            
            Best regards,
            {stakeholder.group.client.company_name} Team
            """
            
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [stakeholder.email],
                fail_silently=False,
            )

class RemoveStakeholderView(generics.DestroyAPIView):
    """Remove a stakeholder from the system"""
    permission_classes = [IsAuthenticated, IsClientAdminOrTerramoAdmin]
    
    def get_object(self):
        stakeholder_id = self.kwargs.get('stakeholder_id')
        stakeholder = get_object_or_404(Stakeholder, id=stakeholder_id)
        
        # Verify user has access to this stakeholder
        if (self.request.user.role != 'terramo_admin' and 
            stakeholder.group.client != self.request.user.client):
            raise PermissionError("You don't have permission to remove this stakeholder.")
        
        return stakeholder
    
    def destroy(self, request, *args, **kwargs):
        stakeholder = self.get_object()
        
        with transaction.atomic():
            # Also remove associated user if they exist and only belong to this stakeholder
            if stakeholder.user and hasattr(stakeholder.user, 'usr_stakeholder'):
                user = stakeholder.user
                # Only delete user if they're only associated with this stakeholder
                if Stakeholder.objects.filter(user=user).count() == 1:
                    user.delete()
            
            stakeholder.delete()
        
        return Response(status=status.HTTP_204_NO_CONTENT)



class StakeholderGroupListView(generics.ListAPIView):
    """List stakeholder groups for the current user's client"""
    serializer_class = UpdatedStakeholderGroupSerializer
    permission_classes = [IsAuthenticated, IsClientAdminOrTerramoAdmin]
    
    def get_queryset(self):
        if self.request.user.role == 'terramo_admin':
            return StakeholderGroup.objects.all().order_by('name')
        else:
            return StakeholderGroup.objects.filter(
                client=self.request.user.client,
                is_active=True
            ).order_by('name')



class StakeholderListView(generics.ListAPIView):
    """List stakeholders in a group - Client Admin only"""
    serializer_class = StakeholderSerializer
    permission_classes = [IsAuthenticated, IsClientAdminOrTerramoAdmin]
    
    def get_queryset(self):
        group_id = self.kwargs['group_id']
        group = get_object_or_404(
            StakeholderGroup,
            id=group_id,
            client=self.request.user.client
        )
        return Stakeholder.objects.filter(group=group).order_by('-created_at')


class UpdatedStakeholderListView(generics.ListAPIView):
    """List stakeholders for a specific group"""
    serializer_class = StakeholderSerializer
    permission_classes = [IsAuthenticated, IsClientAdminOrTerramoAdmin]
    
    def get_queryset(self):
        group_id = self.kwargs.get('group_id')
        group = get_object_or_404(StakeholderGroup, id=group_id)
        
        # Verify user has access to this group
        if (self.request.user.role != 'terramo_admin' and 
            group.client != self.request.user.client):
            return Stakeholder.objects.none()
        
        return Stakeholder.objects.filter(group=group, status='approved').select_related('group', 'user').order_by('created_at')