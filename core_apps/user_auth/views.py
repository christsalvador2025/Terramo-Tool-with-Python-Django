# from typing import Any, Optional
# from django.conf import settings
# from django.contrib.auth import get_user_model
# from django.utils import timezone
# from djoser.views import TokenCreateView
# from djoser.views import User
# from loguru import logger
# from rest_framework import permissions, status
# from rest_framework.response import Response
# from rest_framework.request import Request
# from rest_framework.views import APIView
# from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework_simplejwt.views import TokenRefreshView

# from .emails import send_otp_email
# from .utils import generate_otp

# User = get_user_model()


# def set_auth_cookies(
#     response: Response, access_token: str, refresh_token: Optional[str] = None
# ) -> None:
#     access_token_lifetime = settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds()
#     cookie_settings = {
#         "path": settings.COOKIE_PATH,
#         "secure": settings.COOKIE_SECURE,
#         "httponly": settings.COOKIE_HTTPONLY,
#         "samesite": settings.COOKIE_SAMESITE,
#         "max_age": access_token_lifetime,
#     }
#     response.set_cookie("access", access_token, **cookie_settings)

#     if refresh_token:
#         refresh_token_lifetime = settings.SIMPLE_JWT[
#             "REFRESH_TOKEN_LIFETIME"
#         ].total_seconds()
#         refresh_cookie_settings = cookie_settings.copy()
#         refresh_cookie_settings["max_age"] = refresh_token_lifetime
#         response.set_cookie("refresh", refresh_token, **refresh_cookie_settings)

#     logged_in_cookie_settings = cookie_settings.copy()
#     logged_in_cookie_settings["httponly"] = False
#     response.set_cookie("logged_in", "true", **logged_in_cookie_settings)


# class CustomTokenCreateView(TokenCreateView):
#     def _action(self, serializer):
#         user = serializer.user
#         if user.is_locked_out:
#             return Response(
#                 {
#                     "error": f"Account is locked due to multiple failed login attempts. Please "
#                     f"try again after {settings.LOCKOUT_DURATION.total_seconds() / 60} minutes. ",
#                 },
#                 status=status.HTTP_403_FORBIDDEN,
#             )
#         user.reset_failed_login_attempts()

#         otp = generate_otp()
#         user.set_otp(otp)
#         send_otp_email(user.email, otp)

#         logger.info(f"OTP sent for login to user: {user.email}")

#         return Response(
#             {
#                 "success": "OTP sent to your email",
#                 "email": user.email,
#             },
#             status=status.HTTP_200_OK,
#         )

#     def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
#         serializer = self.get_serializer(data=request.data)

#         try:
#             serializer.is_valid(raise_exception=True)
#         except Exception:
#             email = request.data.get("email")
#             user = User.objects.filter(email=email).first()
#             if user:
#                 user.handle_failed_login_attempts()
#                 failed_attempts = user.failed_login_attempts
#                 logger.error(
#                     f"Failed login attempts: {failed_attempts}  for user: {email}"
#                 )
#                 if failed_attempts >= settings.LOGIN_ATTEMPTS:
#                     return Response(
#                         {
#                             "error": f"You have exceeded the maximum number of login attempts. "
#                             f"Your account has been locked for "
#                             f"{settings.LOCKOUT_DURATION.total_seconds() / 60} minutes. "
#                             f"An email has been sent to you with further instructions",
#                         },
#                         status=status.HTTP_403_FORBIDDEN,
#                     )
#             else:
#                 logger.error(f"Failed login attempt for non-existent user: {email}")

#             return Response(
#                 {"error": "Your Login Credentials are not correct"},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
#         return self._action(serializer)


# class CustomTokenRefreshView(TokenRefreshView):
#     def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
#         refresh_token = request.COOKIES.get("refresh")

#         if refresh_token:
#             request.data["refresh"] = refresh_token

#         refresh_res = super().post(request, *args, **kwargs)

#         if refresh_res.status_code == status.HTTP_200_OK:
#             access_token = refresh_res.data.get("access")
#             refresh_token = refresh_res.data.get("refresh")

#             if access_token and refresh_token:
#                 set_auth_cookies(
#                     refresh_res,
#                     access_token=access_token,
#                     refresh_token=refresh_token,
#                 )

#                 refresh_res.data.pop("access", None)
#                 refresh_res.data.pop("refresh", None)

#                 refresh_res.data["message"] = "Access tokens refreshed successfully."

#             else:
#                 refresh_res.data["message"] = (
#                     "Access or refresh token not found in refresh response data"
#                 )
#                 logger.error(
#                     "Access or refresh token not found in refresh response data"
#                 )

#         return refresh_res


# class OTPVerifyView(APIView):
#     permission_classes = [permissions.AllowAny]

#     def post(self, request):
#         otp = request.data.get("otp")

#         if not otp:
#             return Response(
#                 {"error": "OTP is required"},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
#         user = User.objects.filter(otp=otp, otp_expiry_time__gt=timezone.now()).first()

#         if not user:
#             return Response(
#                 {"error": "Invalid or expired OTP"},
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

#         user.verify_otp(otp)

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


# class LogoutAPIView(APIView):
#     def post(self, request, *args, **kwargs):
#         response = Response(status=status.HTTP_204_NO_CONTENT)
#         response.delete_cookie("access")
#         response.delete_cookie("refresh")
#         response.delete_cookie("logged_in")
#         return response

"""
------------------------------------------------------------------------------------------------------------------------
    START : 
# from typing import Any, Optional
# from django.conf import settings
# from django.contrib.auth import get_user_model
# from django.utils import timezone
# from djoser.views import TokenCreateView
# from djoser.views import User
# from loguru import logger
# from rest_framework import permissions, status
# from rest_framework.response import Response
# from rest_framework.request import Request
# from rest_framework.views import APIView
# from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework_simplejwt.views import TokenRefreshView

# from .emails import send_otp_email
# from .utils import generate_otp
------------------------------------------------------------------------------------------------------------------------

"""
# ------------------------------------------------------------
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate, login
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.urls import reverse
from django.db import transaction
from rest_framework import status, generics, permissions, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta
import uuid
from loguru import logger

from core_apps.user_auth.models import User
from core_apps.clients.models import Client
from core_apps.stakeholder_analysis.models import StakeholderGroup, StakeholderInvitation
from .serializers import (
    ClientInvitationSerializer,
    ClientLoginSerializer,
    StakeholderLoginSerializer,
    StakeholderRegistrationSerializer,
    UserProfileSerializer,
    GenerateLoginLinkSerializer,
    StakeholderInvitationSerializer,
    BulkStakeholderInvitationSerializer,
    DashboardStatsSerializer,
    LoginSerializer,
    LogoutSerializer
)

# auth
from rest_framework.request import Request
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from typing import Optional, Any
from djoser.views import TokenCreateView
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework.permissions import AllowAny, IsAuthenticated
import hashlib
from django.core.cache import cache
def set_auth_cookies(
    response: Response, access_token: str, refresh_token: Optional[str] = None
) -> None:
    access_token_lifetime = settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds()
    cookie_settings = {
        "path": settings.COOKIE_PATH,
        "secure": settings.COOKIE_SECURE,
        "httponly": settings.COOKIE_HTTPONLY,
        "samesite": settings.COOKIE_SAMESITE,
        "max_age": access_token_lifetime,
    }
    response.set_cookie("access", access_token, **cookie_settings)

    if refresh_token:
        refresh_token_lifetime = settings.SIMPLE_JWT[
            "REFRESH_TOKEN_LIFETIME"
        ].total_seconds()
        refresh_cookie_settings = cookie_settings.copy()
        refresh_cookie_settings["max_age"] = refresh_token_lifetime
        response.set_cookie("refresh", refresh_token, **refresh_cookie_settings)

    logged_in_cookie_settings = cookie_settings.copy()
    logged_in_cookie_settings["httponly"] = False
    response.set_cookie("logged_in", "true", **logged_in_cookie_settings)

# Custom throttling classes
class LoginRateThrottle(AnonRateThrottle):
    scope = 'login'
    rate = '5/min'  # 5 login attempts per minute


class LogoutRateThrottle(UserRateThrottle):
    scope = 'logout'
    rate = '10/min'

class CustomTokenCreateView(TokenCreateView):
    """
    Custom token creation view that extends Djoser's TokenCreateView
    to include cookies and custom response format
    """
    throttle_classes = [LoginRateThrottle]
    
    def _action(self, serializer):
        # Get the user from the serializer
        user = serializer.user
        
        # Check if user account is active
        if not user.is_active:
            return Response(
                {'error': 'User account is disabled'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        
        # Log successful login
        logger.info(f"User {user.email} logged in successfully via Djoser")
        
        # Update last login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        # Create response
        response_data = {
            'access': access_token,
            'refresh': refresh_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': getattr(user, 'first_name', ''),
                'last_name': getattr(user, 'last_name', ''),
            }
        }
        
        response = Response(response_data, status=status.HTTP_200_OK)
        
        # Set cookies
        set_auth_cookies(response, access_token, refresh_token)
        
        return response


class CustomTokenRefreshView(TokenRefreshView):
    """
    Custom token refresh view that includes cookies and better error handling
    """
    throttle_classes = [UserRateThrottle]
    
    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)
            
            if response.status_code == 200:
                access_token = response.data.get('access')
                if access_token:
                    set_auth_cookies(response, access_token)
            
            return response
        except (TokenError, InvalidToken) as e:
            logger.warning(f"Token refresh failed: {e}")
            return Response(
                {'error': 'Invalid or expired refresh token'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )


class LoginView(APIView):
    """
    Secure login endpoint with rate limiting and validation
    """
    permission_classes = [AllowAny]
    throttle_classes = [LoginRateThrottle]
    serializer_class = LoginSerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid input', 'details': serializer.errors}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        # Check for brute force attempts
        if self._is_brute_force_attempt(email, request):
            return Response(
                {'error': 'Too many failed attempts. Please try again later.'}, 
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        
        # Authenticate user
        user = authenticate(request, username=email, password=password)
        
        if user is None:
            self._record_failed_attempt(email, request)
            logger.warning(f"Failed login attempt for email: {email}")
            return Response(
                {'error': 'Invalid credentials'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        if not user.is_active:
            return Response(
                {'error': 'User account is disabled'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Clear failed attempts on successful login
        self._clear_failed_attempts(email, request)
        
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
        
        # Set authentication cookies
        set_auth_cookies(response, access_token, refresh_token)
        
        logger.info(f"User {user.email} logged in successfully")
        
        return response
    
    def _get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def _get_cache_key(self, email, request):
        """Generate cache key for failed attempts"""
        ip = self._get_client_ip(request)
        return f"failed_login:{hashlib.md5(f'{email}:{ip}'.encode()).hexdigest()}"
    
    def _is_brute_force_attempt(self, email, request):
        """Check if this is a brute force attempt"""
        cache_key = self._get_cache_key(email, request)
        failed_attempts = cache.get(cache_key, 0)
        return failed_attempts >= getattr(settings, 'MAX_LOGIN_ATTEMPTS', 5)
    
    def _record_failed_attempt(self, email, request):
        """Record a failed login attempt"""
        cache_key = self._get_cache_key(email, request)
        failed_attempts = cache.get(cache_key, 0) + 1
        cache.set(cache_key, failed_attempts, 300)  # 5 minutes
    
    def _clear_failed_attempts(self, email, request):
        """Clear failed login attempts"""
        cache_key = self._get_cache_key(email, request)
        cache.delete(cache_key)


class LogoutView(APIView):
    """
    Secure logout endpoint that blacklists tokens and clears cookies
    """
    permission_classes = [AllowAny]  # Allow both authenticated and anonymous users
    throttle_classes = [LogoutRateThrottle]
    serializer_class = LogoutSerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid input', 'details': serializer.errors}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Try to get refresh token from request data or cookies
            refresh_token = (
                serializer.validated_data.get('refresh_token') or 
                request.COOKIES.get('refresh')
            )
            
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
                logger.info("Refresh token blacklisted successfully")
            
        except (TokenError, InvalidToken) as e:
            logger.warning(f"Error blacklisting token during logout: {e}")
            # Don't return error - logout should still succeed
        except Exception as e:
            logger.error(f"Unexpected error during logout: {e}")
        
        response = Response(
            {'message': 'Logout successful'}, 
            status=status.HTTP_200_OK
        )
        
        # Clear cookies
        response.delete_cookie('access', path=settings.COOKIE_PATH)
        response.delete_cookie('refresh', path=settings.COOKIE_PATH)
        response.delete_cookie('logged_in', path=settings.COOKIE_PATH)
        
        return response
    
class LogoutAPIView(APIView):
    def post(self, request, *args, **kwargs):
        response = Response(status=status.HTTP_204_NO_CONTENT)
        response.delete_cookie("access")
        response.delete_cookie("refresh")
        response.delete_cookie("logged_in")
        return response


# class CustomTokenCreateView(TokenCreateView):
    
#     def _action(self, serializer):
#         user = serializer.user
#         if user.is_locked_out:
#             return Response(
#                 {
#                     "error": f"Account is locked due to multiple failed login attempts. Please "
#                     f"try again after {settings.LOCKOUT_DURATION.total_seconds() / 60} minutes. ",
#                 },
#                 status=status.HTTP_403_FORBIDDEN,
#             )
#         user.reset_failed_login_attempts()

#         # otp = generate_otp()
#         # user.set_otp(otp)
#         # send_otp_email(user.email, otp)

#         # logger.info(f"OTP sent for login to user: {user.email}")

#         # return Response(
#         #     {
#         #         "success": "OTP sent to your email",
#         #         "email": user.email,
#         #     },
#         #     status=status.HTTP_200_OK,
#         # )

#     def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
#         serializer = self.get_serializer(data=request.data)

#         try:
#             serializer.is_valid(raise_exception=True)
        
#             print(f"serializer = {serializer}")
#             refresh = RefreshToken.for_user(user)
#             access_token = str(refresh.access_token)
#             refresh_token = str(refresh)

#             response = Response(
#                 {
#                     "success": "Login successful. Now add your profile information, "
#                     "so that we can create an account for you"
#                 },
#                 status=status.HTTP_200_OK,
#             )
#             set_auth_cookies(response, access_token, refresh_token)
#             logger.info(f"Successful login with OTP: {user.email}")
#             return response
#         except Exception:
#             email = request.data.get("email")
#             user = User.objects.filter(email=email).first()
#             if user:
#                 # user.handle_failed_login_attempts()
#                 failed_attempts = user.failed_login_attempts
#                 logger.error(
#                     f"Failed login attempts: {failed_attempts}  for user: {email}"
#                 )
#                 if failed_attempts >= settings.LOGIN_ATTEMPTS:
#                     return Response(
#                         {
#                             "error": f"You have exceeded the maximum number of login attempts. "
#                             f"Your account has been locked for "
#                             f"{settings.LOCKOUT_DURATION.total_seconds() / 60} minutes. "
#                             f"An email has been sent to you with further instructions",
#                         },
#                         status=status.HTTP_403_FORBIDDEN,
#                     )
#             else:
#                 logger.error(f"Failed login attempt for non-existent user: {email}")

#             return Response(
#                 {"error": "Your Login Credentials are not correct"},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
#         return self._action(serializer)


# class CustomTokenRefreshView(TokenRefreshView):
#     def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
#         refresh_token = request.COOKIES.get("refresh")

#         if refresh_token:
#             request.data["refresh"] = refresh_token

#         refresh_res = super().post(request, *args, **kwargs)

#         if refresh_res.status_code == status.HTTP_200_OK:
#             access_token = refresh_res.data.get("access")
#             refresh_token = refresh_res.data.get("refresh")

#             if access_token and refresh_token:
#                 set_auth_cookies(
#                     refresh_res,
#                     access_token=access_token,
#                     refresh_token=refresh_token,
#                 )

#                 refresh_res.data.pop("access", None)
#                 refresh_res.data.pop("refresh", None)

#                 refresh_res.data["message"] = "Access tokens refreshed successfully."

#             else:
#                 refresh_res.data["message"] = (
#                     "Access or refresh token not found in refresh response data"
#                 )
#                 logger.error(
#                     "Access or refresh token not found in refresh response data"
#                 )

#         return refresh_res


# class OTPVerifyView(APIView):
#     permission_classes = [permissions.AllowAny]

#     def post(self, request):
#         otp = request.data.get("otp")

#         if not otp:
#             return Response(
#                 {"error": "OTP is required"},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
#         user = User.objects.filter(otp=otp, otp_expiry_time__gt=timezone.now()).first()

#         if not user:
#             return Response(
#                 {"error": "Invalid or expired OTP"},
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

#         user.verify_otp(otp)

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





class ClientInvitationView(APIView):
    """
    Generate invitation link for Client Admin
    Only accessible by Terramo Admin (Super Admin)
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        if not request.user.role == User.UserRole.SUPER_ADMIN:
            return Response(
                {"error": "Only Super Admin can create client invitations"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = ClientInvitationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                with transaction.atomic():
                    client = serializer.save()
                    
                    # Generate invitation token
                    invitation_token = str(uuid.uuid4())
                    
                    # Set expiration (24 hours from now)
                    expires_at = timezone.now() + timedelta(hours=24)
                    
                    # Store invitation details in client model or create a separate invitation model
                    client.invitation_token = invitation_token
                    client.invitation_expires_at = expires_at
                    client.save()
                    
                    # Generate invitation link
                    invitation_link = f"{settings.DOMAIN}/auth/client-login/{invitation_token}/"
                    
                    # Send invitation email
                    self._send_invitation_email(client, invitation_link)
                    
                    return Response({
                        "message": "Client invitation created successfully",
                        "invitation_link": invitation_link,
                        "client_id": client.id,
                        "expires_at": expires_at
                    }, status=status.HTTP_201_CREATED)
                    
            except Exception as e:
                logger.error(f"Error creating client invitation: {str(e)}")
                return Response(
                    {"error": "Failed to create client invitation"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def _send_invitation_email(self, client, invitation_link):
        """Send invitation email to client admin"""
        try:
            subject = f"Invitation to Terramo Survey Platform - {client.company_name}"
            html_message = render_to_string('emails/client_invitation.html', {
                'client': client,
                'invitation_link': invitation_link,
                'expires_at': client.invitation_expires_at
            })
            
            send_mail(
                subject=subject,
                message=f"Click this link to access your dashboard: {invitation_link}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[client.email],
                html_message=html_message,
                fail_silently=False,
            )
            logger.info(f"Invitation email sent to {client.email}")
        except Exception as e:
            logger.error(f"Failed to send invitation email: {str(e)}")


class ClientLoginView(APIView):
    """
    Handle Client Admin login via invitation link
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, invitation_token):
        """Validate invitation token and redirect to login form"""
        try:
            client = get_object_or_404(
                Client,
                invitation_token=invitation_token,
                invitation_expires_at__gt=timezone.now()
            )
            
            return Response({
                "message": "Valid invitation token",
                "client_id": client.id,
                "company_name": client.company_name,
                "email": client.email
            }, status=status.HTTP_200_OK)
            
        except Client.DoesNotExist:
            return Response(
                {"error": "Invalid or expired invitation token"},
                status=status.HTTP_404_NOT_FOUND
            )
    
    def post(self, request, invitation_token):
        """Process Client Admin login"""
        try:
            client = get_object_or_404(
                Client,
                invitation_token=invitation_token,
                invitation_expires_at__gt=timezone.now()
            )
            
            serializer = ClientLoginSerializer(data=request.data)
            if serializer.is_valid():
                email = serializer.validated_data['email']
                
                # Validate email matches invitation
                if email != client.email:
                    return Response(
                        {"error": "Email does not match invitation"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Get or create user
                user, created = User.objects.get_or_create(
                    email=email,
                    defaults={
                        'username': email,
                        'first_name': client.contact_person_first_name or '',
                        'last_name': client.contact_person_last_name or '',
                        'role': User.UserRole.COMPANY_ADMIN,
                        'client': client,
                        'is_active': True
                    }
                )
                
                if not created:
                    # Update existing user
                    user.client = client
                    user.role = User.UserRole.COMPANY_ADMIN
                    user.is_active = True
                    user.save()
                
                # Create default stakeholder group if it doesn't exist
                stakeholder_group, _ = StakeholderGroup.objects.get_or_create(
                    client=client,
                    name='Management',
                    defaults={
                        'description': 'Default management stakeholder group',
                        'created_by': user,
                        'is_active': True
                    }
                )
                
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                
                return Response({
                    "message": "Login successful",
                    "user": UserProfileSerializer(user).data,
                    "access_token": str(refresh.access_token),
                    "refresh_token": str(refresh),
                    "redirect_url": "/dashboard/"
                }, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Client.DoesNotExist:
            return Response(
                {"error": "Invalid or expired invitation token"},
                status=status.HTTP_404_NOT_FOUND
            )


class GenerateLoginLinkView(APIView):
    """
    Generate new login link for returning Client Admin
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = GenerateLoginLinkSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                # Find user and client
                user = User.objects.get(email=email, role=User.UserRole.COMPANY_ADMIN)
                client = user.client
                
                # Generate new login token
                login_token = str(uuid.uuid4())
                expires_at = timezone.now() + timedelta(hours=24)
                
                # Update client with new token
                client.login_token = login_token
                client.login_expires_at = expires_at
                client.save()
                
                # Generate login link
                login_link = f"{settings.DOMAIN}/auth/client-login/{login_token}/"
                
                # Send login email
                self._send_login_email(user, login_link)
                
                return Response({
                    "message": "Login link sent to your email",
                    "expires_at": expires_at
                }, status=status.HTTP_200_OK)
                
            except User.DoesNotExist:
                return Response(
                    {"error": "No account found with this email"},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def _send_login_email(self, user, login_link):
        """Send login link email"""
        try:
            subject = f"Login to Terramo Survey Platform - {user.client.company_name}"
            html_message = render_to_string('emails/login_link.html', {
                'user': user,
                'login_link': login_link,
                'expires_at': user.client.login_expires_at
            })
            
            send_mail(
                subject=subject,
                message=f"Click this link to access your dashboard: {login_link}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False,
            )
            logger.info(f"Login link sent to {user.email}")
        except Exception as e:
            logger.error(f"Failed to send login email: {str(e)}")


class StakeholderInvitationView(APIView):
    """
    Send invitation to stakeholders
    Only accessible by Client Admin
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        if request.user.role != User.UserRole.COMPANY_ADMIN:
            return Response(
                {"error": "Only Client Admin can send stakeholder invitations"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = StakeholderInvitationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                with transaction.atomic():
                    stakeholder_group_id = serializer.validated_data['stakeholder_group_id']
                    emails = serializer.validated_data['emails']
                    
                    # Get stakeholder group
                    stakeholder_group = get_object_or_404(
                        StakeholderGroup,
                        id=stakeholder_group_id,
                        client=request.user.client
                    )
                    
                    invitations_created = []
                    
                    for email in emails:
                        # Create or update invitation
                        invitation, created = StakeholderInvitation.objects.get_or_create(
                            stakeholder_group=stakeholder_group,
                            email=email,
                            defaults={
                                'invite_token': uuid.uuid4(),
                                'expires_at': timezone.now() + timedelta(days=7),
                                'sent_by': request.user,
                                'status': StakeholderInvitation.Status.PENDING
                            }
                        )
                        
                        if not created:
                            # Update existing invitation
                            invitation.invite_token = uuid.uuid4()
                            invitation.expires_at = timezone.now() + timedelta(days=7)
                            invitation.status = StakeholderInvitation.Status.PENDING
                            invitation.sent_by = request.user
                            invitation.save()
                        
                        # Send invitation email
                        self._send_stakeholder_invitation_email(invitation, stakeholder_group)
                        invitations_created.append(invitation)
                    
                    return Response({
                        "message": f"Invitations sent successfully to {len(invitations_created)} stakeholders",
                        "invitations": [
                            {
                                "email": inv.email,
                                "invite_token": inv.invite_token,
                                "expires_at": inv.expires_at
                            }
                            for inv in invitations_created
                        ]
                    }, status=status.HTTP_201_CREATED)
                    
            except Exception as e:
                logger.error(f"Error sending stakeholder invitations: {str(e)}")
                return Response(
                    {"error": "Failed to send invitations"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def _send_stakeholder_invitation_email(self, invitation, stakeholder_group):
        """Send invitation email to stakeholder"""
        try:
            invitation_link = f"{settings.DOMAIN}/auth/stakeholder-login/{invitation.invite_token}/"
            
            subject = f"Invitation to participate in {stakeholder_group.client.company_name} Survey"
            html_message = render_to_string('emails/stakeholder_invitation.html', {
                'invitation': invitation,
                'stakeholder_group': stakeholder_group,
                'invitation_link': invitation_link,
            })
            
            send_mail(
                subject=subject,
                message=f"Click this link to participate in the survey: {invitation_link}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[invitation.email],
                html_message=html_message,
                fail_silently=False,
            )
            logger.info(f"Stakeholder invitation sent to {invitation.email}")
        except Exception as e:
            logger.error(f"Failed to send stakeholder invitation: {str(e)}")


class StakeholderLoginView(APIView):
    """
    Handle Stakeholder login/registration
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, invite_token):
        """Validate invitation token"""
        try:
            invitation = get_object_or_404(
                StakeholderInvitation,
                invite_token=invite_token,
                expires_at__gt=timezone.now(),
                status=StakeholderInvitation.Status.PENDING
            )
            
            # Check if user already exists
            user_exists = User.objects.filter(
                email=invitation.email,
                role=User.UserRole.STAKEHOLDER
            ).exists()
            
            return Response({
                "message": "Valid invitation token",
                "email": invitation.email,
                "stakeholder_group": invitation.stakeholder_group.name,
                "company_name": invitation.stakeholder_group.client.company_name,
                "user_exists": user_exists
            }, status=status.HTTP_200_OK)
            
        except StakeholderInvitation.DoesNotExist:
            return Response(
                {"error": "Invalid or expired invitation token"},
                status=status.HTTP_404_NOT_FOUND
            )
    
    def post(self, request, invite_token):
        """Process Stakeholder login or registration"""
        try:
            invitation = get_object_or_404(
                StakeholderInvitation,
                invite_token=invite_token,
                expires_at__gt=timezone.now(),
                status=StakeholderInvitation.Status.PENDING
            )
            
            # Check if it's login or registration
            user_exists = User.objects.filter(
                email=invitation.email,
                role=User.UserRole.STAKEHOLDER
            ).exists()
            
            if user_exists:
                # Existing user login
                serializer = StakeholderLoginSerializer(data=request.data)
                if serializer.is_valid():
                    email = serializer.validated_data['email']
                    
                    if email != invitation.email:
                        return Response(
                            {"error": "Email does not match invitation"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    
                    user = User.objects.get(email=email, role=User.UserRole.STAKEHOLDER)
                    
                    # Update invitation status
                    invitation.status = StakeholderInvitation.Status.ACCEPTED
                    invitation.accepted_at = timezone.now()
                    invitation.save()
                    
                    # Generate tokens
                    refresh = RefreshToken.for_user(user)
                    
                    return Response({
                        "message": "Login successful",
                        "user": UserProfileSerializer(user).data,
                        "access_token": str(refresh.access_token),
                        "refresh_token": str(refresh),
                        "redirect_url": "/survey/"
                    }, status=status.HTTP_200_OK)
                
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            else:
                # New user registration
                serializer = StakeholderRegistrationSerializer(data=request.data)
                if serializer.is_valid():
                    email = serializer.validated_data['email']
                    
                    if email != invitation.email:
                        return Response(
                            {"error": "Email does not match invitation"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    
                    # Create new stakeholder user
                    user = User.objects.create_user(
                        email=email,
                        username=email,
                        first_name=serializer.validated_data['first_name'],
                        last_name=serializer.validated_data['last_name'],
                        role=User.UserRole.STAKEHOLDER,
                        client=invitation.stakeholder_group.client,
                        is_active=True
                    )
                    
                    # Update invitation status
                    invitation.status = StakeholderInvitation.Status.ACCEPTED
                    invitation.accepted_at = timezone.now()
                    invitation.save()
                    
                    # Generate tokens
                    refresh = RefreshToken.for_user(user)
                    
                    return Response({
                        "message": "Registration successful",
                        "user": UserProfileSerializer(user).data,
                        "access_token": str(refresh.access_token),
                        "refresh_token": str(refresh),
                        "redirect_url": "/survey/"
                    }, status=status.HTTP_201_CREATED)
                
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                
        except StakeholderInvitation.DoesNotExist:
            return Response(
                {"error": "Invalid or expired invitation token"},
                status=status.HTTP_404_NOT_FOUND
            )


class UserProfileView(generics.RetrieveUpdateAPIView):
    """
    Get and update user profile
    """
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        return self.request.user


# class LogoutView(APIView):
#     """
#     Logout user by blacklisting refresh token
#     """
#     permission_classes = [permissions.IsAuthenticated]
    
#     def post(self, request):
#         try:
#             refresh_token = request.data.get('refresh_token')
#             token = RefreshToken(refresh_token)
#             token.blacklist()
            
#             return Response(
#                 {"message": "Logout successful"},
#                 status=status.HTTP_200_OK
#             )
#         except Exception as e:
#             logger.error(f"Logout error: {str(e)}")
#             return Response(
#                 {"error": "Invalid token"},
#                 status=status.HTTP_400_BAD_REQUEST
#             )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def dashboard_view(request):
    """
    Dashboard endpoint that returns user-specific data
    """
    user = request.user
    
    if user.role == User.UserRole.COMPANY_ADMIN:
        # Client Admin dashboard data
        stakeholder_groups = StakeholderGroup.objects.filter(
            client=user.client,
            is_active=True
        )
        
        return Response({
            "user": UserProfileSerializer(user).data,
            "dashboard_type": "client_admin",
            "client": {
                "id": user.client.id,
                "company_name": user.client.company_name,
            },
            "stakeholder_groups": [
                {
                    "id": group.id,
                    "name": group.name,
                    "description": group.description,
                    "members_count": group.invitations.filter(
                        status=StakeholderInvitation.Status.ACCEPTED
                    ).count()
                }
                for group in stakeholder_groups
            ]
        })
    
    elif user.role == User.UserRole.STAKEHOLDER:
        # Stakeholder dashboard data
        return Response({
            "user": UserProfileSerializer(user).data,
            "dashboard_type": "stakeholder",
            "client": {
                "id": user.client.id,
                "company_name": user.client.company_name,
            },
            "available_surveys": []  # Add survey logic here
        })
    
    else:
        return Response(
            {"error": "Unauthorized access"},
            status=status.HTTP_403_FORBIDDEN
        )


# class StakeholderGroupViewSet(viewsets.ModelViewSet):
#     """
#     ViewSet for managing stakeholder groups
#     """
#     permission_classes = [permissions.IsAuthenticated]
    
#     def get_queryset(self):
#         """Filter queryset based on user role"""
#         if self.request.user.role == User.UserRole.SUPER_ADMIN:
#             return StakeholderGroup.objects.all()
#         elif self.request.user.role == User.UserRole.COMPANY_ADMIN:
#             return StakeholderGroup.objects.filter(client=self.request.user.client)
#         else:
#             return StakeholderGroup.objects.none()
    
#     def get_serializer_class(self):
#         """Return appropriate serializer based on action"""
#         if self.action == 'create':
#             return StakeholderGroupCreateSerializer
#         elif self.action in ['update', 'partial_update']:
#             return StakeholderGroupUpdateSerializer
#         return StakeholderGroupSerializer
    
#     def perform_create(self, serializer):
#         """Override create to add client and created_by"""
#         serializer.save(
#             client=self.request.user.client,
#             created_by=self.request.user
#         )
    
#     @action(detail=False, methods=['get'])
#     def my_groups(self, request):
#         """Get stakeholder groups for current client admin"""
#         if request.user.role != User.UserRole.COMPANY_ADMIN:
#             return Response(
#                 {"error": "Only Client Admin can access this endpoint"},
#                 status=status.HTTP_403_FORBIDDEN
#             )
        
#         groups = self.get_queryset().filter(is_active=True)
#         serializer = self.get_serializer(groups, many=True)
#         return Response(serializer.data)
    
#     @action(detail=True, methods=['get'])
#     def members(self, request, pk=None):
#         """Get members of a specific stakeholder group"""
#         group = self.get_object()
        
#         # Check permission
#         if (request.user.role == User.UserRole.COMPANY_ADMIN and 
#             group.client != request.user.client):
#             return Response(
#                 {"error": "You can only view members of your own groups"},
#                 status=status.HTTP_403_FORBIDDEN
#             )
        
#         invitations = StakeholderInvitation.objects.filter(
#             stakeholder_group=group,
#             status=StakeholderInvitation.Status.ACCEPTED
#         )
        
#         serializer = StakeholderInvitationDetailSerializer(invitations, many=True)
#         return Response(serializer.data)
    
#     @action(detail=True, methods=['post'])
#     def deactivate(self, request, pk=None):
#         """Deactivate a stakeholder group"""
#         group = self.get_object()
        
#         # Check permission
#         if (request.user.role == User.UserRole.COMPANY_ADMIN and 
#             group.client != request.user.client):
#             return Response(
#                 {"error": "You can only deactivate your own groups"},
#                 status=status.HTTP_403_FORBIDDEN
#             )
        
#         group.is_active = False
#         group.save()
        
#         return Response({"message": "Stakeholder group deactivated successfully"})


# class ClientManagementViewSet(viewsets.ModelViewSet):
#     """
#     ViewSet for managing clients (Super Admin only)
#     """
#     queryset = Client.objects.all()
#     permission_classes = [permissions.IsAuthenticated]
    
#     def get_serializer_class(self):
#         """Return appropriate serializer based on action"""
#         if self.action in ['update', 'partial_update']:
#             return ClientUpdateSerializer
#         return ClientDetailSerializer
    
#     def get_permissions(self):
#         """Only Super Admin can access this viewset"""
#         if self.request.user.role != User.UserRole.SUPER_ADMIN:
#             self.permission_denied(
#                 self.request, 
#                 message="Only Super Admin can manage clients"
#             )
#         return super().get_permissions()
    
#     @action(detail=True, methods=['get'])
#     def client_groups(self, request, pk=None):
#         """Get stakeholder groups for a specific client"""
#         client = self.get_object()
#         groups = StakeholderGroup.objects.filter(client=client, is_active=True)
#         serializer = StakeholderGroupSerializer(groups, many=True)
#         return Response(serializer.data)
    
#     @action(detail=True, methods=['get'])
#     def client_stats(self, request, pk=None):
#         """Get statistics for a specific client"""
#         client = self.get_object()
        
#         stats = {
#             'total_groups': client.stakeholder_groups.filter(is_active=True).count(),
#             'total_stakeholders': StakeholderInvitation.objects.filter(
#                 stakeholder_group__client=client,
#                 status=StakeholderInvitation.Status.ACCEPTED
#             ).count(),
#             'pending_invitations': StakeholderInvitation.objects.filter(
#                 stakeholder_group__client=client,
#                 status=StakeholderInvitation.Status.PENDING,
#                 expires_at__gt=timezone.now()
#             ).count(),
#             'expired_invitations': StakeholderInvitation.objects.filter(
#                 stakeholder_group__client=client,
#                 status=StakeholderInvitation.Status.PENDING,
#                 expires_at__lte=timezone.now()
#             ).count(),
#         }
        
#         return Response(stats)


# class InvitationManagementViewSet(viewsets.ReadOnlyModelViewSet):
#     """
#     ViewSet for managing invitations
#     """
#     serializer_class = StakeholderInvitationDetailSerializer
#     permission_classes = [permissions.IsAuthenticated]
    
#     def get_queryset(self):
#         """Filter queryset based on user role"""
#         if self.request.user.role == User.UserRole.SUPER_ADMIN:
#             return StakeholderInvitation.objects.all()
#         elif self.request.user.role == User.UserRole.COMPANY_ADMIN:
#             return StakeholderInvitation.objects.filter(
#                 stakeholder_group__client=self.request.user.client
#             )
#         else:
#             return StakeholderInvitation.objects.none()
    
#     @action(detail=False, methods=['get'])
#     def my_invitations(self, request):
#         """Get invitations sent by current client admin"""
#         if request.user.role != User.UserRole.COMPANY_ADMIN:
#             return Response(
#                 {"error": "Only Client Admin can access this endpoint"},
#                 status=status.HTTP_403_FORBIDDEN
#             )
        
#         invitations = self.get_queryset().filter(sent_by=request.user)
#         serializer = self.get_serializer(invitations, many=True)
#         return Response(serializer.data)
    
#     @action(detail=False, methods=['get'])
#     def pending(self, request):
#         """Get pending invitations"""
#         invitations = self.get_queryset().filter(
#             status=StakeholderInvitation.Status.PENDING,
#             expires_at__gt=timezone.now()
#         )
#         serializer = self.get_serializer(invitations, many=True)
#         return Response(serializer.data)
    
#     @action(detail=False, methods=['get'])
#     def expired(self, request):
#         """Get expired invitations"""
#         invitations = self.get_queryset().filter(
#             status=StakeholderInvitation.Status.PENDING,
#             expires_at__lte=timezone.now()
#         )
#         serializer = self.get_serializer(invitations, many=True)
#         return Response(serializer.data)


class BulkStakeholderInvitationView(APIView):
    """
    Handle bulk stakeholder invitations via CSV upload
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        if request.user.role != User.UserRole.COMPANY_ADMIN:
            return Response(
                {"error": "Only Client Admin can send bulk invitations"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = BulkStakeholderInvitationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                stakeholder_group_id = serializer.validated_data['stakeholder_group_id']
                csv_file = serializer.validated_data['csv_file']
                
                # Get stakeholder group
                stakeholder_group = get_object_or_404(
                    StakeholderGroup,
                    id=stakeholder_group_id,
                    client=request.user.client
                )
                
                # Process CSV file
                emails = self._process_csv_file(csv_file)
                
                if not emails:
                    return Response(
                        {"error": "No valid emails found in CSV file"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Create invitations
                invitations_created = []
                errors = []
                
                with transaction.atomic():
                    for email in emails:
                        try:
                            invitation, created = StakeholderInvitation.objects.get_or_create(
                                stakeholder_group=stakeholder_group,
                                email=email,
                                defaults={
                                    'invite_token': uuid.uuid4(),
                                    'expires_at': timezone.now() + timedelta(days=7),
                                    'sent_by': request.user,
                                    'status': StakeholderInvitation.Status.PENDING
                                }
                            )
                            
                            if not created:
                                # Update existing invitation
                                invitation.invite_token = uuid.uuid4()
                                invitation.expires_at = timezone.now() + timedelta(days=7)
                                invitation.status = StakeholderInvitation.Status.PENDING
                                invitation.sent_by = request.user
                                invitation.save()
                            
                            # Send invitation email
                            self._send_stakeholder_invitation_email(invitation, stakeholder_group)
                            invitations_created.append(invitation)
                            
                        except Exception as e:
                            errors.append(f"Error processing {email}: {str(e)}")
                            logger.error(f"Error processing bulk invitation for {email}: {str(e)}")
                
                return Response({
                    "message": f"Bulk invitations processed",
                    "successful_invitations": len(invitations_created),
                    "errors": errors,
                    "total_processed": len(emails)
                }, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                logger.error(f"Error processing bulk invitations: {str(e)}")
                return Response(
                    {"error": "Failed to process bulk invitations"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#     def _process_csv_file(self, csv_file):
#         """Process CSV file and extract emails"""
#         emails = []
#         try:
#             # Read CSV file
#             file_content = csv_file.read().decode('utf-8')
#             csv_reader = csv.DictReader(io.StringIO(file_content))
            
#             for row in csv_reader:
#                 # Look for email in various column names
#                 email = None
#                 for key in ['email', 'Email', 'EMAIL', 'e-mail', 'E-mail']:
#                     if key in row and row[key]:
#                         email = row[key].strip()
#                         break
                
#                 if email:
#                     try:
#                         validate_email(email)
#                         emails.append(email)
#                     except Exception:
#                         logger.warning(f"Invalid email format: {email}")
#                         continue
            
#         except Exception as e:
#             logger.error(f"Error processing CSV file: {str(e)}")
        
#         return list(set(emails))  # Remove duplicates
    
#     def _send_stakeholder_invitation_email(self, invitation, stakeholder_group):
#         """Send invitation email to stakeholder"""
#         # Implementation same as in StakeholderInvitationView
#         pass


class DashboardStatsView(APIView):
    """
    Get dashboard statistics
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        if request.user.role == User.UserRole.SUPER_ADMIN:
            # System-wide statistics
            stats = {
                'total_clients': Client.objects.count(),
                'active_clients': Client.objects.filter(is_active=True).count(),
                'total_stakeholder_groups': StakeholderGroup.objects.filter(is_active=True).count(),
                'total_stakeholders': StakeholderInvitation.objects.filter(
                    status=StakeholderInvitation.Status.ACCEPTED
                ).count(),
                'pending_invitations': StakeholderInvitation.objects.filter(
                    status=StakeholderInvitation.Status.PENDING,
                    expires_at__gt=timezone.now()
                ).count(),
                'completed_surveys': 0,  # Add survey logic here
            }
        elif request.user.role == User.UserRole.COMPANY_ADMIN:
            # Client-specific statistics
            stats = {
                'total_clients': 1,
                'active_clients': 1,
                'total_stakeholder_groups': StakeholderGroup.objects.filter(
                    client=request.user.client,
                    is_active=True
                ).count(),
                'total_stakeholders': StakeholderInvitation.objects.filter(
                    stakeholder_group__client=request.user.client,
                    status=StakeholderInvitation.Status.ACCEPTED
                ).count(),
                'pending_invitations': StakeholderInvitation.objects.filter(
                    stakeholder_group__client=request.user.client,
                    status=StakeholderInvitation.Status.PENDING,
                    expires_at__gt=timezone.now()
                ).count(),
                'completed_surveys': 0,  # Add survey logic here
            }
        else:
            return Response(
                {"error": "Unauthorized access"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = DashboardStatsSerializer(stats)
        return Response(serializer.data)


class ValidateInvitationView(APIView):
    """
    Validate invitation token without processing login
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, token):
        try:
            # Check if it's a client invitation
            client = Client.objects.filter(
                invitation_token=token,
                invitation_expires_at__gt=timezone.now()
            ).first()
            
            if client:
                return Response({
                    "type": "client_invitation",
                    "valid": True,
                    "email": client.email,
                    "company_name": client.company_name,
                    "expires_at": client.invitation_expires_at
                })
            
            # Check if it's a stakeholder invitation
            stakeholder_invitation = StakeholderInvitation.objects.filter(
                invite_token=token,
                expires_at__gt=timezone.now(),
                status=StakeholderInvitation.Status.PENDING
            ).first()
            
            if stakeholder_invitation:
                return Response({
                    "type": "stakeholder_invitation",
                    "valid": True,
                    "email": stakeholder_invitation.email,
                    "stakeholder_group": stakeholder_invitation.stakeholder_group.name,
                    "company_name": stakeholder_invitation.stakeholder_group.client.company_name,
                    "expires_at": stakeholder_invitation.expires_at
                })
            
            return Response(
                {"valid": False, "error": "Invalid or expired token"},
                status=status.HTTP_404_NOT_FOUND
            )
            
        except Exception as e:
            logger.error(f"Error validating invitation: {str(e)}")
            return Response(
                {"valid": False, "error": "Invalid token format"},
                status=status.HTTP_400_BAD_REQUEST
            )


class ResendInvitationView(APIView):
    """
    Resend invitation email
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, invitation_id):
        if request.user.role != User.UserRole.COMPANY_ADMIN:
            return Response(
                {"error": "Only Client Admin can resend invitations"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            invitation = get_object_or_404(
                StakeholderInvitation,
                id=invitation_id,
                stakeholder_group__client=request.user.client
            )
            
            # Update invitation
            invitation.invite_token = uuid.uuid4()
            invitation.expires_at = timezone.now() + timedelta(days=7)
            invitation.status = StakeholderInvitation.Status.PENDING
            invitation.sent_by = request.user
            invitation.save()
            
            # Resend email
            self._send_stakeholder_invitation_email(invitation, invitation.stakeholder_group)
            
            return Response({"message": "Invitation resent successfully"})
            
        except Exception as e:
            logger.error(f"Error resending invitation: {str(e)}")
            return Response(
                {"error": "Failed to resend invitation"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _send_stakeholder_invitation_email(self, invitation, stakeholder_group):
        """Send invitation email to stakeholder"""
        # Implementation same as in StakeholderInvitationView
        pass


# class CancelInvitationView(APIView):
#     """
#     Cancel pending invitation
#     """
#     permission_classes = [permissions.IsAuthenticated]
    
#     def post(self, request, invitation_id):
#         if request.user.role != User.UserRole.COMPANY_ADMIN:
#             return Response(
#                 {"error": "Only Client Admin can cancel invitations"},
#                 status=status.HTTP_403_FORBIDDEN
#             )
        
#         try:
#             invitation = get_object_or_404(
#                 StakeholderInvitation,
#                 id=invitation_id,
#                 stakeholder_group__client=request.user.client,
#                 status=StakeholderInvitation.Status.PENDING
#             )
            
#             invitation.status = Stakeholder