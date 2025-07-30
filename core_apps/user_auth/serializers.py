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

from rest_framework import serializers
from django.contrib.auth import authenticate
from django.core.validators import validate_email
from django.utils import timezone
from django.contrib.auth.password_validation import validate_password
import uuid

from core_apps.user_auth.models import User
# from core_apps.clients.models import Client
# from core_apps.stakeholder_analysis.models import StakeholderGroup, StakeholderInvitation
from djoser.serializers import (
    UserCreateSerializer as DjoserUserCreateSerializer,
)
class UserCreateSerializer(DjoserUserCreateSerializer):
    class Meta(DjoserUserCreateSerializer.Meta):
        model = User
        fields = [
            "email",
            "password",
            "first_name",
            "last_name",
    
        ]

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
    
# class ClientInvitationSerializer(serializers.ModelSerializer):
#     """
#     Serializer for creating client invitations
#     """
#     email = serializers.EmailField(required=True)
    
#     class Meta:
#         model = Client
#         fields = [
#             'company_name',
#             'email',
#             'contact_person_first_name',
#             'contact_person_last_name',
#             'phone_number',
#             'website',
#             'industry',
#             'country',
#             'city',
#             'address',
#             'description'
#         ]
        
#     def validate_email(self, value):
#         """Validate email is not already used by another client"""
#         if Client.objects.filter(email=value).exists():
#             raise serializers.ValidationError("A client with this email already exists")
#         return value
    
#     def validate_company_name(self, value):
#         """Validate company name is not already used"""
#         if Client.objects.filter(company_name=value).exists():
#             raise serializers.ValidationError("A client with this company name already exists")
#         return value


# class ClientLoginSerializer(serializers.Serializer):
#     """
#     Serializer for client admin login
#     """
#     email = serializers.EmailField(required=True)
    
#     def validate_email(self, value):
#         """Validate email format"""
#         try:
#             validate_email(value)
#         except Exception:
#             raise serializers.ValidationError("Please enter a valid email address")
#         return value


# class GenerateLoginLinkSerializer(serializers.Serializer):
#     """
#     Serializer for generating login link for returning users
#     """
#     email = serializers.EmailField(required=True)
    
#     def validate_email(self, value):
#         """Validate email format"""
#         try:
#             validate_email(value)
#         except Exception:
#             raise serializers.ValidationError("Please enter a valid email address")
#         return value


# class StakeholderLoginSerializer(serializers.Serializer):
#     """
#     Serializer for stakeholder login
#     """
#     email = serializers.EmailField(required=True)
    
#     def validate_email(self, value):
#         """Validate email format"""
#         try:
#             validate_email(value)
#         except Exception:
#             raise serializers.ValidationError("Please enter a valid email address")
#         return value


# class StakeholderRegistrationSerializer(serializers.Serializer):
#     """
#     Serializer for stakeholder registration
#     """
#     email = serializers.EmailField(required=True)
#     first_name = serializers.CharField(max_length=30, required=True)
#     last_name = serializers.CharField(max_length=30, required=True)
    
#     def validate_email(self, value):
#         """Validate email format and uniqueness for stakeholders"""
#         try:
#             validate_email(value)
#         except Exception:
#             raise serializers.ValidationError("Please enter a valid email address")
        
#         # Check if stakeholder with this email already exists
#         if User.objects.filter(email=value, role=User.UserRole.STAKEHOLDER).exists():
#             raise serializers.ValidationError("A stakeholder with this email already exists")
        
#         return value
    
#     def validate_first_name(self, value):
#         """Validate first name"""
#         if not value.strip():
#             raise serializers.ValidationError("First name cannot be empty")
#         return value.strip().title()
    
#     def validate_last_name(self, value):
#         """Validate last name"""
#         if not value.strip():
#             raise serializers.ValidationError("Last name cannot be empty")
#         return value.strip().title()


# class StakeholderInvitationSerializer(serializers.Serializer):
#     """
#     Serializer for sending stakeholder invitations
#     """
#     stakeholder_group_id = serializers.UUIDField(required=True)
#     emails = serializers.ListField(
#         child=serializers.EmailField(),
#         min_length=1,
#         max_length=50,
#         required=True
#     )
    
#     def validate_emails(self, value):
#         """Validate email list"""
#         if not value:
#             raise serializers.ValidationError("At least one email is required")
        
#         # Remove duplicates while preserving order
#         unique_emails = []
#         seen = set()
#         for email in value:
#             if email not in seen:
#                 unique_emails.append(email)
#                 seen.add(email)
        
#         if len(unique_emails) != len(value):
#             raise serializers.ValidationError("Duplicate emails found")
        
#         return unique_emails
    
#     def validate_stakeholder_group_id(self, value):
#         """Validate stakeholder group exists"""
#         if not StakeholderGroup.objects.filter(id=value).exists():
#             raise serializers.ValidationError("Invalid stakeholder group")
#         return value


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile
    """
    full_name = serializers.CharField(read_only=True)
    client_name = serializers.CharField(source='client.company_name', read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id',
         
            'email',
            'first_name',
          
            'last_name',
            'full_name',
            'role',
            'client_name',
            'is_active',
            'date_joined',
            'created_at',
            'updated_at'
        ]
        read_only_fields = [
            'id',
            'username',
            'email',
            'role',
            'client_name',
            'is_active',
            'date_joined',
            'created_at',
            'updated_at'
        ]


# class StakeholderGroupSerializer(serializers.ModelSerializer):
#     """
#     Serializer for stakeholder groups
#     """
#     members_count = serializers.SerializerMethodField()
#     pending_invitations = serializers.SerializerMethodField()
    
#     class Meta:
#         model = StakeholderGroup
#         fields = [
#             'id',
#             'name',
#             'description',
#             'unique_group_token',
#             'show_in_chart',
#             'is_active',
#             'members_count',
#             'pending_invitations',
#             'created_at',
#             'updated_at'
#         ]
#         read_only_fields = [
#             'id',
#             'unique_group_token',
#             'created_at',
#             'updated_at'
#         ]
    
#     def get_members_count(self, obj):
#         """Get count of accepted members"""
#         return obj.invitations.filter(
#             status=StakeholderInvitation.Status.ACCEPTED
#         ).count()
    
#     def get_pending_invitations(self, obj):
#         """Get count of pending invitations"""
#         return obj.invitations.filter(
#             status=StakeholderInvitation.Status.PENDING,
#             expires_at__gt=timezone.now()
#         ).count()


# class StakeholderInvitationDetailSerializer(serializers.ModelSerializer):
#     """
#     Serializer for stakeholder invitation details
#     """
#     stakeholder_group_name = serializers.CharField(source='stakeholder_group.name', read_only=True)
#     client_name = serializers.CharField(source='stakeholder_group.client.company_name', read_only=True)
#     sent_by_name = serializers.CharField(source='sent_by.full_name', read_only=True)
#     is_expired = serializers.SerializerMethodField()
    
#     class Meta:
#         model = StakeholderInvitation
#         fields = [
#             'id',
#             'email',
#             'invite_token',
#             'status',
#             'stakeholder_group_name',
#             'client_name',
#             'sent_by_name',
#             'sent_at',
#             'accepted_at',
#             'expires_at',
#             'is_expired'
#         ]
#         read_only_fields = [
#             'id',
#             'invite_token',
#             'stakeholder_group_name',
#             'client_name',
#             'sent_by_name',
#             'sent_at',
#             'accepted_at',
#             'expires_at'
#         ]
    
#     def get_is_expired(self, obj):
#         """Check if invitation is expired"""
#         return obj.expires_at < timezone.now()


# class ClientDetailSerializer(serializers.ModelSerializer):
#     """
#     Serializer for client details
#     """
#     stakeholder_groups_count = serializers.SerializerMethodField()
#     total_stakeholders = serializers.SerializerMethodField()
    
#     class Meta:
#         model = Client
#         fields = [
#             'id',
#             'company_name',
#             'email',
#             'contact_person_first_name',
#             'contact_person_last_name',
#             'phone_number',
#             'website',
#             'industry',
#             'country',
#             'city',
#             'address',
#             'description',
#             'stakeholder_groups_count',
#             'total_stakeholders',
#             'created_at',
#             'updated_at'
#         ]
#         read_only_fields = [
#             'id',
#             'stakeholder_groups_count',
#             'total_stakeholders',
#             'created_at',
#             'updated_at'
#         ]
    
#     def get_stakeholder_groups_count(self, obj):
#         """Get count of stakeholder groups"""
#         return obj.stakeholder_groups.filter(is_active=True).count()
    
#     def get_total_stakeholders(self, obj):
#         """Get total count of stakeholders across all groups"""
#         return StakeholderInvitation.objects.filter(
#             stakeholder_group__client=obj,
#             status=StakeholderInvitation.Status.ACCEPTED
#         ).count()


# class PasswordResetSerializer(serializers.Serializer):
#     """
#     Serializer for password reset request
#     """
#     email = serializers.EmailField(required=True)
    
#     def validate_email(self, value):
#         """Validate email exists"""
#         try:
#             validate_email(value)
#         except Exception:
#             raise serializers.ValidationError("Please enter a valid email address")
        
#         if not User.objects.filter(email=value).exists():
#             raise serializers.ValidationError("No account found with this email address")
        
#         return value


# class PasswordResetConfirmSerializer(serializers.Serializer):
#     """
#     Serializer for password reset confirmation
#     """
#     uid = serializers.CharField(required=True)
#     token = serializers.CharField(required=True)
#     new_password = serializers.CharField(required=True, write_only=True)
#     confirm_password = serializers.CharField(required=True, write_only=True)
    
#     def validate_new_password(self, value):
#         """Validate new password"""
#         validate_password(value)
#         return value
    
#     def validate(self, attrs):
#         """Validate passwords match"""
#         if attrs['new_password'] != attrs['confirm_password']:
#             raise serializers.ValidationError("Passwords do not match")
#         return attrs


# class TokenRefreshSerializer(serializers.Serializer):
#     """
#     Serializer for token refresh
#     """
#     refresh_token = serializers.CharField(required=True)
    
#     def validate_refresh_token(self, value):
#         """Validate refresh token format"""
#         if not value:
#             raise serializers.ValidationError("Refresh token is required")
#         return value


# class BulkStakeholderInvitationSerializer(serializers.Serializer):
#     """
#     Serializer for bulk stakeholder invitations with CSV upload
#     """
#     stakeholder_group_id = serializers.UUIDField(required=True)
#     csv_file = serializers.FileField(required=True)
    
#     def validate_csv_file(self, value):
#         """Validate CSV file"""
#         if not value.name.endswith('.csv'):
#             raise serializers.ValidationError("File must be a CSV file")
        
#         if value.size > 5 * 1024 * 1024:  # 5MB limit
#             raise serializers.ValidationError("File size must be less than 5MB")
        
#         return value
    
#     def validate_stakeholder_group_id(self, value):
#         """Validate stakeholder group exists"""
#         if not StakeholderGroup.objects.filter(id=value).exists():
#             raise serializers.ValidationError("Invalid stakeholder group")
#         return value


# class StakeholderGroupCreateSerializer(serializers.ModelSerializer):
#     """
#     Serializer for creating stakeholder groups
#     """
#     class Meta:
#         model = StakeholderGroup
#         fields = [
#             'name',
#             'description',
#             'show_in_chart',
#             'is_active'
#         ]
    
#     def validate_name(self, value):
#         """Validate group name uniqueness within client"""
#         request = self.context.get('request')
#         if request and request.user.client:
#             if StakeholderGroup.objects.filter(
#                 client=request.user.client,
#                 name=value
#             ).exists():
#                 raise serializers.ValidationError(
#                     "A stakeholder group with this name already exists"
#                 )
#         return value
    
#     def create(self, validated_data):
#         """Create stakeholder group with client and created_by"""
#         request = self.context.get('request')
#         validated_data['client'] = request.user.client
#         validated_data['created_by'] = request.user
#         return super().create(validated_data)


# class StakeholderGroupUpdateSerializer(serializers.ModelSerializer):
#     """
#     Serializer for updating stakeholder groups
#     """
#     class Meta:
#         model = StakeholderGroup
#         fields = [
#             'name',
#             'description',
#             'show_in_chart',
#             'is_active'
#         ]
    
#     def validate_name(self, value):
#         """Validate group name uniqueness within client"""
#         request = self.context.get('request')
#         instance = self.instance
#         if request and request.user.client:
#             if StakeholderGroup.objects.filter(
#                 client=request.user.client,
#                 name=value
#             ).exclude(id=instance.id).exists():
#                 raise serializers.ValidationError(
#                     "A stakeholder group with this name already exists"
#                 )
#         return value


# class ClientUpdateSerializer(serializers.ModelSerializer):
#     """
#     Serializer for updating client information
#     """
#     class Meta:
#         model = Client
#         fields = [
#             'company_name',
#             'contact_person_first_name',
#             'contact_person_last_name',
#             'phone_number',
#             'website',
#             'industry',
#             'country',
#             'city',
#             'address',
#             'description'
#         ]
    
#     def validate_company_name(self, value):
#         """Validate company name uniqueness"""
#         instance = self.instance
#         if Client.objects.filter(company_name=value).exclude(id=instance.id).exists():
#             raise serializers.ValidationError("A client with this company name already exists")
#         return value


# class DashboardStatsSerializer(serializers.Serializer):
#     """
#     Serializer for dashboard statistics
#     """
#     total_clients = serializers.IntegerField(read_only=True)
#     active_clients = serializers.IntegerField(read_only=True)
#     total_stakeholder_groups = serializers.IntegerField(read_only=True)
#     total_stakeholders = serializers.IntegerField(read_only=True)
#     pending_invitations = serializers.IntegerField(read_only=True)
#     completed_surveys = serializers.IntegerField(read_only=True)


# class InvitationLinkSerializer(serializers.Serializer):
#     """
#     Serializer for invitation link generation
#     """
#     client_id = serializers.UUIDField(required=True)
#     expiry_hours = serializers.IntegerField(default=24, min_value=1, max_value=168)  # Max 7 days
    
#     def validate_client_id(self, value):
#         """Validate client exists"""
#         if not Client.objects.filter(id=value).exists():
#             raise serializers.ValidationError("Invalid client ID")
#         return value
    

# Serializers for validation
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True, min_length=6)
    
    def validate_email(self, value):
        return value.lower().strip()


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=False)