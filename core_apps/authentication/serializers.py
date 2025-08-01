from rest_framework import serializers
from django.contrib.auth import authenticate
from django.core.validators import EmailValidator
from .models import ( 
    ClientAdmin, Stakeholder, 
    StakeholderGroup, InvitationToken, LoginSession
)
from core_apps.clients.models import Client
from django.conf import settings
User = settings.AUTH_USER_MODEL
# class ClientCreateSerializer(serializers.ModelSerializer):
#     """Serializer for creating clients by Terramo Admin"""
    
#     products = serializers.MultipleChoiceField(choices=Client.PRODUCT_CHOICES)

#     class Meta:
#         model = Client
#         fields = [
#             'company_name', 'company_contact_email', 'date_required', 'products',
#             'first_name', 'last_name', 'gender', 'birth_year',
#             'street', 'postal_code', 'city', 'country',
#             'phone_number', 'mobile_number', 'email',
#             'internal_processing_note'
#         ]

#     def validate_products(self, value):
#         if not value:
#             raise serializers.ValidationError("At least one product must be selected.")
#         return list(value)  # ✅ Ensure it stays a list

#     def create(self, validated_data):
#         # ✅ Ensure 'products' is stored as a list (not a set)
#         validated_data['products'] = list(validated_data.get('products', []))
        
#         # Optional: if you're passing created_by manually
#         created_by = self.context['request'].user if 'request' in self.context else None
#         if created_by:
#             validated_data['created_by'] = created_by

#         return Client.objects.create(**validated_data)
# class ClientCreateSerializer(serializers.ModelSerializer):
#     """Serializer for creating clients by Terramo Admin"""
#     products = serializers.MultipleChoiceField(choices=Client.PRODUCT_CHOICES)
    
#     class Meta:
#         model = Client
#         fields = [
#             'company_name', 'company_contact_email', 'date_required', 'products',
#             'first_name', 'last_name', 'gender', 'birth_year',
#             'street', 'postal_code', 'city', 'country',
#             'phone_number', 'mobile_number', 'email',
#             'internal_processing_note'
#         ]
    
#     def validate_products(self, value):
#         if not value:
#             raise serializers.ValidationError("At least one product must be selected.")
#         return value

class ClientAdminCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating client admin with invitation"""
    
    class Meta:
        model = ClientAdmin
        fields = ['email', 'first_name', 'last_name']
    
    def validate_email(self, value):
        if ClientAdmin.objects.filter(email=value).exists():
            raise serializers.ValidationError("Client admin with this email already exists.")
        return value

class StakeholderGroupSerializer(serializers.ModelSerializer):
    """Serializer for stakeholder groups"""
    stakeholders_count = serializers.SerializerMethodField()
    stakeholder_invite_url = serializers.SerializerMethodField()
    class Meta:
        model = StakeholderGroup
        fields = ['id', 'name', 'created_at', 'is_active', 'stakeholders_count', 'invitation_token', 'stakeholder_invite_url']
        read_only_fields = ['id', 'created_at', 'invitation_token']
    
    def get_stakeholders_count(self, obj):
        return obj.stakeholders.count()
    
    def get_stakeholder_invite_url(self, obj):
        return obj.get_invite_full_url()

# class StakeholderCreateSerializer(serializers.ModelSerializer):
#     """Serializer for creating stakeholders"""
    
#     class Meta:
#         model = Stakeholder
#         fields = ['email', 'first_name', 'last_name', 'group']
#         read_only_fields = ['group']
    
#     def validate_email(self, value):
#         group = self.context.get('group')
#         if group and Stakeholder.objects.filter(email=value, group=group).exists():
#             raise serializers.ValidationError("Stakeholder with this email already exists in this group.")
#         return value

class StakeholderCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating stakeholders"""

    class Meta:
        model = Stakeholder
        fields = ['email', 'first_name', 'last_name', 'group']
        read_only_fields = ['group']

    def validate_email(self, value):
        group = self.context.get('group')
        if group and Stakeholder.objects.filter(email=value, group=group).exists():
            raise serializers.ValidationError("Stakeholder with this email already exists in this group.")
        return value
class StakeholderRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for stakeholder registration"""
    
    class Meta:
        model = Stakeholder
        fields = ['first_name', 'last_name']
    
    def validate(self, attrs):
        if not attrs.get('first_name') or not attrs.get('last_name'):
            raise serializers.ValidationError("First name and last name are required.")
        return attrs

class EmailLoginSerializer(serializers.Serializer):
    """Serializer for email-only login"""
    email = serializers.EmailField()
    
    def validate_email(self, value):
        if not value:
            raise serializers.ValidationError("Email is required.")
        return value

class InvitationTokenSerializer(serializers.ModelSerializer):
    """Serializer for invitation tokens"""
    is_valid = serializers.SerializerMethodField()
    
    class Meta:
        model = InvitationToken
        fields = ['id', 'token', 'token_type', 'email', 'created_at', 'expires_at', 'is_valid']
        read_only_fields = ['id', 'token', 'created_at', 'expires_at']
    
    def get_is_valid(self, obj):
        return obj.is_valid()

class ClientAdminDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for client admin"""
    client_company = serializers.CharField(source='client.company_name', read_only=True)
    
    class Meta:
        model = ClientAdmin
        fields = [
            'id', 'email', 'first_name', 'last_name', 
            'is_active', 'created_at', 'last_login', 'client_company'
        ]

class StakeholderDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for stakeholder"""
    group_name = serializers.CharField(source='group.name', read_only=True)
    client_company = serializers.CharField(source='group.client.company_name', read_only=True)
    
    class Meta:
        model = Stakeholder
        fields = [
            'id', 'email', 'first_name', 'last_name', 
            'is_registered', 'created_at', 'last_login',
            'group_name', 'client_company'
        ]