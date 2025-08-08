from rest_framework import serializers
from django.contrib.auth import authenticate
from django.core.validators import EmailValidator
from .models import ( 
    ClientAdmin, Stakeholder, 
    StakeholderGroup, InvitationToken, LoginSession, StakeholderInvitation
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


"""
Final: v2
"""

class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = [
            'company_name', 'company_contact_email', 'date_required', 'products',
            'first_name', 'last_name', 'gender', 'birth_year',
            'street', 'postal_code', 'city', 'country',
            'phone_number', 'mobile_number', 'email',
            'internal_processing_note'
        ]
        
# class EmailLoginAuthSerializer(serializers.Serializer):
#     email = serializers.EmailField()
    
#     def validate_email(self, value):
#         if not value:
#             raise serializers.ValidationError("Email is required.")
#         return value.lower()
    
# class ClientAdminLoginSerializer(EmailLoginAuthSerializer):
#     def validate(self, attrs):
#         email = attrs.get('email')
        
#         try:
#             client_admin = ClientAdmin.objects.get(email=email, is_active=True)
#             attrs['client_admin'] = client_admin
#         except ClientAdmin.DoesNotExist:
#             raise serializers.ValidationError("Invalid email or client admin not found.")
        
#         return attrs


"""
Updated: Stakeholders -- Start --
"""
class StakeholderGroupDataSerializer(serializers.ModelSerializer):
    stakeholders_count = serializers.SerializerMethodField()
    pending_invitations_count = serializers.SerializerMethodField()
    invitation_url = serializers.SerializerMethodField()
    
    class Meta:
        model = StakeholderGroup
        fields = [
            'id', 'name', 'client', 'created_by', 'created_at', 
            'is_active', 'invitation_token', 'stakeholders_count', 
            'pending_invitations_count', 'invitation_url'
        ]
        read_only_fields = ['id', 'client', 'created_by', 'created_at', 'invitation_token']
    
    def get_stakeholders_count(self, obj):
        return obj.stakeholders.filter(is_registered=True).count()
    
    def get_pending_invitations_count(self, obj):
        return obj.invitations.filter(status__in=['sent', 'clicked', 'email_verified']).count()
    
    def get_invitation_url(self, obj):
        return obj.get_invite_full_url()
    
    def validate_name(self, value):
        """Ensure unique name per client"""
        request = self.context.get('request')
        if request and request.user.client:
            existing = StakeholderGroup.objects.filter(
                name=value, 
                client=request.user.client
            )
            if self.instance:
                existing = existing.exclude(id=self.instance.id)
            
            if existing.exists():
                raise serializers.ValidationError(
                    f"A stakeholder group with name '{value}' already exists for your organization."
                )
        return value

class StakeholderSerializer(serializers.ModelSerializer):
    group_name = serializers.CharField(source='group.name', read_only=True)
    invitation_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Stakeholder
        fields = [
            'id', 'email', 'first_name', 'last_name', 'group', 
            'group_name', 'is_registered', 'status', 'created_at', 
            'last_login', 'invitation_count'
        ]
        read_only_fields = ['id', 'created_at', 'last_login', 'is_registered']
    
    def get_invitation_count(self, obj):
        return obj.invitations.count()

class StakeholderInvitationSerializer(serializers.ModelSerializer):
    group_name = serializers.CharField(source='stakeholder_group.name', read_only=True)
    sent_by_name = serializers.SerializerMethodField()
    stakeholder_name = serializers.SerializerMethodField()
    is_expired = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = StakeholderInvitation
        fields = [
            'id', 'stakeholder_group', 'group_name', 'email', 'invitation_token',
            'status', 'email_status', 'sent_at', 'clicked_at', 'email_verified_at',
            'completed_at', 'sent_by', 'sent_by_name', 'expires_at', 'stakeholder',
            'stakeholder_name', 'is_expired'
        ]
        read_only_fields = [
            'id', 'invitation_token', 'sent_at', 'clicked_at', 
            'email_verified_at', 'completed_at', 'sent_by'
        ]
    
    def get_sent_by_name(self, obj):
        return f"{obj.sent_by.first_name} {obj.sent_by.last_name}".strip() or obj.sent_by.email
    
    def get_stakeholder_name(self, obj):
        if obj.stakeholder:
            return f"{obj.stakeholder.first_name} {obj.stakeholder.last_name}".strip() or obj.stakeholder.email
        return None

class SendInvitationSerializer(serializers.Serializer):
    email = serializers.EmailField(validators=[EmailValidator()])
    send_email = serializers.BooleanField(default=True)
    
    def validate_email(self, value):
        """Validate email format and check for duplicates"""
        group_id = self.context.get('group_id')
        if group_id:
            # Check if invitation already exists for this email and group
            if StakeholderInvitation.objects.filter(
                email=value, 
                stakeholder_group_id=group_id,
                status__in=['sent', 'clicked', 'email_verified']
            ).exists():
                raise serializers.ValidationError(
                    f"An active invitation already exists for {value} in this group."
                )
        return value.lower()

class EmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(validators=[EmailValidator()])
    token = serializers.UUIDField()
    
    def validate(self, data):
        """Validate email matches the invitation token"""
        try:
            invitation = StakeholderInvitation.objects.get(
                invitation_token=data['token'],
                status__in=['clicked', 'email_verified']
            )
            if invitation.email.lower() != data['email'].lower():
                raise serializers.ValidationError({
                    'email': 'Email does not match the invitation.'
                })
            
            if invitation.is_expired:
                raise serializers.ValidationError({
                    'token': 'This invitation has expired.'
                })
                
            data['invitation'] = invitation
        except StakeholderInvitation.DoesNotExist:
            raise serializers.ValidationError({
                'token': 'Invalid or expired invitation token.'
            })
        
        return data

class StakeholderRegistrationDataSerializer(serializers.Serializer):
    email = serializers.EmailField(validators=[EmailValidator()])
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100)
    token = serializers.UUIDField()
    
    def validate_first_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("First name cannot be empty.")
        return value.strip()
    
    def validate_last_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Last name cannot be empty.")
        return value.strip()
    
    def validate(self, data):
        """Validate email matches invitation and invitation is in correct state"""
        try:
            invitation = StakeholderInvitation.objects.get(
                invitation_token=data['token'],
                status__in=['email_verified']
            )
            
            if invitation.email.lower() != data['email'].lower():
                raise serializers.ValidationError({
                    'email': 'Email does not match the invitation.'
                })
            
            if invitation.is_expired:
                raise serializers.ValidationError({
                    'token': 'This invitation has expired.'
                })
            
            # Check if stakeholder already exists and is registered
            if (invitation.stakeholder and 
                invitation.stakeholder.is_registered and 
                invitation.stakeholder.status == 'approved'):
                raise serializers.ValidationError({
                    'non_field_errors': ['Registration already completed for this invitation.']
                })
                
            data['invitation'] = invitation
            
        except StakeholderInvitation.DoesNotExist:
            raise serializers.ValidationError({
                'token': 'Invalid or expired invitation token.'
            })
        
        return data

class ApproveRejectSerializer(serializers.Serializer):
    action = serializers.ChoiceField(choices=['approve', 'reject'])
    reason = serializers.CharField(max_length=500, required=False, allow_blank=True)
    
    def validate_reason(self, value):
        action = self.initial_data.get('action')
        if action == 'reject' and not value.strip():
            raise serializers.ValidationError(
                "Reason is required when rejecting a stakeholder."
            )
        return value.strip() if value else value
"""
Updated: Stakeholders -- End --
"""