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
from loguru import logger
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
# class StakeholderRegistrationSerializer(serializers.ModelSerializer):
#     """Serializer for stakeholder registration"""
    
#     class Meta:
#         model = Stakeholder
#         fields = ['first_name', 'last_name']
    
#     def validate(self, attrs):
#         if not attrs.get('first_name') or not attrs.get('last_name'):
#             raise serializers.ValidationError("First name and last name are required.")
#         return attrs

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

# class InvitationValidateSerializer(serializers.Serializer):
#     invitation_token = serializers.UUIDField()

#     def validate(self, attrs):
#         token = attrs['invitation_token']
#         try:
#             invitation = StakeholderInvitation.objects.select_related('stakeholder_group').get(
#                 invitation_token=token
#             )
#         except StakeholderInvitation.DoesNotExist:
#             raise serializers.ValidationError("Invalid or expired invitation token.")

#         if invitation.is_expired:
#             raise serializers.ValidationError("Invitation has expired.")

#         attrs['invitation'] = invitation
#         return attrs


# class EmailRequestVerificationSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     invitation_token = serializers.UUIDField()

#     def validate(self, attrs):
#         email = attrs['email']
#         token = attrs['invitation_token']

#         try:
#             invitation = StakeholderInvitation.objects.select_related('stakeholder_group').get(
#                 invitation_token=token
#             )
#         except StakeholderInvitation.DoesNotExist:
#             raise serializers.ValidationError("Invalid invitation token.")

#         if invitation.is_expired:
#             raise serializers.ValidationError("Invitation expired.")

#         # Check if stakeholder exists in this group
#         stakeholder = Stakeholder.objects.filter(
#             email=email,
#             group=invitation.stakeholder_group
#         ).first()

#         attrs['stakeholder'] = stakeholder
#         attrs['invitation'] = invitation
#         return attrs

#     def create(self, validated_data):
#         stakeholder = validated_data['stakeholder']
#         invitation = validated_data['invitation']
#         email = validated_data['email']

#         if not stakeholder:
#             # Create new stakeholder
#             stakeholder = Stakeholder.objects.create(
#                 email=email,
#                 group=invitation.stakeholder_group,
#                 status='pending',
#                 is_registered=False,
#                 user=None  # Will be set upon full registration
#             )

#         # Link stakeholder to invitation
#         invitation.stakeholder = stakeholder
#         invitation.status = 'email_verified'
#         invitation.email_verified_at = timezone.now()
#         invitation.save()

#         return stakeholder
from django.utils import timezone
class InvitationValidationSerializer(serializers.Serializer):
    """Serializer to validate invitation token"""
    token = serializers.UUIDField()
    
    def validate_token(self, value):
        try:
            stakeholder_group = StakeholderGroup.objects.get(invitation_token=value, is_active=True)
            return value
        except StakeholderGroup.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired invitation token.")


# class EmailSubmissionSerializer(serializers.Serializer):
#     """Serializer for email submission in invitation process"""
#     email = serializers.EmailField()
#     token = serializers.UUIDField()
    
#     def validate(self, data):
#         email = data['email']
#         token = data['token']
        
#         # Validate token exists
#         try:
#             stakeholder_group = StakeholderGroup.objects.get(
#                 invitation_token=token, 
#                 is_active=True
#             )
#         except StakeholderGroup.DoesNotExist:
#             raise serializers.ValidationError("Invalid invitation token.")
        
#         # Check if email already exists in this group
#         existing_stakeholder = Stakeholder.objects.filter(
#             email=email, 
#             group=stakeholder_group
#         ).first()
        
#         data['stakeholder_group'] = stakeholder_group
#         data['existing_stakeholder'] = existing_stakeholder
        
#         return data

class EmailSubmissionSerializer(serializers.Serializer):
    """Serializer for email submission in invitation process."""
    email = serializers.EmailField()
    token = serializers.UUIDField()  # StakeholderGroup.invitation_token

    def validate(self, attrs):
        # normalize email
        email = (attrs.get("email") or "").strip().lower()
        token = attrs.get("token")

        # find active group via invitation token
        try:
            stakeholder_group = StakeholderGroup.objects.get(
                invitation_token=token,
                is_active=True,
            )
        except StakeholderGroup.DoesNotExist:
            raise serializers.ValidationError({"token": ["Invalid invitation token."]})

        # existing Stakeholder in this group?
        existing_stakeholder = (
            Stakeholder.objects
            .filter(email__iexact=email, group=stakeholder_group)
            .select_related("user")
            .first()
        )

        # existing Invitation in this group?
        existing_invitation = (
            StakeholderInvitation.objects
            .filter(email__iexact=email, stakeholder_group=stakeholder_group)
            .select_related("stakeholder")
            # no created_at field on your model; order by most recent activity you have
            .order_by("-clicked_at", "-sent_at", "-id")
            .first()
        )

        attrs.update({
            "email": email,
            "stakeholder_group": stakeholder_group,
            "existing_stakeholder": existing_stakeholder,
            "existing_invitation": existing_invitation,
        })
        return attrs
# class StakeholderRegistrationSerializer(serializers.Serializer):
#     """Serializer for stakeholder registration"""
#     # email = serializers.EmailField(read_only=True)  # Email is already provided from previous step
#     email = serializers.EmailField()
#     first_name = serializers.CharField(max_length=100)
#     last_name = serializers.CharField(max_length=100)
#     token = serializers.UUIDField()
    
#     def validate(self, data):
#         # Validate token and get stakeholder group
#         try:
#             # stakeholder_group = StakeholderGroup.objects.get(
#             #     invitation_token=data['token'], 
#             #     is_active=True
#             # )
#              stakeholder = Stakeholder.objects.get(
#                 email=data['email'], 
#                 # is_active=True
#             )
#         except Stakeholder.DoesNotExist:
#             raise serializers.ValidationError("Stakeholder not found.")
        
#         data['stakeholder_group'] = stakeholder_group
        
#         return data
    
#     def create(self, validated_data):
#         # stakeholder_group = validated_data['stakeholder_group']
        
#         # Get email from the stakeholder that was created in the email submission step
#         # We need to get this from context or pass it separately
#         # email = self.context.get('email')
#         email = validated_data['email']
#         if not email:
#             raise serializers.ValidationError("Email is required for registration.")
        
#         # Update existing stakeholder with registration details
#         # print(f"stakeholder_group - {stakeholder_group}")
#         print(f"email - {email}")
#         print(f"token - {validated_data['token']}")
#         try:
#             stakeholder = Stakeholder.objects.get(
#                 email=email,
#                 # group=stakeholder_group,
#                 is_registered=False
#             )
            
      
#             stakeholder.first_name = validated_data['first_name']
#             stakeholder.last_name = validated_data['last_name']
#             stakeholder.is_registered = True
#             stakeholder.save()
        
#         except Stakeholder.DoesNotExist:
#             raise serializers.ValidationError("Stakeholder not found or already registered.")
        
#         except Exception as e:
#             print(f"errort --- {e}")
#             raise serializers.ValidationError(f"Error : {e}")
#         # Update stakeholder invitation status to email_verified
#         stakeholder_invitation = StakeholderInvitation.objects.filter(
#             email=email,
#             # stakeholder_group=stakeholder_group
#         ).first()
        
#         if stakeholder_invitation:
#             stakeholder_invitation.status = 'email_verified'
#             stakeholder_invitation.email_verified_at = timezone.now()
#             stakeholder_invitation.save()
        
#         return stakeholder
class StakeholderRegistrationSerializer(serializers.Serializer):
    """Serializer for stakeholder registration."""
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100)
    token = serializers.UUIDField()   

    def validate(self, data):
        try:
            print(f"data['token']---{data['token']}")
            stakeholder = Stakeholder.objects.get(
                id=data['token'],
                is_registered=False
            )
            print(f"stakeholder...")
        except Stakeholder.DoesNotExist:

            raise serializers.ValidationError({
                "token": ["Invalid or expired invitation token."]
            })
        except Exception as e:
            print(e)
        # Email is now for informational purposes only
        data['stakeholder'] = stakeholder
        
        return data
        
     
    def create(self, validated_data):
        stakeholder = validated_data['stakeholder']
     
        stakeholder.first_name = validated_data['first_name']
        stakeholder.last_name = validated_data['last_name']
        stakeholder.is_registered = True
        stakeholder.save()

        # Optionally update invitation status
        invitation = StakeholderInvitation.objects.filter(
            stakeholder=stakeholder
        ).first()
        if invitation:
            invitation.status = 'email_verified'
            invitation.email_verified_at = timezone.now()
            invitation.save()

        return stakeholder

# class StakeholderApprovalSerializer(serializers.ModelSerializer):
#     """Serializer for stakeholder approval by client admin"""
#     class Meta:
#         model = Stakeholder
#         fields = ['id', 'status']
#         read_only_fields = ['id']
    
#     def validate_status(self, value):
#         if value not in ['approved', 'rejected']:
#             raise serializers.ValidationError("Status must be either 'approved' or 'rejected'.")
#         return value
    
#     def update(self, instance, validated_data):
#         status = validated_data.get('status')
        
#         if status == 'approved':
#             # Create user account
#             user, user_created = User.objects.get_or_create(
#                 email=instance.email,
#                 defaults={
#                     'username': instance.email,
#                     'first_name': instance.first_name,
#                     'last_name': instance.last_name,
#                     'role': 'stakeholder',
#                     'client': instance.group.client,
#                     'is_active': True
#                 }
#             )
            
#             # Update stakeholder
#             instance.user = user
#             instance.is_registered = True
#             instance.status = 'approved'
#             instance.save()
            
#             # Update invitation status
#             invitation = StakeholderInvitation.objects.filter(
#                 email=instance.email,
#                 stakeholder_group=instance.group
#             ).first()
            
#             if invitation:
#                 invitation.status = 'completed'
#                 invitation.completed_at = timezone.now()
#                 invitation.save()
        
#         else:  # rejected
#             instance.status = 'rejected'
#             instance.save()
            
#             # Update invitation status
#             invitation = StakeholderInvitation.objects.filter(
#                 email=instance.email,
#                 stakeholder_group=instance.group
#             ).first()
            
#             if invitation:
#                 invitation.status = 'expired'
#                 invitation.save()
        
#         return instance
from django.db import transaction
from core_apps.esg.models import ESGQuestion, ESGQuestionResponse

class StakeholderApprovalSerializer(serializers.ModelSerializer):
    """Serializer for stakeholder approval by client admin"""
    class Meta:
        model = Stakeholder
        fields = ['id', 'status']
        read_only_fields = ['id']
    
    def validate_status(self, value):
        if value not in ['approved', 'rejected']:
            raise serializers.ValidationError("Status must be either 'approved' or 'rejected'.")
        return value
    
    @transaction.atomic
    def update(self, instance, validated_data):
        status = validated_data.get('status')
        
        if status == 'approved':
            # Create user account
            user, user_created = User.objects.get_or_create(
                email=instance.email,
                defaults={
                    'username': instance.email,
                    'first_name': instance.first_name,
                    'last_name': instance.last_name,
                    'role': 'stakeholder',
                    'client': instance.group.client,
                    'is_active': True
                }
            )
            
            # Update stakeholder
            instance.user = user
            instance.is_registered = True
            instance.status = 'approved'
            instance.save()
            
            # Update invitation status
            invitation = StakeholderInvitation.objects.filter(
                email=instance.email,
                stakeholder_group=instance.group
            ).first()
            
            if invitation:
                invitation.status = 'completed'
                invitation.completed_at = timezone.now()
                invitation.save()
            
            # Create ESG Question Responses for all active questions
            self._create_esg_question_responses(user)
        
        else:  # rejected
            instance.status = 'rejected'
            instance.save()
            
            # Update invitation status
            invitation = StakeholderInvitation.objects.filter(
                email=instance.email,
                stakeholder_group=instance.group
            ).first()
            
            if invitation:
                invitation.status = 'expired'
                invitation.save()
        
        return instance
    
    def _create_esg_question_responses(self, user):
        """Create ESG question responses for the approved stakeholder"""
        try:
            # Get all active ESG questions
            esg_questions = ESGQuestion.objects.filter(is_active=True)
            
            # Create responses for each question
            responses_to_create = []
            for question in esg_questions:
                # Check if response already exists (avoid duplicates)
                if not ESGQuestionResponse.objects.filter(question=question, user=user).exists():
                    response = ESGQuestionResponse(
                        question=question,
                        user=user,
                        questionnaire_type='stakeholder',
                        priority=None,   
                        status_quo=None,   
                        status='draft'   
                    )
                    responses_to_create.append(response)
            
            # Bulk create for better performance
            if responses_to_create:
                ESGQuestionResponse.objects.bulk_create(responses_to_create)
                print(f"Created {len(responses_to_create)} ESG question responses for user {user.email}")
        
        except Exception as e:
            print(f"Error creating ESG question responses: {e}")
          

class UpdatedStakeholderSerializer(serializers.ModelSerializer):
    """Serializer for stakeholder details"""
    group_name = serializers.CharField(source='group.name', read_only=True)
    company_name = serializers.CharField(source='group.client.company_name', read_only=True)
    
    class Meta:
        model = Stakeholder
        fields = [
            'id', 'email', 'first_name', 'last_name', 
            'group_name', 'company_name', 'is_registered', 
            'status', 'created_at', 'last_login'
        ]
        read_only_fields = [
            'id', 'group_name', 'company_name', 
            'created_at', 'last_login'
        ]


# ----------------- updated code : August 18, 2025 Client Admin ---------
from datetime import timedelta
from core_apps.user_auth.models import User as UserData
from django.utils.crypto import get_random_string
try:
    from core_apps.esg.models import ESGYear, ESGQuestion, ESGQuestionResponse
    ESG_AVAILABLE = True
except ImportError:
    ESG_AVAILABLE = False
    logger.warning("ESG model not available")
    print(f"--- ESG not available ---")

try:
    from core_apps.authentication.models import StakeholderLoginToken  # Adjust import path as needed
    LOGIN_TOKEN_AVAILABLE = True
except ImportError:
    LOGIN_TOKEN_AVAILABLE = False
    logger.warning("StakeholderLoginToken model not available")

# class CreateStakeholderSerializer(serializers.Serializer):
#     email = serializers.EmailField(validators=[EmailValidator()])
#     first_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
#     last_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
#     send_invitation = serializers.BooleanField(default=True)

#     def validate_email(self, value):
#         group_id = self.context.get('group_id')
        
#         # Check if stakeholder already exists in this group
#         if Stakeholder.objects.filter(email=value, group_id=group_id).exists():
#             raise serializers.ValidationError(
#                 "A stakeholder with this email already exists in this group."
#             )
        
#         # Check if there's already a pending invitation for this group
#         if StakeholderInvitation.objects.filter(
#             email=value, 
#             stakeholder_group_id=group_id,
#             status__in=['sent', 'clicked', 'email_verified']
#         ).exists():
#             raise serializers.ValidationError(
#                 "A pending invitation already exists for this email in this group."
#             )
        
#         return value

#     def create(self, validated_data):
#         group_id = self.context.get('group_id')
#         request_user = self.context['request'].user
        
#         group = StakeholderGroup.objects.get(id=group_id)
        
#         # Generate auto password for user creation
#         auto_pwd = get_random_string(length=12)
        
#         # Create stakeholder with approved status if created by admin
#         stakeholder = Stakeholder.objects.create(
#             email=validated_data['email'],
#             first_name=validated_data.get('first_name', ''),
#             last_name=validated_data.get('last_name', ''),
#             group=group,
#             status='approved',  # Auto-approve when created by admin
#             is_registered=True
#         )
        
#         # Create user account for the stakeholder
#         try:
#             user_obj = UserData.objects.create_user(
#                 email=stakeholder.email,
#                 first_name=stakeholder.first_name,
#                 last_name=stakeholder.last_name,
#                 password=auto_pwd,
#                 role="stakeholder",   
#                 client=stakeholder.group.client,
#                 is_active=True,
#             )
            
#             # Link stakeholder to user
#             stakeholder.user = user_obj
#             stakeholder.is_registered = True
#             stakeholder.save()
            
#             # Create ESG responses for the user
#             if ESG_AVAILABLE:
#                 self.create_esg_responses_for_user(user_obj)
            
#             logger.info(f"Successfully created user and linked to stakeholder: {stakeholder.email}")
            
#         except Exception as e:
#             logger.error(f"Failed to create user for stakeholder {stakeholder.email}: {e}")
#             # Optionally, you might want to rollback stakeholder creation or handle this differently
#             raise serializers.ValidationError(f"Failed to create user account: {str(e)}")
        
#         # Create invitation if requested
#         if validated_data.get('send_invitation', True):
#             expires_at = timezone.now() + timedelta(days=7)  # 7 days expiry
#             StakeholderInvitation.objects.create(
#                 stakeholder_group=group,
#                 email=validated_data['email'],
#                 sent_by=request_user,
#                 expires_at=expires_at,
#                 stakeholder=stakeholder,
#                 status='delivered'
#             )
        
#         return stakeholder

#     def create_esg_responses_for_user(self, user):
#         """
#         Create ESGQuestionResponse records for a stakeholder user
#         """
#         if not ESG_AVAILABLE:
#             logger.warning("ESG models not available, skipping ESG response creation")
#             return []
            
#         # Get current ESG year
#         current_year = ESGYear.get_current_year()
        
#         if not current_year:
#             logger.warning("No current ESG year found, skipping ESG response creation")
#             return []
        
#         # Get all active ESG questions for the current year
#         active_questions = ESGQuestion.objects.filter(
#             year=current_year,
#             is_active=True
#         ).select_related('category')
        
#         if not active_questions.exists():
#             logger.warning(f"No active ESG questions found for year {current_year.year}")
#             return []
        
#         # Create ESGQuestionResponse records
#         responses_to_create = []
#         for question in active_questions:
#             response = ESGQuestionResponse(
#                 question=question,
#                 user=user,
#                 questionnaire_type='stakeholder',
#                 status='draft'
#             )
#             responses_to_create.append(response)
        
#         try:
#             # Bulk create for better performance
#             created_responses = ESGQuestionResponse.objects.bulk_create(
#                 responses_to_create, 
#                 ignore_conflicts=True
#             )
#             logger.info(f"Created {len(responses_to_create)} ESG question responses for {user.email}")
#             return created_responses
#         except Exception as e:
#             logger.error(f"Failed to create ESG responses for {user.email}: {e}")
#             return []
        

class CreateStakeholderSerializer(serializers.Serializer):
    email = serializers.EmailField(validators=[EmailValidator()])
    first_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    send_invitation = serializers.BooleanField(default=True)
    send_login_link = serializers.BooleanField(default=True)  # New field for login link

    def validate_email(self, value):
        group_id = self.context.get('group_id')
        
        # Check if stakeholder already exists in this group
        if Stakeholder.objects.filter(email=value, group_id=group_id).exists():
            raise serializers.ValidationError(
                "A stakeholder with this email already exists in this group."
            )
        
        # Check if there's already a pending invitation for this group
        if StakeholderInvitation.objects.filter(
            email=value, 
            stakeholder_group_id=group_id,
            status__in=['sent', 'clicked', 'email_verified']
        ).exists():
            raise serializers.ValidationError(
                "A pending invitation already exists for this email in this group."
            )
        
        return value

    def create(self, validated_data):
        group_id = self.context.get('group_id')
        request_user = self.context['request'].user
        request = self.context['request']
        
        group = StakeholderGroup.objects.get(id=group_id)
        
        # Generate auto password for user creation
        auto_pwd = get_random_string(length=12)
        
        # Create stakeholder with approved status if created by admin
        stakeholder = Stakeholder.objects.create(
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            group=group,
            status='approved',  # Auto-approve when created by admin
            is_registered=True
        )
        
        # Create user account for the stakeholder
        try:
            user_obj = UserData.objects.create_user(
                email=stakeholder.email,
                first_name=stakeholder.first_name,
                last_name=stakeholder.last_name,
                password=auto_pwd,
                role="stakeholder",   
                client=stakeholder.group.client,
                is_active=True,
            )
            
            # Link stakeholder to user
            stakeholder.user = user_obj
            stakeholder.is_registered = True
            stakeholder.save()
            
            # Create ESG responses for the user
            if ESG_AVAILABLE:
                self.create_esg_responses_for_user(user_obj)
            
            logger.info(f"Successfully created user and linked to stakeholder: {stakeholder.email}")
            
        except Exception as e:
            logger.error(f"Failed to create user for stakeholder {stakeholder.email}: {e}")
            # Optionally, you might want to rollback stakeholder creation or handle this differently
            raise serializers.ValidationError(f"Failed to create user account: {str(e)}")
        
        # Create invitation if requested
        stakeholder_invitation = None
        if validated_data.get('send_invitation', True):
            pass
            # expires_at = timezone.now() + timedelta(days=7)  # 7 days expiry
            # stakeholder_invitation = StakeholderInvitation.objects.create(
            #     stakeholder_group=group,
            #     email=validated_data['email'],
            #     sent_by=request_user,
            #     expires_at=expires_at,
            #     stakeholder=stakeholder,
            #     status='sent'
            # )
        
        # Create login token and send login link if requested
        if validated_data.get('send_login_link', True) and LOGIN_TOKEN_AVAILABLE:
            self.create_and_send_login_token(stakeholder, stakeholder_invitation, request)
        
        return stakeholder

    def create_and_send_login_token(self, stakeholder, stakeholder_invitation, request):
        """Create login token and send login link email"""
        try:
            from django.core.mail import send_mail
            from .views import generate_stakeholder_login_email  # Adjust import as needed
            
            # Create new login token
            login_token_obj = StakeholderLoginToken.objects.create(
                stakeholder=stakeholder,
                stakeholder_invitation=stakeholder_invitation,
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
            )
            
            login_url = login_token_obj.get_login_url()
            logger.info(f"Generated login token for {stakeholder.email}: {login_token_obj.token}")
            
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
                    recipient_list=[stakeholder.email],
                    fail_silently=False,
                )
                
                logger.info(f"Login link sent successfully to {stakeholder.email}")
                
            except Exception as e:
                logger.error(f"Failed to send login email to {stakeholder.email}: {e}")
                # Mark token as used since email failed
                login_token_obj.mark_as_used()
                raise
                
        except Exception as e:
            logger.error(f"Failed to create login token for {stakeholder.email}: {e}")
            # Don't fail the entire stakeholder creation if login token fails
            pass

    def get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def create_esg_responses_for_user(self, user):
        """
        Create ESGQuestionResponse records for a stakeholder user
        """
        if not ESG_AVAILABLE:
            logger.warning("ESG models not available, skipping ESG response creation")
            return []
            
        # Get current ESG year
        current_year = ESGYear.get_current_year()
        
        if not current_year:
            logger.warning("No current ESG year found, skipping ESG response creation")
            return []
        
        # Get all active ESG questions for the current year
        active_questions = ESGQuestion.objects.filter(
            year=current_year,
            is_active=True
        ).select_related('category')
        
        if not active_questions.exists():
            logger.warning(f"No active ESG questions found for year {current_year.year}")
            return []
        
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
        
        try:
            # Bulk create for better performance
            created_responses = ESGQuestionResponse.objects.bulk_create(
                responses_to_create, 
                ignore_conflicts=True
            )
            logger.info(f"Created {len(responses_to_create)} ESG question responses for {user.email}")
            return created_responses
        except Exception as e:
            logger.error(f"Failed to create ESG responses for {user.email}: {e}")
            return []
        




class UpdatedStakeholderSerializer(serializers.ModelSerializer):
    group = serializers.SerializerMethodField()
    
    class Meta:
        model = Stakeholder
        fields = [
            'id', 'email', 'first_name', 'last_name', 'group',
            'is_registered', 'status', 'created_at', 'last_login'
        ]
    
    def get_group(self, obj):
        return {
            'id': str(obj.group.id),
            'name': obj.group.name
        }

class UpdatedStakeholderGroupSerializer(serializers.ModelSerializer):
    invite_url = serializers.SerializerMethodField()
    class Meta:
        model = StakeholderGroup
        fields = ['id', 'name', 'is_active', 'invitation_token','invite_url','created_at']
    def get_invite_url(self, obj):
    
        return obj.get_invite_full_url()

 

# ------------------- STAKEHOLDER GROUPS ACCEPT, PENDING AND REJECTING --------------------
from django.utils import timezone

class StakeholderGroupSimpleSerializer(serializers.ModelSerializer):
    """Simple serializer for stakeholder group info"""
    class Meta:
        model = StakeholderGroup
        fields = ['id', 'name']

class PendingStakeholderSerializer(serializers.ModelSerializer):
    """Serializer for pending stakeholders list"""
    group = StakeholderGroupSimpleSerializer(read_only=True)
    full_name = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    days_since_created = serializers.SerializerMethodField()
    
    class Meta:
        model = Stakeholder
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'group', 'status', 'status_display', 'created_at', 
            'days_since_created', 'is_registered', 'last_login'
        ]
    
    def get_full_name(self, obj):
        """Get full name of stakeholder"""
        if obj.first_name and obj.last_name:
            return f"{obj.first_name} {obj.last_name}"
        elif obj.first_name:
            return obj.first_name
        elif obj.last_name:
            return obj.last_name
        return obj.email.split('@')[0]  # Use email prefix if no name
    
    def get_days_since_created(self, obj):
        """Calculate days since stakeholder was created"""
        
        delta = timezone.now() - obj.created_at
        return delta.days

class StakeholderApprovalSerializer(serializers.Serializer):
    """Serializer for stakeholder approval/rejection"""
    reason = serializers.CharField(max_length=500, required=False, allow_blank=True)
    send_notification = serializers.BooleanField(default=True)