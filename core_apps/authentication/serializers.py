from rest_framework import serializers
from django.contrib.auth import authenticate
from django.core.validators import EmailValidator
from .models import (  Stakeholder, 
    StakeholderGroup, InvitationToken, LoginSession, StakeholderInvitation
)

from core_apps.clients.models import Client
from django.conf import settings
User = settings.AUTH_USER_MODEL
from loguru import logger


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

from django.utils import timezone
class InvitationValidationSerializer(serializers.Serializer):
    """Serializer to validate invitation token"""
    token = serializers.UUIDField()
    client_id = serializers.UUIDField()
    
    
        
    def validate_token_and_client(self,value):
        try:
            request = self.context.get('request')
            stakeholder_group = None
            if request:
                token = request.data.get('token')
                client_id = request.data.get('client_id') or None
                stakeholder_group = StakeholderGroup.objects.get(
                    invitation_token=token,
                    # client=client_id, 
                    is_active=True, 
                    disable_the_invitation=False,
                )
           
            return value
        
        except StakeholderGroup.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired invitation token.")



class EmailSubmissionSerializer(serializers.Serializer):
    """Serializer for email submission in invitation process."""
    email = serializers.EmailField()
    token = serializers.UUIDField()  # StakeholderGroup.invitation_token
    client_id = serializers.UUIDField()

    def validate_email(self, value):
        """Validate email uniqueness"""
        email = value.lower().strip()
        if Client.objects.filter(email=email).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        
        return email
    
    def validate(self, attrs):
        # normalize email
        email = (attrs.get("email") or "").strip().lower()
        token = attrs.get("token")
        client_id = attrs.get("client_id")
        # find active group via invitation token
        try:
            
            stakeholder_group = StakeholderGroup.objects.get(
                invitation_token=token,
                is_active=True,
                disable_the_invitation=False
            )
            client_data = Client.objects.get(
                id=client_id,
                is_active=True,
                # disable_the_invitation=False
            )
        except StakeholderGroup.DoesNotExist:
            raise serializers.ValidationError({"token": [f"Invalid invitation token."]})

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
            .order_by("-clicked_at", "-sent_at", "-id")
            .first()
        )

        attrs.update({
            "email": email,
            "client":client_data,
            "stakeholder_group": stakeholder_group,
            "existing_stakeholder": existing_stakeholder,
            "existing_invitation": existing_invitation,
        })
        return attrs



class StakeholderRegistrationSerializer(serializers.Serializer):
    """Serializer for stakeholder registration."""
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100)
    # stakeholder_id = serializers.UUIDField() # this is the stakeholder id pass by payload
    token = serializers.UUIDField() # this is an id of the stakeholder.
 
    def validate(self, data):
         
        try:
            request = self.context.get('request')
  
            print(f"data-----{data}")
            stakeholder = Stakeholder.objects.get(
                id=data['token'],
                is_registered=False,
                # email__iexact=request.data.get('email'),
            )

            if stakeholder:
                print(f"stakeholder=>{stakeholder.email}, get email {data['email']}, group - {stakeholder.group.id}")
                if stakeholder.email != data['email']:
                        # raise serializers.ValidationError(
                        #     "Email of the stakeholder is not match."
                        # )
                        
                        raise serializers.ValidationError(
                            "Email does not match."
                        )
                if not StakeholderGroup.objects.filter(invitation_token=stakeholder.group.invitation_token, is_active=True,disable_the_invitation=False,).first():
                        raise serializers.ValidationError(
                            "A stakeholder group is not exists."
                        )
      
        except Stakeholder.DoesNotExist:

            raise serializers.ValidationError({
                "token": ["Invalid or expired invitation token. {}"]
            })
        except Exception as e:
            raise serializers.ValidationError({
                "error": e,
                "status": 500
            })
            # print(f"erorr registration - {e} - s")
        
        data['stakeholder'] = stakeholder
        
        return data
        

    
    def create(self, validated_data):
        stakeholder = validated_data['stakeholder']
     
        stakeholder.first_name = validated_data['first_name']
        stakeholder.last_name = validated_data['last_name']
        # stakeholder.client = validated_data['client']
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


class StakeholderUserRegistrationSerializer(serializers.Serializer):
    """Serializer for stakeholder registration."""
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100)
    stakeholder_id = serializers.UUIDField() # this is the stakeholder id pass by payload
    token = serializers.UUIDField()
    group_id = serializers.UUIDField()
    client_id = serializers.UUIDField()
    

        
    def validate(self, data):
        request = self.context.get('request')
        try:
            if not StakeholderGroup.objects.filter(id=request.data.get('group_id'), is_active=True,disable_the_invitation=False,).exists():
                raise serializers.ValidationError(
                    "A stakeholder group is not exists."
                )
            
            if Stakeholder.objects.filter(email=request.data.get('email'), group_id=request.data.get('group_id')).exists():
                raise serializers.ValidationError(
                    "A stakeholder with this email already exists in this group."
                )
      
      
        except Exception as e:
            raise serializers.ValidationError({
                "error": f"Error Registering the user. {e}"
            })
        
        
        # data['stakeholder'] = stakeholder
        
        return data
 
   
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



class CreateStakeholderSerializer(serializers.Serializer):
    email = serializers.EmailField(validators=[EmailValidator()])
    first_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    send_invitation = serializers.BooleanField(default=True)
    # send_login_link = serializers.BooleanField(default=True)  # New field for login link

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
        clientid = self.context.get('clientid')
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
            is_registered=True,
            client=request_user.client,
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
            # pass
            expires_at = timezone.now() + timedelta(days=7)  # 7 days expiry
            stakeholder_invitation = StakeholderInvitation.objects.create(
                stakeholder_group=group,
                email=validated_data['email'],
                sent_by=request_user,
                expires_at=expires_at,
                stakeholder=stakeholder,
                status='sent'
            )
        
      
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

class AllStakeholderSerializer(serializers.ModelSerializer):
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




# ----------------------
from .models import StakeholderGroupTerramo, StakeholderGroupInvitationTerramo

class StakeholderGroupTerramoCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating stakeholder groups"""
    
    class Meta:
        model = StakeholderGroupTerramo
        fields = ['name', 'description', 'sort_order', 'is_active']
    
    def validate_name(self, value):
        request = self.context.get('request')
        if request and hasattr(request.user, 'role'):
            if request.user.role == 'terramo_admin':
                # Check for duplicate template names
                if StakeholderGroupTerramo.objects.filter(
                    name=value, client__isnull=True, template__isnull=True
                ).exists():
                    raise serializers.ValidationError("A global template with this name already exists")
            elif request.user.role == 'client_admin':
                # Check for duplicate names within client
                if StakeholderGroupTerramo.objects.filter(
                    name=value, client=request.user.client
                ).exists():
                    raise serializers.ValidationError("A group with this name already exists for your organization")
        return value


class StakeholderGroupTerramoSerializer(serializers.ModelSerializer):
    """Serializer for stakeholder groups"""
    
    group_type = serializers.ReadOnlyField()
    stakeholder_count = serializers.SerializerMethodField()
    # stakeholder_users = serializers.SerializerMethodField()
    
    client_name = serializers.CharField(source='client.company_name', read_only=True)
    template_name = serializers.CharField(source='template.name', read_only=True)
    can_add_stakeholders = serializers.SerializerMethodField()
    
    class Meta:
        model = StakeholderGroupTerramo
        fields = [
            'id', 'name', 'description', 'group_type', 'client', 'client_name',
            'template', 'template_name', 'is_active', 'sort_order',
            'stakeholder_count','can_add_stakeholders', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    

    
    def get_stakeholder_count(self, obj):
        request = self.context.get('request')
        if request and hasattr(request.user, 'role'):
            if request.user.role == 'terramo_admin':
                return obj.get_stakeholder_count()
            elif request.user.role == 'client_admin':
                if obj.is_template:
                    return obj.get_stakeholder_count_for_client(request.user.client)
                else:
                    return obj.get_stakeholder_count()
        return 0
    
    def get_can_add_stakeholders(self, obj):
        request = self.context.get('request')
        if request and hasattr(request.user, 'role'):
            if request.user.role == 'terramo_admin':
                return True
            elif request.user.role == 'client_admin':
                return obj.is_template or obj.client == request.user.client
        return False



# -- Invitations
class StakeholderGroupInvitationSerializer(serializers.ModelSerializer):
    """Serializer for stakeholder group invitations"""
    
    group_name = serializers.CharField(source='stakeholder_group.name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    invitation_url = serializers.SerializerMethodField()
    is_valid = serializers.ReadOnlyField()
    is_expired = serializers.ReadOnlyField()
    remaining_uses = serializers.ReadOnlyField()
    time_remaining = serializers.SerializerMethodField()
    
    class Meta:
        model = StakeholderGroupInvitationTerramo
        fields = [
            'id', 'stakeholder_group', 'group_name', 'token', 'created_by', 
            'created_by_name', 'created_at', 'expires_at', 'is_active',
            'max_uses', 'current_uses', 'remaining_uses', 'used_at', 
            'used_by_email', 'message', 'invitation_url', 'is_valid', 
            'is_expired', 'time_remaining'
        ]
        read_only_fields = [
            'id', 'token', 'created_at', 'current_uses', 'used_at', 'used_by_email'
        ]
    
    def get_invitation_url(self, obj):
        return obj.get_invitation_url()
    
    def get_time_remaining(self, obj):
        if obj.expires_at:
            now = timezone.now()
            if obj.expires_at > now:
                delta = obj.expires_at - now
                if delta.days > 0:
                    return f"{delta.days} days"
                else:
                    hours = delta.seconds // 3600
                    minutes = (delta.seconds % 3600) // 60
                    return f"{hours}h {minutes}m"
            return "Expired"
        return "No expiry"
    
    def validate_stakeholder_group(self, value):
        request = self.context.get('request')
        if request and hasattr(request.user, 'role'):
            if request.user.role == 'client_admin':
                # Client admin can only create invitations for groups they can use
                if not (value.is_template or value.client == request.user.client):
                    raise serializers.ValidationError(
                        'You can only create invitations for global templates or your own groups'
                    )
        return value
    
    def validate_expires_at(self, value):
        if value and value <= timezone.now():
            raise serializers.ValidationError("Expiry date must be in the future")
        return value
    


class InvitationAcceptSerializer(serializers.Serializer):
    """Serializer for accepting invitations"""
    
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=100, required=False)
    last_name = serializers.CharField(max_length=100, required=False)
    phone = serializers.CharField(max_length=20, required=False)
    organization = serializers.CharField(max_length=200, required=False)
    role_in_organization = serializers.CharField(max_length=100, required=False)
    client_id = serializers.UUIDField(required=False, help_text="Required for global templates")
    
    def validate_email(self, value):
        return value.lower()