# core_app/serializers.py

from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.utils.translation import gettext_lazy as _
from django.db import transaction
from django.utils import timezone
from django.db.models import Q # For OR queries in validations

# Import your models
from .models import Company, ESGCategory, ESGQuestion, \
                    StakeholderGroup, StakeholderUser, ESGResponse, \
                    StakeholderInvitation, AuditLog, Product

User = get_user_model() # Get the currently active user model

# --- Authentication and User Related Serializers ---
class UserSerializer(serializers.ModelSerializer):
    company_name = serializers.CharField(source='company.name', read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 
                 'role', 'company', 'company_name', 'is_active', 'created_at']
        read_only_fields = ['id', 'created_at']

class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 
                 'password', 'password_confirm', 'role', 'company']
        
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        return user
class AuthTokenSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(
        label=_("Password"),
        style={'input_type': 'password'},
        trim_whitespace=False,
        write_only=True
    )
    token = serializers.CharField(label=_("Token"), read_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            # Authenticate with the custom backend (email as username)
            user = authenticate(request=self.context.get('request'), email=email, password=password)
            if not user:
                msg = _('Unable to log in with provided credentials.')
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = _('Must include "email" and "password".')
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'role', 'company', 'is_active', 'date_joined')
        read_only_fields = ('id', 'date_joined')

# --- Company and Stakeholder Management Serializers ---

# class CompanySerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Company
#         fields = ('id', 'name')
#         read_only_fields = ('id',)

class CompanySerializer(serializers.ModelSerializer):
    products = serializers.SerializerMethodField()
    total_users = serializers.SerializerMethodField()
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    
    class Meta:
        model = Company
        fields = ['id', 'name', 'email', 'phone', 'address', 
                 'contact_person_name', 'contact_person_email', 'contact_person_phone',
                 'products', 'total_users', 'is_active', 'created_at', 'created_by_name']
        read_only_fields = ['id', 'created_at']
    
    def get_products(self, obj):
        company_products = Product.objects.filter(company=obj, is_active=True)
        return [{'id': cp.product.id, 'name': cp.product.name, 'type': cp.product.type} 
                for cp in company_products]
    
    def get_total_users(self, obj):
        return obj.users.filter(is_active=True).count()



# class StakeholderGroupSerializer(serializers.ModelSerializer):
#     # This serializer is used for displaying/managing groups by admins.
#     # The 'invite_token' is read-only here as it's system-generated.
#     company_name = serializers.CharField(source='company.name', read_only=True)

#     class Meta:
#         model = StakeholderGroup
#         fields = ('id', 'name', 'description', 'company', 'company_name', 'invite_token', 'is_active', 'created_by', 'created_at')
#         read_only_fields = ('id', 'invite_token', 'created_by', 'created_at')

class StakeholderGroupSerializer(serializers.ModelSerializer):
    users_count = serializers.SerializerMethodField()
    pending_invitations = serializers.SerializerMethodField()
    company_name = serializers.CharField(source='company.name', read_only=True)
    
    class Meta:
        model = StakeholderGroup
        fields = ['id', 'company', 'company_name', 'name', 'description', 
                 'users_count', 'pending_invitations', 'is_active', 'created_at']
        read_only_fields = ['id', 'created_at', 'invite_token']
    
    def get_users_count(self, obj):
        return obj.stakeholder_users.filter(is_active=True).count()
    
    def get_pending_invitations(self, obj):
        return obj.invitations.filter(status='pending').count()
    
class StakeholderInvitationSerializer(serializers.ModelSerializer):
    # For managing individual invitation records (e.g., viewing pending invites)
    stakeholder_group_name = serializers.CharField(source='stakeholder_group.name', read_only=True)
    company_name = serializers.CharField(source='stakeholder_group.company.name', read_only=True)
    sent_by_email = serializers.CharField(source='sent_by.email', read_only=True)

    class Meta:
        model = StakeholderInvitation
        fields = ('id', 'stakeholder_group', 'stakeholder_group_name', 'company_name',
                  'email', 'token', 'status', 'sent_by', 'sent_by_email', 'sent_at',
                  'expires_at', 'accepted_at')
        read_only_fields = ('id', 'token', 'status', 'sent_by', 'sent_by_email',
                            'sent_at', 'accepted_at')


class StakeholderInvitationCreateSerializer(serializers.ModelSerializer):
    emails = serializers.ListField(
        child=serializers.EmailField(),
        write_only=True
    )
    
    class Meta:
        model = StakeholderInvitation
        fields = ['stakeholder_group', 'emails']
    
    def create(self, validated_data):
        emails = validated_data.pop('emails')
        stakeholder_group = validated_data['stakeholder_group']
        sent_by = self.context['request'].user
        
        invitations = []
        for email in emails:
            invitation, created = StakeholderInvitation.objects.get_or_create(
                stakeholder_group=stakeholder_group,
                email=email,
                defaults={
                    'sent_by': sent_by,
                    'expires_at': timezone.now() + timedelta(days=7)
                }
            )
            if created:
                invitations.append(invitation)
        
        return invitations

class BulkStakeholderInvitationSerializer(serializers.Serializer):
    # This serializer is for the POST request to send bulk invitations.
    # It takes the ID of the stakeholder group and a list of emails.
    stakeholder_group = serializers.UUIDField(help_text="The UUID of the stakeholder group to invite to.")
    emails = serializers.ListField(
        child=serializers.EmailField(),
        min_length=1,
        help_text="A list of email addresses to invite."
    )
    expires_at = serializers.DateTimeField(required=False, allow_null=True, help_text="Optional: UTC datetime when invitations expire. Defaults to 7 days.")

    def validate_stakeholder_group(self, value):
        # Ensure the stakeholder group exists and is active
        try:
            group = StakeholderGroup.objects.get(id=value, is_active=True)
            self.context['stakeholder_group_obj'] = group # Store the object for later use in other validations
            return value
        except StakeholderGroup.DoesNotExist:
            raise serializers.ValidationError("Stakeholder group not found or is inactive.")

    def validate_emails(self, value):
        if not value:
            raise serializers.ValidationError("At least one email address is required.")
        if len(value) != len(set(value)): # Check for duplicates within the request list
            raise serializers.ValidationError("Duplicate email addresses found in the list.")

        group_obj = self.context.get('stakeholder_group_obj')
        if group_obj:
            # Efficiently check for existing StakeholderUser or PENDING StakeholderInvitation for this specific group
            # Use Q objects for OR query
            conflicting_users = User.objects.filter(
                email__in=[e.lower() for e in value], # Case-insensitive email comparison
                stakeholder_users__stakeholder_group=group_obj # User already linked to this group
            ).values_list('email', flat=True)

            conflicting_invites = StakeholderInvitation.objects.filter(
                email__in=[e.lower() for e in value], # Case-insensitive email comparison
                stakeholder_group=group_obj,
                status=StakeholderInvitation.Status.PENDING # User has a pending invite for this group
            ).values_list('email', flat=True)

            all_conflicting_emails = set(list(conflicting_users) + list(conflicting_invites))

            if all_conflicting_emails:
                raise serializers.ValidationError(
                    f"The following emails are already part of this group or have pending invitations: {', '.join(sorted(list(all_conflicting_emails)))}"
                )
        return value

# --- ESG Related Serializers ---

class ESGCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ESGCategory
        fields = ('id', 'name', 'description', 'is_active')
        read_only_fields = ('id')

class ESGQuestionSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.name', read_only=True)

    class Meta:
        model = ESGQuestion
        fields = ('id', 'category', 'category_name', 'question_text', 'question_type', 'options', 'is_active',)
        read_only_fields = ('id',)

class ESGResponseSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True)
    question_text = serializers.CharField(source='question.question_text', read_only=True)
    company_name = serializers.CharField(source='company.name', read_only=True)

    class Meta:
        model = ESGResponse
        fields = ('id', 'user', 'user_email', 'company', 'company_name', 'question', 'question_text',
                  'answer', 'priority', 'status', 'comment',)
        read_only_fields = ('id', 'user', 'company',)

    def create(self, validated_data):
        # Set user and company automatically based on the request user context
        validated_data['user'] = self.context['request'].user
        validated_data['company'] = self.context['request'].user.company
        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Ensure user and company are not changed on update
        validated_data.pop('user', None)
        validated_data.pop('company', None)
        return super().update(instance, validated_data)


# --- Stakeholder Registration Serializer (Unified for new/existing users and different invite types) ---

class StakeholderRegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=150)
    last_name = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    # This token is what's passed from the individual email invitation link
    invitation_token = serializers.UUIDField(write_only=True, required=False, allow_null=True)
    # This ID is for the general group join link, usually passed as a query param
    group_id = serializers.UUIDField(write_only=True, required=False, allow_null=True)

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError({"password_confirm": "Passwords do not match."})

        invitation_token = data.get('invitation_token')
        group_id = data.get('group_id')

        # Ensure at least one token/ID is provided
        if not invitation_token and not group_id:
            raise serializers.ValidationError("Either 'invitation_token' or 'group_id' is required to register/login.")

        stakeholder_group_obj = None
        invitation_obj = None

        if invitation_token:
            # If invitation token is present, it takes precedence
            try:
                invitation_obj = StakeholderInvitation.objects.get(token=invitation_token)
                if invitation_obj.status != StakeholderInvitation.Status.PENDING:
                    raise serializers.ValidationError({"invitation_token": "This invitation has already been used or is invalid."})
                if invitation_obj.expires_at and invitation_obj.expires_at < timezone.now():
                    invitation_obj.status = StakeholderInvitation.Status.EXPIRED # Mark expired
                    invitation_obj.save() # Save the status update
                    raise serializers.ValidationError({"invitation_token": "This invitation link has expired."})

                # For individual invitations, the email provided must match the invited email
                if data['email'].lower() != invitation_obj.email.lower():
                    raise serializers.ValidationError({"email": "The email provided does not match the invited email address."})

                stakeholder_group_obj = invitation_obj.stakeholder_group
                self.context['invitation'] = invitation_obj # Store invitation for later use in view/create method

            except StakeholderInvitation.DoesNotExist:
                raise serializers.ValidationError({"invitation_token": "Invalid or non-existent invitation token."})

        elif group_id:
            # If only group_id is present (general group join link)
            try:
                stakeholder_group_obj = StakeholderGroup.objects.get(id=group_id, is_active=True)
            except StakeholderGroup.DoesNotExist:
                raise serializers.ValidationError({"group_id": "Invalid or inactive stakeholder group ID."})

        self.context['stakeholder_group'] = stakeholder_group_obj # Store for later use

        # Check if email is already registered, but only if it's NOT an invitation_token flow
        # In invitation_token flow, we expect the email to potentially exist for an existing user logging in
        if User.objects.filter(email=data['email']).exists() and not invitation_token:
            existing_user = User.objects.get(email=data['email'])
            # If user exists and is already in this group via a general link, prevent double registration
            if StakeholderUser.objects.filter(user=existing_user, stakeholder_group=stakeholder_group_obj).exists():
                raise serializers.ValidationError({"email": "This email is already a member of this stakeholder group. Please log in directly."})

        return data

    @transaction.atomic
    def create(self, validated_data):
        stakeholder_group = self.context['stakeholder_group']
        invitation = self.context.get('invitation') # Will be None if group_id was used

        user = User.objects.create_user(
            username=validated_data['email'], # Using email as username for simplicity
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            role=User.UserRole.STAKEHOLDER, # Assign STAKEHOLDER role
            company=stakeholder_group.company, # Link to the company of the group
            is_active=True
        )

        # Create the StakeholderUser entry to link the user to the specific group
        StakeholderUser.objects.create(
            user=user,
            stakeholder_group=stakeholder_group
        )

        # If an invitation was used, mark it as accepted
        if invitation:
            invitation.status = StakeholderInvitation.Status.ACCEPTED
            invitation.accepted_at = timezone.now()
            invitation.save()

        return user
    

class StakeholderUserSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    group_name = serializers.CharField(source='stakeholder_group.name', read_only=True)
    
    class Meta:
        model = StakeholderUser
        fields = ['id', 'stakeholder_group', 'group_name', 'user', 
                 'joined_at', 'is_active']
        read_only_fields = ['id', 'joined_at']