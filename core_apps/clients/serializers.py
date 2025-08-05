from rest_framework import serializers
from .models import Invitation, ClientProduct, Client, ClientInvitation
from core_apps.products.models import Product
from django.utils import timezone
from core_apps.clients.models import Client, Invitation # Import Client model
from django.conf import settings 
from django.contrib.auth import get_user_model
from core_apps.clients.models import Invitation, InvitationStatus
User = settings.AUTH_USER_MODEL
Userobs = get_user_model()
from django.utils.translation import gettext_lazy as _
from django.db import transaction
from django.core.validators import EmailValidator
# from core_apps.stakeholder_analysis.models import StakeholderGroup
from core_apps.authentication.models import StakeholderGroup
import uuid
class InvitationSerializer(serializers.ModelSerializer):
    client_name = serializers.CharField(source='client.company_name', read_only=True)
    invited_by_username = serializers.CharField(source='invited_by.username', read_only=True)
    invite_url = serializers.SerializerMethodField()

    class Meta:
        model = Invitation
        fields = (
            'id', 'token', 'client', 'client_name', 'email', 'invited_by', 
            'invited_by_username', 'is_active', 'expires_at', 'sent_at', 
            'accepted_at', 'created_at', 'invite_url'
        )
        read_only_fields = ('token', 'invited_by', 'sent_at', 'accepted_at', 'created_at', 'updated_at', 'invite_url')

    def get_invite_url(self, obj):
        # This will use the model's method to generate the full invite URL for the frontend
        return obj.get_invite_url()

    def validate(self, data):
        # Ensure that only client admins can create invites for their own client
        # And superusers can create for any client
        request = self.context.get('request')
        
        if request and not request.user.is_superuser:
            # If not a superuser, they must be a clientAdmin and specify their own client
            if request.user.role == 'clientAdmin':
                if 'client' in data and data['client'] != request.user.client:
                    raise serializers.ValidationError("Client Admins can only create invitations for their own client.")
                # Automatically set the client for client admins if not explicitly provided
                data['client'] = request.user.client
            else:
                raise serializers.ValidationError("Only client admins or superusers can create invitations.")

        return data

    def create(self, validated_data):
        # Set the invited_by field automatically from the request user
        validated_data['invited_by'] = self.context['request'].user
        
        # Set a default expiration if not provided (e.g., 7 days)
        if 'expires_at' not in validated_data or not validated_data['expires_at']:
            validated_data['expires_at'] = timezone.now() + timezone.timedelta(days=7)
            
        return super().create(validated_data)
    


class StakeholderRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    
    class Meta:
        model = Userobs
        fields = ('username', 'password', 'password_confirm') # Email and client are from invitation

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError({"password_confirm": "Passwords do not match."})
        return data

    def create(self, validated_data):
        # This method is designed to be called by the invitation acceptance view
        # The email, client, and role will be set by the view based on the invitation
        user = Userobs.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            email=self.context.get('email'), 
            client=self.context.get('client'), 
            role='stakeholder' 
        )
        return user

class ClientSerializer(serializers.ModelSerializer):
    created_by_username = serializers.CharField(source='created_by.email', read_only=True) # Use email for username
    email = serializers.EmailField(required=True, help_text=_("Contact person's email for the client."))
    
    # New field to include the invitation URL in the response
    invite_link = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Client
        fields = [
            'id', 'company_name', 'date', 'company_photo', 'role',
            'contact_person_first_name', 'contact_person_last_name',
            'gender', 'year_of_birth', 'street', 'zip_code', 'location',
            'landline_number', 'mobile_phone_number', 'city', 'land',
            'email', 'miscellaneous', 'is_active', 'created_by', 'created_by_username',
            'created_at', 'updated_at', 'invite_link' # Include the new field here
        ]
        read_only_fields = ['created_by', 'created_at', 'updated_at']

    def validate_company_name(self, value):
        if Client.objects.filter(company_name__iexact=value, is_active=True).exists():
            raise serializers.ValidationError(_("A client with this company name already exists."))
        return value

    def create(self, validated_data):
        request = self.context.get('request')
        validated_data['created_by'] = request.user if request else None

        with transaction.atomic():
            client = super().create(validated_data)

            # 1. Create default StakeholderGroup for the new client
            StakeholderGroup.objects.create(
                client=client,
                name=f"{client.company_name} Stakeholders"
            )

            # 2. Create Invitation for the Client Admin
            expires_at = timezone.now() + timezone.timedelta(
                days=getattr(settings, 'INVITATION_EXPIRATION_DAYS', 1)
            )

            invitation = Invitation.objects.create(
                client=client,
                email=client.email, 
                invited_by=request.user,
                expires_at=expires_at,
                is_active=True,
                status=InvitationStatus.NOT_ACCEPTED
            )
            
            # Store the created invitation instance in the serializer's instance
            # so get_invite_link can access it.
            self._created_invitation = invitation 

        return client

    def get_invite_link(self, obj):
        # This method is called after the object is created/retrieved.
        # If this is a new client being created, we'll have the invitation stored.
        if hasattr(self, '_created_invitation'):
            return self._created_invitation.get_invite_url()
        # If this is a retrieve/list operation, try to find the invitation
        # (assuming there's one primary invitation per client for initial setup)
        # You might need more sophisticated logic if a client can have multiple active invites.
        latest_invitation = obj.invitations.filter(
            status__in=[InvitationStatus.NOT_ACCEPTED, InvitationStatus.ACCEPTED],
            is_active=True
        ).order_by('-created_at').first()
        
        if latest_invitation:
            return latest_invitation.get_invite_url()
        return None
    

class ClientCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating clients with invitation logic"""
    
    company_name = serializers.CharField(write_only=True)
    company_address = serializers.CharField(write_only=True, required=False, allow_blank=True)
    company_phone = serializers.CharField(write_only=True, required=False, allow_blank=True)
    company_website = serializers.URLField(write_only=True, required=False, allow_blank=True)
    
    class Meta:
        model = Client
        fields = [
            'id', 'contact_email', 'contact_name', 'contact_phone',
            'company_name', 'company_address', 'company_phone', 'company_website',
            'is_registered', 'created_at'
        ]
        read_only_fields = ['id', 'is_registered', 'created_at']
    
    def validate_contact_email(self, value):
        """Ensure contact email is unique"""
        if Client.objects.filter(contact_email=value).exists():
            raise serializers.ValidationError("Contact email must be unique per company.")
        return value
    
    def create(self, validated_data):
        """Create client with company and invitation"""
        request = self.context['request']
        
        # Validate user role
        if request.user.role != 'terramo_admin':
            raise serializers.ValidationError("Only Terramo Admin can create clients.")
        return 'ow?'
        # # Extract company data
        # company_data = {
        #     'name': validated_data.pop('company_name'),
        #     'address': validated_data.pop('company_address', ''),
        #     'phone': validated_data.pop('company_phone', ''),
        #     'website': validated_data.pop('company_website', ''),
        #     'created_by': request.user
        # }
        
        # # Create company
        # company = Company.objects.create(**company_data)
        
        # # Create client
        # client = Client.objects.create(company=company, **validated_data)
        
        # # Create invitation
        # invitation = Invitation.objects.create(
        #     client=client,
        #     invited_email=client.contact_email
        # )
        
        # # Create default stakeholder group
        # StakeholderGroup.objects.create(
        #     company=company,
        #     name='Management',
        #     description='Default management stakeholder group',
        #     is_default=True
        # )
        
        # return client

class ClientTestSerializers(serializers.ModelSerializer):
    # This field will be read-only and generated by the view/model
    invite_link = serializers.SerializerMethodField()

    class Meta:
        model = Client
        fields = ['id', 'client', 'token', 'created_at', 'expires_at', 'is_valid', 'invite_link']
        read_only_fields = ['id', 'client', 'token', 'created_at', 'expires_at', 'is_valid', 'invite_link']

    def get_invite_link(self, obj):
        # Construct the full invite link.
        # You'll need to replace 'yourdomain.com' with your actual frontend domain.
        # And '/invite/' with the actual path your frontend uses to handle invitations.
        return f"http://yourfrontend.com/invite/{obj.token}"




"""
-------------------------------------------------------------------
UPDATED CODE SERIALIZERS.py
---------------------------------------------------------
"""
from core_apps.products.serializers import ProductSerializer

class ClientProductSerializer(serializers.ModelSerializer):
    """Serializer for client-product relationships"""
    product = ProductSerializer(read_only=True)
    product_id = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = ClientProduct
        fields = [
            'id', 'product', 'product_id', 'purchased_at', 
            'expires_at', 'is_active'
        ]
        read_only_fields = ['id', 'purchased_at']
class ClientProductDataSerializer(serializers.ModelSerializer):
    """Serializer for client-product relationships"""
    product = ProductSerializer(read_only=True)
    product_id = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = ClientProduct
        fields = [
            'id', 'product', 'product_id', 'purchased_at', 
            'expires_at', 'is_active'
        ]
        read_only_fields = ['id', 'purchased_at']


# class ClientCreateDataSerializer(serializers.ModelSerializer):
#     """Serializer for creating clients with products and invitation"""
   
#     # Product selection (write-only)
#     # product_ids = serializers.ListField(
#     #     child=serializers.IntegerField(),
#     #     write_only=True,
#     #     required=False,
#     #     help_text="List of product IDs to associate with the client"
#     # )
#     product_ids = serializers.ListField(
#         child=serializers.UUIDField(),
#         write_only=True,
#         required=False,
#         help_text="List of product UUIDs to associate with the client"
#     )
    
#     # Client products (read-only for response)
#     client_products = ClientProductDataSerializer(
#         source='clientproduct_set',
#         many=True,
#         read_only=True
#     )
    
#     # Invitation details
#     send_invitation = serializers.BooleanField(
#         default=True, 
#         write_only=True,
#         help_text="Whether to send an invitation email"
#     )
    
#     invitation_expires_days = serializers.IntegerField(
#         default=30,
#         write_only=True,
#         help_text="Number of days until invitation expires"
#     )
#     raw_token = serializers.UUIDField(
#         write_only=True,
#         required=False,
#         help_text="token invitation"
#     )
#     # raw_token = serializers.UUIDField(write_only=True, required=False)

#     class Meta:
#         model = Client
#         fields = [
#             # Company Data
#             'id', 'company_name', 'date', 'company_photo', 'role',
            
#             # Contact Person
#             'contact_person_first_name', 'contact_person_last_name',
#             'gender', 'year_of_birth',
            
#             # Address Details
#             'street', 'zip_code', 'location', 'landline_number',
#             'mobile_phone_number', 'city', 'land', 'email',
            
#             # Other fields
#             'miscellaneous', 'is_active',
            
#             # Relations and special fields
#             'client_products', 'product_ids', 'send_invitation',
#             'invitation_expires_days', 'invitation_token', 'raw_token',
            
#             # Timestamps
#             'created_at', 'updated_at'
#         ]
#         read_only_fields = [
#             'id', 'invitation_token', 'created_at', 'updated_at'
#         ]
#         extra_kwargs = {
#             'email': {'validators': [EmailValidator()]},
#             'contact_person_first_name': {'required': True},
#             'year_of_birth': {'required': True},
#             'street': {'required': True},
#             'location': {'required': True},
#             'city': {'required': True},
#         }
    
#     def validate_email(self, value):
#         """Validate email uniqueness"""
#         email = value.lower().strip()
#         if self.instance:  # Update case
#             if Client.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
#                 raise serializers.ValidationError("A client with this email already exists.")
#         else:  # Create case
#             if Client.objects.filter(email=email).exists():
#                 raise serializers.ValidationError("A client with this email already exists.")
#         return email
    
#     def validate_year_of_birth(self, value):
#         """Validate year of birth"""
#         current_year = timezone.now().year
#         if value < 1900 or value > current_year - 18:
#             raise serializers.ValidationError(
#                 f"Year of birth must be between 1900 and {current_year - 18}"
#             )
#         return value
    
#     # def validate_product_ids(self, value):
#     #     """Validate that all product IDs exist"""
#     #     if value:
#     #         existing_products = Product.objects.filter(id__in=value)
#     #         if existing_products.count() != len(value):
#     #             invalid_ids = set(value) - set(existing_products.values_list('id', flat=True))
#     #             raise serializers.ValidationError(
#     #                 f"Invalid product IDs: {list(invalid_ids)}"
#     #             )
#     #     return value
    
    
#     def validate_product_ids(self, value):
#         """Ensure all product UUIDs exist in the database"""
#         existing_products = Product.objects.filter(id__in=value)
#         if existing_products.count() != len(value):
#             existing_ids = set(existing_products.values_list('id', flat=True))
#             invalid_ids = set(value) - existing_ids
#             raise serializers.ValidationError(
#                 f"Invalid product IDs: {list(invalid_ids)}"
#             )
#         return value
    
#     @transaction.atomic
#     def create(self, validated_data):
#         """Create client with products and invitation"""
#         try:
#             # generated_token = serializers.UUIDField(write_only=True, required=False)
#             product_ids = validated_data.pop('product_ids', [])
#             # print(f"product_ids => {product_ids}")
#             send_invitation = validated_data.pop('send_invitation', True)
#             invitation_expires_days = validated_data.pop('invitation_expires_days', 30)
        
#             raw_token = validated_data.pop('raw_token', uuid.uuid4())
#             print(f"raw_token => {raw_token}")
        
#             # Set created_by if available in context
#             request = self.context.get('request')
#             if request and hasattr(request, 'user'):
#                 validated_data['created_by'] = request.user
            
#             # Create client
#             client = Client.objects.create(**validated_data)
            
#             # create client invitation
#             ClientInvitation.objects.create(
#                 token=raw_token,
#                 client=client
#             )
#             # Create client-product relationships
#             if product_ids:
#                 client_products = []
#                 for product_id in product_ids:
#                     client_products.append(
#                         ClientProduct(
#                             client=client,
#                             product_id=product_id,
#                             purchased_at=timezone.now(),
#                             is_active=True
#                         )
#                     )
#                 ClientProduct.objects.bulk_create(client_products)
            
#             # Create invitation if requested
#             if send_invitation:

                
#                 expires_at = timezone.now() + timezone.timedelta(days=invitation_expires_days)
#                 Invitation.objects.create(
#                     client=client,
#                     email=client.email,
#                     token=raw_token,
#                     invited_by=request.user if request and hasattr(request, 'user') else None,
#                     expires_at=expires_at,
#                     sent_at=timezone.now(),
#                     status=InvitationStatus.NOT_ACCEPTED
#                 )
            
#             return client
        
#         except Exception as e:
#             # logger.error(f"Unexpected error creating client-product relationships: {str(e)}")
#             # raise serializers.ValidationError({
#             #     'product_ids': 'Error assigning products to client.'
#             # })
#             raise serializers.ValidationError({
#                 'error': str(e)  # thik 
#             })

class ClientCreateDataSerializer(serializers.ModelSerializer):
    """Serializer for creating clients with products and invitation"""

    product_ids = serializers.ListField(
        child=serializers.UUIDField(),
        write_only=True,
        required=False,
        help_text="List of product UUIDs to associate with the client"
    )

    client_products = ClientProductDataSerializer(
        source='clientproduct_set',
        many=True,
        read_only=True
    )

    send_invitation = serializers.BooleanField(
        default=True,
        write_only=True,
        help_text="Whether to send an invitation email"
    )

    invitation_expires_days = serializers.IntegerField(
        default=30,
        write_only=True,
        help_text="Number of days until invitation expires"
    )

    raw_token = serializers.UUIDField(
        write_only=True,
        required=False,
        help_text="token invitation"
    )

    # Expose the actual raw token used for the ClientInvitation (read-only)
    invitation_raw_token = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Client
        fields = [
            # Company Data
            'id', 'company_name', 'date', 'company_photo', 'role',

            # Contact Person
            'contact_person_first_name', 'contact_person_last_name',
            'gender', 'year_of_birth',

            # Address Details
            'street', 'zip_code', 'location', 'landline_number',
            'mobile_phone_number', 'city', 'land', 'email',

            # Other fields
            'miscellaneous', 'is_active',

            # Relations and special fields
            'client_products', 'product_ids', 'send_invitation',
            'invitation_expires_days', 'invitation_token', 'raw_token',
            'invitation_raw_token',

            # Timestamps
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'invitation_token', 'created_at', 'updated_at'
        ]
        extra_kwargs = {
            'email': {'validators': [EmailValidator()]},
            'contact_person_first_name': {'required': True},
            'year_of_birth': {'required': True},
            'street': {'required': True},
            'location': {'required': True},
            'city': {'required': True},
        }

    def get_invitation_raw_token(self, obj):
        # Assumes default related_name from ClientInvitation to Client is 'clientinvitation'
        print(f"obs----{obj}")
        ci = getattr(obj, 'clientadmin_invitation', None)
        return ci.token if ci else None

    def validate_email(self, value):
        """Validate email uniqueness"""
        email = value.lower().strip()
        if self.instance:  # Update case
            if Client.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
                raise serializers.ValidationError("A client with this email already exists.")
        else:  # Create case
            if Client.objects.filter(email=email).exists():
                raise serializers.ValidationError("A client with this email already exists.")
        return email

    def validate_year_of_birth(self, value):
        """Validate year of birth"""
        current_year = timezone.now().year
        if value < 1900 or value > current_year - 18:
            raise serializers.ValidationError(
                f"Year of birth must be between 1900 and {current_year - 18}"
            )
        return value

    def validate_product_ids(self, value):
        """Ensure all product UUIDs exist in the database"""
        existing_products = Product.objects.filter(id__in=value)
        if existing_products.count() != len(value):
            existing_ids = set(existing_products.values_list('id', flat=True))
            invalid_ids = set(value) - existing_ids
            raise serializers.ValidationError(
                f"Invalid product IDs: {list(invalid_ids)}"
            )
        return value

    @transaction.atomic
    def create(self, validated_data):
        """Create client with products and invitation"""
        try:
            product_ids = validated_data.pop('product_ids', [])
            send_invitation = validated_data.pop('send_invitation', True)
            invitation_expires_days = validated_data.pop('invitation_expires_days', 30)
            raw_token = validated_data.pop('raw_token', uuid.uuid4())

            # Set created_by if available in context
            request = self.context.get('request')
            if request and hasattr(request, 'user'):
                validated_data['created_by'] = request.user

            # Create client
            client = Client.objects.create(**validated_data)

            

            # Create ClientInvitation (separate record)
            # client_invitation = ClientInvitation.objects.create(
            #     token=raw_token,
            #     client=client
            # )
            # # Override client's own invitation_token to match raw_token
            # if hasattr(client_invitation, 'token'):
            #     client_invitation.token = raw_token
            #     client_invitation.save(update_fields=['token'])

            # Create client-product relationships
            if product_ids:
                client_products = []
                for product_id in product_ids:
                    client_products.append(
                        ClientProduct(
                            client=client,
                            product_id=product_id,
                            purchased_at=timezone.now(),
                            is_active=True
                        )
                    )
                ClientProduct.objects.bulk_create(client_products)

            # Create invitation if requested
            # if send_invitation:
            #     expires_at = timezone.now() + timezone.timedelta(days=invitation_expires_days)
            #     ClientInvitation.objects.create(
            #         client=client,
            #         email=client.email,
            #         token=raw_token,
            #         invited_by=request.user if request and hasattr(request, 'user') else None,
            #         expires_at=expires_at,
            #         sent_at=timezone.now(),
            #         status=InvitationStatus.NOT_ACCEPTED
            #     )

            return client

        except Exception as e:
            raise serializers.ValidationError({
                'error': str(e)
            })
class ClientListSerializer(serializers.ModelSerializer):
    """Simplified serializer for listing clients"""
    products_count = serializers.SerializerMethodField()
    invitation_status = serializers.SerializerMethodField()
    
    class Meta:
        model = Client
        fields = [
            'id', 'company_name', 'contact_person_first_name',
            'contact_person_last_name', 'email', 'city', 'land',
            'is_active', 'products_count', 'invitation_status',
            'created_at'
        ]
    
    def get_products_count(self, obj):
        return obj.clientproduct_set.filter(is_active=True).count()
    
    def get_invitation_status(self, obj):
        latest_invitation = obj.invitations.order_by('-created_at').first()
        if latest_invitation:
            return {
                'status': latest_invitation.status,
                'status_display': latest_invitation.get_status_display(),
                'expires_at': latest_invitation.expires_at,
                'is_expired': latest_invitation.is_expired()
            }
        return None

class ClientDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for client retrieval"""
    client_products = ClientProductSerializer(
        source='clientproduct_set',
        many=True,
        read_only=True
    )
    created_by_name = serializers.CharField(
        source='created_by.get_full_name',
        read_only=True
    )
    latest_invitation = serializers.SerializerMethodField()
    
    class Meta:
        model = Client
        fields = [
            # Company Data
            'id', 'company_name', 'date', 'company_photo', 'role',
            
            # Contact Person
            'contact_person_first_name', 'contact_person_last_name',
            'gender', 'year_of_birth',
            
            # Address Details
            'street', 'zip_code', 'location', 'landline_number',
            'mobile_phone_number', 'city', 'land', 'email',
            
            # Other fields
            'miscellaneous', 'is_active', 'invitation_token',
            
            # Relations
            'client_products', 'created_by_name', 'latest_invitation',
            
            # Timestamps
            'created_at', 'updated_at'
        ]
    
    def get_latest_invitation(self, obj):
        latest_invitation = obj.invitations.order_by('-created_at').first()
        if latest_invitation:
            return {
                'id': latest_invitation.id,
                'token': latest_invitation.token,
                'status': latest_invitation.status,
                'status_display': latest_invitation.get_status_display(),
                'sent_at': latest_invitation.sent_at,
                'accepted_at': latest_invitation.accepted_at,
                'expires_at': latest_invitation.expires_at,
                'is_expired': latest_invitation.is_expired(),
                'is_valid_for_acceptance': latest_invitation.is_valid_for_acceptance(),
                'invite_url': latest_invitation.get_invite_url()
            }
        return None
    

"""
INVITE LINKS ---------------------------
"""

class InvitationDataSerializer(serializers.ModelSerializer):
    """Serializer for the Invitation model."""
    client_company_name = serializers.CharField(source='client.company_name', read_only=True)
    invited_by_name = serializers.CharField(source='invited_by.get_full_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_expired = serializers.SerializerMethodField()
    is_valid_for_acceptance = serializers.SerializerMethodField()
    invite_url = serializers.SerializerMethodField()

    class Meta:
        model = Invitation
        fields = [
            'id', 'token', 'client', 'client_company_name', 'email', 'accepted_at',
            'invited_by', 'invited_by_name', 'is_active', 'expires_at', 'sent_at',
            'status', 'status_display', 'is_expired', 'is_valid_for_acceptance', 'invite_url',
            'created_at', 'updated_at'
        ]
        read_only_fields = fields # All fields are read-only for this serializer

    def get_is_expired(self, obj):
        return obj.is_expired()

    def get_is_valid_for_acceptance(self, obj):
        return obj.is_valid_for_acceptance()

    def get_invite_url(self, obj):
        # This will return the full URL including the frontend domain
        # assuming settings.DOMAIN is set up correctly.
        return obj.get_invite_url()

class EmailLoginSerializer(serializers.Serializer):
    """Serializer for email-only login"""
    email = serializers.EmailField()
    
    def validate_email(self, value):
        if not value:
            raise serializers.ValidationError("Email is required.")
        return value
    
class AcceptInvitationSerializer(serializers.Serializer):
    """Serializer for accepting invitation"""
    token = serializers.UUIDField()
    
    def validate_token(self, value):
        """Validate invitation token"""
        try:
            invitation = ClientInvitation.objects.get(
                token=value, 
                is_active=True
            )
            self.context['invitation'] = invitation
            return value
        except ClientInvitation.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired invitation token.")






class AcceptInvitationWithEmailSerializer(serializers.Serializer):
    """Enhanced serializer for accepting invitation with email verification"""
    email = serializers.EmailField()
    token = serializers.UUIDField()
    
    def validate_email(self, value):
        """Validate email field"""
        if not value:
            raise serializers.ValidationError("Email is required.")
        return value
    
    def validate_token(self, value):
        """Validate invitation token"""
        try:
            invitation = ClientInvitation.objects.get(
                token=value, 
                is_active=True
            )
            self.context['invitation'] = invitation
            return value
        except ClientInvitation.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired invitation token.")
    
    def validate(self, attrs):
        """Ensure email matches the invitation email"""
        email = attrs.get('email')
        invitation = self.context.get('invitation')
        print(f"yos- -{invitation.client.email}")
        if invitation and invitation.client.email.lower() != email.lower():
            raise serializers.ValidationError(
                "The provided email does not match the invitation email."
            )
            
        return attrs