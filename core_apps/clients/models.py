from django.db import models
from django import forms
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django_countries.fields import CountryField
import uuid
from core_apps.common.permissions import IsTerramoAdmin, IsCompanyAdmin, IsSameCompany
from core_apps.common.models import TimeStampedModel
from core_apps.products.models import Product
from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth import login, authenticate, get_user_model
from django.urls import reverse
import os
# User = get_user_model()
User = settings.AUTH_USER_MODEL
# from django.core.validators import EmailValidator
# email = models.EmailField(unique=True, validators=[EmailValidator()])
DEFAULT_STAKEHOLDER_GROUP_NAMES = ["Management / Executive Board"]

def client_image_path(instance, filename):
    """Generate file path for client images"""
    ext = filename.split('.')[-1]
    filename = f'{uuid.uuid4()}.{ext}'
    return os.path.join('clients', filename)
class Client(TimeStampedModel):
    """Client/Customer entity"""
    class Salutation(models.TextChoices):
        MR = (
            "mr",
            _("Mr"),
        )
        MRS = (
            "mrs",
            _("Mrs"),
        )
        MISS = (
            "miss",
            _("Miss"),
        )

    class Gender(models.TextChoices):
        MALE = (
            "male",
            _("Male"),
        )
        FEMALE = (
            "female",
            _("Female"),
        )
        OTHER = (
            "other",
            _("Other"),
        )
    class CompanyRole(models.TextChoices):
        TERRAMO_CUSTOMER = "Terramo Customer", _("Terramo Customer")
    
   
    """
    ------------------------------------------------------------------------------
    |   Company Data
    ------------------------------------------------------------------------------
    """
    company_name = models.CharField(max_length=200, null=False, blank=True)
    date = models.DateField(default=timezone.now)
  
    company_photo = models.ImageField(
        verbose_name=_("Company Photo"), 
        default="/company_default.png",
        # upload_to=client_image_path,
        upload_to="uploads/"
    )
    role = models.CharField(max_length=20, choices=CompanyRole.choices, default=CompanyRole.TERRAMO_CUSTOMER)

 
    """
    ------------------------------------------------------------------------------
    |   Contact Person
    ------------------------------------------------------------------------------
    """
    contact_person_first_name = models.CharField(_("Contact Person First Name"), max_length=200, null=False, blank=False)
    contact_person_last_name = models.CharField(_("Contact Person Last Name"),max_length=200, null=False, blank=True)
    gender = models.CharField(
        _("Gender"), max_length=8, choices=Gender.choices, default=Gender.MALE
    )
    # country = CountryField(_("Country"), default=settings.DEFAULT_COUNTRY)
    year_of_birth = models.PositiveIntegerField(blank=False, null=False, help_text="YYYY")
    

    """
    ---------------------------------------------------------------------------
    |   Address Details
    ---------------------------------------------------------------------------
    """
    street = models.CharField(_("Street"), max_length=100, blank=False)
    zip_code = models.CharField(_("Zip Code"), max_length=20, )
    location = models.CharField(_("Location"), max_length=100, blank=False)
    landline_number = PhoneNumberField(
        _("Landline Number"), max_length=30, default=settings.DEFAULT_LANDLINE_NUMBER
    )
    mobile_phone_number = PhoneNumberField(
        _("Phone Number"), max_length=30, default=settings.DEFAULT_PHONE_NUMBER
    )
    city = models.CharField(_("City"), max_length=50)
    land = CountryField(_("Land"), default=settings.DEFAULT_COUNTRY)
    email = models.EmailField(blank=False, null=False)
    invitation_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)

    
    miscellaneous = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
     
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_companies')
    
    class Meta:
        db_table = 'clients'
        verbose_name_plural = 'Clients'
        ordering = ['company_name', 'email']
        unique_together = ["company_name", "land"]
        indexes = [
            models.Index(fields=['company_name']),
            models.Index(fields=['email']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return self.company_name
    
class InvitationStatus(models.TextChoices):
    NOT_ACCEPTED = 'not_accepted', _('Not Accepted')
    ACCEPTED = 'accepted', _('Accepted (Link Clicked)')
    REGISTERED = 'registered', _('Registered (Account Created)')


class ClientInvitation(TimeStampedModel):
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    client = models.OneToOneField(   
        'clients.Client', 
        on_delete=models.CASCADE, 
        related_name='clientadmin_invitation'   
    )

    accepted_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Accepted At'))

    is_active = models.BooleanField(default=True, verbose_name=_('Is Active'))
    email_verified = models.BooleanField(default=False, verbose_name=_('Is Email Verified'))
    is_accepted = models.BooleanField(default=False, verbose_name=_('Is Accepted'))
    
    # year = models.PositiveIntegerField(blank=False, null=False, help_text="YYYY")

    class Meta:
        verbose_name = _('Client Invitation')
        verbose_name_plural = _('Client Invitations')
        ordering = ['-created_at']

  

    def __str__(self):
        return f"{self.client.company_name} - {self.client.email}"

    def get_invite_url(self):
        
        # example : http://localhost:3000/client-admin/accept-invitation/96b78b5e-e88e-4577-b9ce-fcc7cac67c8d/
        return f"{settings.FRONTEND_DOMAIN_URL}/{settings.FRONTEND_CLIENT_ACCEPT_ENDPOINT}/{self.token}/"
    
    def is_already_accepted_and_verified(self):
        # A link is valid for acceptance if it's active, not expired, and not yet registered
        return self.is_active and self.email_verified and self.is_accepted
    
    # def is_expired(self):
    #     return self.expires_at and self.expires_at < timezone.now()

    # def is_valid_for_acceptance(self):
    #     # A link is valid for acceptance if it's active, not expired, and not yet registered
    #     return self.is_active and not self.is_expired() and self.status != InvitationStatus.REGISTERED

    # def mark_status(self, new_status):
    #     if new_status in InvitationStatus:
    #         self.status = new_status
    #         if new_status == InvitationStatus.REGISTERED:
    #             self.is_active = False # A registered invite should no longer be active
    #         self.save()
    #     else:
    #         raise ValueError(f"Invalid invitation status: {new_status}")
        
class ClientProduct(TimeStampedModel):
    """Through model for Client-Product relationship"""
    
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    purchased_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'client_products'
        unique_together = ['client', 'product']
        indexes = [
            models.Index(fields=['client', 'is_active']),
        ]



class Invitation(models.Model):
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    
    # The client for which this invitation is being issued
    client = models.ForeignKey(
        'clients.Client', # Use string reference
        on_delete=models.CASCADE, 
        related_name='invitations'
    )

    # The email address of the invited stakeholder (from Client.email)
    email = models.EmailField(_('invited email address'))
    accepted_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Accepted At'))
    # The user who created this invitation (Terramo Admin)
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, # Reference CustomUser
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_invitations'
    )

    is_active = models.BooleanField(default=True, verbose_name=_('Is Active'))
    expires_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Expires At'))
    sent_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Sent At'))
    
    # New status field
    status = models.CharField(
        max_length=20, 
        choices=InvitationStatus.choices, 
        default=InvitationStatus.NOT_ACCEPTED
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Invitation')
        verbose_name_plural = _('Invitations')
        ordering = ['-created_at']
        # Prevent multiple active invitations to the same email for the same client
        # This will raise IntegrityError if you try to create another active invite
        # for the same email and client.
        unique_together = ['email', 'client'] 

    def __str__(self):
        return f"Invite for {self.email} to {self.client.company_name} (Status: {self.get_status_display()})"

    def get_invite_url(self):
        # This URL will point to your frontend application's route for accepting invites.
        # The frontend will then use this token to call your DRF API endpoint.
        # Ensure settings.FRONTEND_DOMAIN_URL is configured in your settings.py
        return f"{settings.DOMAIN}/clients/invitations/accept/{self.token}/"

    def is_expired(self):
        return self.expires_at and self.expires_at < timezone.now()

    def is_valid_for_acceptance(self):
        # A link is valid for acceptance if it's active, not expired, and not yet registered
        return self.is_active and not self.is_expired() and self.status != InvitationStatus.REGISTERED

    def mark_status(self, new_status):
        if new_status in InvitationStatus:
            self.status = new_status
            if new_status == InvitationStatus.REGISTERED:
                self.is_active = False # A registered invite should no longer be active
            self.save()
        else:
            raise ValueError(f"Invalid invitation status: {new_status}")


# class Invitation(models.Model):
#     token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
#     client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='invitations')
#     email = models.EmailField(_('invited email address'))
#     invited_by = models.ForeignKey(
#         settings.AUTH_USER_MODEL,
#         on_delete=models.SET_NULL,
#         null=True,
#         blank=True,
#         related_name='created_invitations'
#     )
#     is_active = models.BooleanField(default=True, verbose_name=_('Is Active'))
#     expires_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Expires At'))
#     sent_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Sent At'))
#     accepted_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Accepted At'))
    
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)

#     class Meta:
#         verbose_name = _('Invitation')
#         verbose_name_plural = _('Invitations')
#         ordering = ['-created_at']
#         unique_together = ['email', 'client'] # Optional: Prevent multiple active invites to same email/client

#     def __str__(self):
#         return f"Invite for {self.email} to {self.client.company_name}"

#     def get_invite_url(self):
#         # This will now point to your frontend application's URL for accepting invites
#         # The frontend will then call your DRF API endpoint with the token
#         return f"{settings.DOMAIN}/clients/invitations/accept/{self.token}/"

#     def is_expired(self):
#         return self.expires_at and self.expires_at < timezone.now()

#     def is_valid(self):
#         return self.is_active and not self.is_expired() and not self.accepted_at

#     def mark_as_accepted(self, user):
#         self.accepted_at = timezone.now()
#         self.is_active = False
#         self.save()


"""
Super Final: ClientInvitation
"""
from datetime import timedelta
# class ClientInvitationToken(TimeStampedModel):
#     """
#     Client invitation model for managing invitation lifecycle
#     """
    
#     class InvitationTokenStatus(models.TextChoices):
#         PENDING = 'pending', _('Pending (Not Sent)')
#         SENT = 'sent', _('Sent (Email Sent)')
#         VIEWED = 'viewed', _('Viewed (Link Clicked)')
#         ACCEPTED = 'accepted', _('Accepted (Terms Agreed)')
#         REGISTERED = 'registered', _('Registered (Account Created)')
#         EXPIRED = 'expired', _('Expired')
#         REVOKED = 'revoked', _('Revoked')

#     # Core fields
#     token = models.UUIDField(
#         default=uuid.uuid4, 
#         unique=True, 
#         editable=False,
#         db_index=True
#     )
    
#     client = models.OneToOneField(   
#         'clients.Client', 
#         on_delete=models.CASCADE, 
#         related_name='clientadmin_invitation'   
#     )
    
#     status = models.CharField(
#         _('Status'),
#         max_length=20,
#         choices=InvitationTokenStatus.choices,
#         default=InvitationTokenStatus.PENDING,
#         db_index=True
#     )
    
#     # Timestamps for tracking invitation lifecycle
#     sent_at = models.DateTimeField(
#         null=True, 
#         blank=True, 
#         verbose_name=_('Sent At'),
#         help_text=_('When the invitation email was sent')
#     )
    
#     viewed_at = models.DateTimeField(
#         null=True, 
#         blank=True, 
#         verbose_name=_('Viewed At'),
#         help_text=_('When the invitation link was first clicked')
#     )
    
#     accepted_at = models.DateTimeField(
#         null=True, 
#         blank=True, 
#         verbose_name=_('Accepted At'),
#         help_text=_('When the user accepted the terms')
#     )
    
#     registered_at = models.DateTimeField(
#         null=True, 
#         blank=True, 
#         verbose_name=_('Registered At'),
#         help_text=_('When the user account was created')
#     )
    
#     expires_at = models.DateTimeField(
#         verbose_name=_('Expires At'),
#         help_text=_('When this invitation expires')
#     )
    
#     revoked_at = models.DateTimeField(
#         null=True, 
#         blank=True, 
#         verbose_name=_('Revoked At')
#     )
    
#     # Legacy fields (keep for backward compatibility, but use status instead)
#     is_active = models.BooleanField(
#         default=True, 
#         verbose_name=_('Is Active'),
#         help_text=_('Legacy field - use status instead')
#     )
    
#     email_verified = models.BooleanField(
#         default=False, 
#         verbose_name=_('Is Email Verified'),
#         help_text=_('Legacy field - use status instead')
#     )
    
#     is_accepted = models.BooleanField(
#         default=False, 
#         verbose_name=_('Is Accepted'),
#         help_text=_('Legacy field - use status instead')
#     )
    
#     # Metadata
#     invitation_metadata = models.JSONField(
#         default=dict,
#         blank=True,
#         help_text=_('Additional invitation metadata')
#     )
    
#     # Tracking fields
#     view_count = models.PositiveIntegerField(
#         default=0,
#         help_text=_('Number of times invitation link was accessed')
#     )
    
#     last_viewed_ip = models.GenericIPAddressField(
#         null=True,
#         blank=True,
#         help_text=_('Last IP address that viewed the invitation')
#     )
    
#     sent_by = models.ForeignKey(
#         settings.AUTH_USER_MODEL,
#         on_delete=models.SET_NULL,
#         null=True,
#         blank=True,
#         related_name='sent_invitations',
#         help_text=_('User who sent this invitation')
#     )

#     class Meta:
#         verbose_name = _('Client Invitation')
#         verbose_name_plural = _('Client Invitations')
#         ordering = ['-created_at']
#         indexes = [
#             models.Index(fields=['status']),
#             models.Index(fields=['expires_at']),
#             models.Index(fields=['client', 'status']),
#         ]

#     def __str__(self):
#         return f"{self.client.company_name} - {self.client.email} ({self.get_status_display()})"

#     def save(self, *args, **kwargs):
#         """Override save to set expiration date and sync legacy fields"""
#         if not self.expires_at:
#             # Set expiration to 7 days from now if not set
#             self.expires_at = timezone.now() + timedelta(days=7)
        
#         # Sync legacy fields with status for backward compatibility
#         if self.status == self.InvitationTokenStatus.REGISTERED:
#             self.is_active = True
#             self.email_verified = True
#             self.is_accepted = True
#         elif self.status == self.InvitationTokenStatus.ACCEPTED:
#             self.is_active = True
#             self.email_verified = True
#             self.is_accepted = True
#         elif self.status == self.InvitationTokenStatus.VIEWED:
#             self.is_active = True
#             self.email_verified = True
#             self.is_accepted = False
#         elif self.status == self.InvitationTokenStatus.SENT:
#             self.is_active = True
#             self.email_verified = False
#             self.is_accepted = False
#         elif self.status in [self.InvitationTokenStatus.EXPIRED, self.InvitationTokenStatus.REVOKED]:
#             self.is_active = False
        
#         super().save(*args, **kwargs)

#     # Properties
#     @property
#     def is_expired(self):
#         """Check if invitation is expired"""
#         return timezone.now() > self.expires_at

#     @property
#     def is_valid_for_acceptance(self):
#         """Check if invitation is valid for acceptance"""
#         return (
#             self.is_active and 
#             not self.is_expired and 
#             self.status in [
#                 self.InvitationTokenStatus.SENT, 
#                 self.InvitationTokenStatus.VIEWED
#             ]
#         )

#     @property
#     def can_send_login_link(self):
#         """
#         Check if user can request login link
#         User can request login link only if they have completed registration
#         """
#         return (
#             self.is_active and 
#             not self.is_expired and 
#             self.status == self.InvitationTokenStatus.REGISTERED
#         )

#     @property
#     def days_until_expiry(self):
#         """Get days until expiration"""
#         if self.is_expired:
#             return 0
#         delta = self.expires_at - timezone.now()
#         return max(0, delta.days)

#     # Methods
#     def get_invite_url(self):
#         """Get the invitation URL"""
#         return f"{settings.FRONTEND_DOMAIN_URL}/{settings.FRONTEND_CLIENT_ACCEPT_ENDPOINT}/{self.token}/"
    
#     def mark_as_sent(self, sent_by=None):
#         """Mark invitation as sent"""
#         if self.status == self.InvitationTokenStatus.PENDING:
#             self.status = self.InvitationTokenStatus.SENT
#             self.sent_at = timezone.now()
#             if sent_by:
#                 self.sent_by = sent_by
#             self.save()
    
#     def mark_as_viewed(self, ip_address=None):
#         """Mark invitation as viewed (link clicked)"""
#         if self.status == self.InvitationTokenStatus.SENT:
#             self.status = self.InvitationTokenStatus.VIEWED
#             self.viewed_at = timezone.now()
        
#         # Always update view tracking
#         self.view_count += 1
#         if ip_address:
#             self.last_viewed_ip = ip_address
#         self.save()
    
#     def mark_as_accepted(self):
#         """Mark invitation as accepted (terms agreed)"""
#         if self.status == self.InvitationTokenStatus.VIEWED:
#             self.status = self.InvitationTokenStatus.ACCEPTED
#             self.accepted_at = timezone.now()
#             self.save()
    
#     def mark_as_registered(self):
#         """Mark invitation as completed (user account created)"""
#         if self.status == self.InvitationTokenStatus.ACCEPTED:
#             self.status = self.InvitationTokenStatus.REGISTERED
#             self.registered_at = timezone.now()
#             self.save()
    
#     def extend_expiry(self, days=7):
#         """Extend invitation expiry"""
#         if self.is_valid_for_acceptance:
#             self.expires_at = timezone.now() + timedelta(days=days)
#             self.save()
    
#     def revoke(self, reason=None):
#         """Revoke the invitation"""
#         self.status = self.InvitationTokenStatus.REVOKED
#         self.revoked_at = timezone.now()
#         self.is_active = False
        
#         if reason:
#             self.invitation_metadata['revoked_reason'] = reason
        
#         self.save()
    
#     def reactivate(self, extend_days=7):
#         """Reactivate an expired invitation"""
#         if self.status == self.InvitationTokenStatus.EXPIRED:
#             self.status = self.InvitationTokenStatus.SENT
#             self.expires_at = timezone.now() + timedelta(days=extend_days)
#             self.is_active = True
#             self.save()
    
#     def clean(self):
#         """Validate the invitation"""
#         from django.core.exceptions import ValidationError
        
#         # Ensure expiry is in the future for new invitations
#         if not self.pk and self.expires_at and self.expires_at <= timezone.now():
#             raise ValidationError({
#                 'expires_at': _('Expiry date must be in the future.')
#             })
        
#         # Auto-expire if past expiry date
#         if self.is_expired and self.status not in [
#             self.InvitationTokenStatus.EXPIRED, 
#             self.InvitationTokenStatus.REVOKED,
#             self.InvitationTokenStatus.REGISTERED
#         ]:
#             self.status = self.InvitationTokenStatus.EXPIRED
#             self.is_active = False

#     # Legacy methods for backward compatibility
#     def is_already_accepted_and_verified(self):
#         """Legacy method - use can_send_login_link instead"""
#         return self.can_send_login_link


"""
Authentication: ----- Login Token

"""

# class ClientAdminLoginToken(models.Model):
#     """
#     Model to securely store login tokens for client admin authentication
#     """
#     # Primary token field
#     token = models.UUIDField(
#         unique=True, 
#         default=uuid.uuid4, 
#         editable=False,
#         db_index=True,
#         help_text="Unique login token"
#     )
    
#     # User relationship
#     user = models.ForeignKey(
#         User, 
#         on_delete=models.CASCADE,
#         related_name='login_tokens',
#         help_text="User this token belongs to"
#     )
    
#     # Token metadata
#     created_at = models.DateTimeField(
#         auto_now_add=True,
#         help_text="When the token was created"
#     )
    
#     expires_at = models.DateTimeField(
#         help_text="When the token expires"
#     )
    
#     # Token status
#     is_used = models.BooleanField(
#         default=False,
#         help_text="Whether this token has been used for login"
#     )
    
#     used_at = models.DateTimeField(
#         null=True, 
#         blank=True,
#         help_text="When the token was used"
#     )
    
#     # Security fields
#     ip_address = models.GenericIPAddressField(
#         null=True, 
#         blank=True,
#         help_text="IP address from which token was requested"
#     )
    
#     user_agent = models.TextField(
#         null=True, 
#         blank=True,
#         help_text="User agent string from token request"
#     )
    
#     # Email tracking
#     email_sent_at = models.DateTimeField(
#         null=True, 
#         blank=True,
#         help_text="When the login email was sent"
#     )
    
#     class Meta:
#         db_table = 'client_admin_login_tokens'
#         ordering = ['-created_at']
#         indexes = [
#             models.Index(fields=['token']),
#             models.Index(fields=['user', '-created_at']),
#             models.Index(fields=['expires_at']),
#             models.Index(fields=['is_used']),
#         ]
#         verbose_name = "Client Admin Login Token"
#         verbose_name_plural = "Client Admin Login Tokens"
    
#     def __str__(self):
#         return f"Login token for {self.user.email} - {self.token}"
    
#     def save(self, *args, **kwargs):
#         """Set expiration time if not already set"""
#         if not self.expires_at:
#             # Set token to expire in 1 hour by default
#             self.expires_at = timezone.now() + timedelta(hours=1)
#         super().save(*args, **kwargs)
    
#     @property
#     def is_expired(self):
#         """Check if token has expired"""
#         return timezone.now() > self.expires_at
    
#     @property
#     def is_valid(self):
#         """Check if token is valid (not used and not expired)"""
#         return not self.is_used and not self.is_expired
    
#     def mark_as_used(self):
#         """Mark token as used"""
#         self.is_used = True
#         self.used_at = timezone.now()
#         self.save(update_fields=['is_used', 'used_at'])
    
#     @classmethod
#     def create_token(cls, user, ip_address=None, user_agent=None, expires_in_hours=1):
#         """
#         Create a new login token for a user
        
#         Args:
#             user: User instance
#             ip_address: IP address of the requester
#             user_agent: User agent string
#             expires_in_hours: Hours until token expires (default: 1)
        
#         Returns:
#             ClientAdminLoginToken instance
#         """
#         # Invalidate any existing unused tokens for this user
#         cls.objects.filter(
#             user=user,
#             is_used=False,
#             expires_at__gt=timezone.now()
#         ).update(is_used=True, used_at=timezone.now())
        
#         # Create new token
#         expires_at = timezone.now() + timedelta(hours=expires_in_hours)
        
#         token = cls.objects.create(
#             user=user,
#             expires_at=expires_at,
#             ip_address=ip_address,
#             user_agent=user_agent,
#             email_sent_at=timezone.now()
#         )
        
#         return token
    
#     @classmethod
#     def get_valid_token(cls, token_uuid):
#         """
#         Get a valid token by UUID
        
#         Args:
#             token_uuid: UUID string or UUID object
        
#         Returns:
#             ClientAdminLoginToken instance or None
#         """
#         try:
#             token = cls.objects.select_related('user').get(
#                 token=token_uuid,
#                 is_used=False,
#                 expires_at__gt=timezone.now()
#             )
#             return token
#         except cls.DoesNotExist:
#             return None
    
#     @classmethod
#     def cleanup_expired_tokens(cls, days_old=7):
#         """
#         Clean up expired and used tokens older than specified days
        
#         Args:
#             days_old: Remove tokens older than this many days
        
#         Returns:
#             Number of tokens deleted
#         """
#         cutoff_date = timezone.now() - timedelta(days=days_old)
#         deleted_count = cls.objects.filter(
#             models.Q(expires_at__lt=timezone.now()) |  # Expired tokens
#             models.Q(is_used=True, used_at__lt=cutoff_date)  # Used tokens older than cutoff
#         ).delete()[0]
        
#         return deleted_count
    

# class ClientAdminLoginToken(models.Model):
#     """
#     Secure storage for client admin login tokens
#     """
#     token = models.UUIDField(
#         default=uuid.uuid4, 
#         unique=True, 
#         editable=False,
#         db_index=True,  # For faster lookups
#         verbose_name=_('Token')
#     )
    
#     user = models.ForeignKey(
#         User,
#         on_delete=models.CASCADE,
#         related_name='client_login_tokens',
#         verbose_name=_('User')
#     )
    
#     client_invitation = models.ForeignKey(
#         'ClientInvitation',
#         on_delete=models.CASCADE,
#         related_name='login_tokens',
#         verbose_name=_('Client Invitation')
#     )
    
#     created_at = models.DateTimeField(
#         auto_now_add=True,
#         verbose_name=_('Created At')
#     )
    
#     expires_at = models.DateTimeField(
#         verbose_name=_('Expires At')
#     )
    
#     is_used = models.BooleanField(
#         default=False,
#         verbose_name=_('Is Used')
#     )
    
#     used_at = models.DateTimeField(
#         null=True,
#         blank=True,
#         verbose_name=_('Used At')
#     )
    
#     ip_address = models.GenericIPAddressField(
#         null=True,
#         blank=True,
#         verbose_name=_('IP Address')
#     )
    
#     user_agent = models.TextField(
#         null=True,
#         blank=True,
#         verbose_name=_('User Agent')
#     )

#     class Meta:
#         verbose_name = _('Client Admin Login Token')
#         verbose_name_plural = _('Client Admin Login Tokens')
#         ordering = ['-created_at']
#         indexes = [
#             models.Index(fields=['token']),
#             models.Index(fields=['user', 'is_used']),
#             models.Index(fields=['expires_at']),
#         ]

#     def __str__(self):
#         return f"Login Token for {self.user.email} - {'Used' if self.is_used else 'Valid'}"

#     def save(self, *args, **kwargs):
#         # Set expiration time (1 hour from creation)
#         if not self.expires_at:
#             self.expires_at = timezone.now() + timedelta(hours=1)
#         super().save(*args, **kwargs)

#     def is_valid(self):
#         """Check if token is still valid"""
#         return (
#             not self.is_used and
#             timezone.now() < self.expires_at
#         )

#     def is_expired(self):
#         """Check if token has expired"""
#         return timezone.now() >= self.expires_at

#     def mark_as_used(self, ip_address=None, user_agent=None):
#         """Mark token as used"""
#         self.is_used = True
#         self.used_at = timezone.now()
#         if ip_address:
#             self.ip_address = ip_address
#         if user_agent:
#             self.user_agent = user_agent
#         self.save(update_fields=['is_used', 'used_at', 'ip_address', 'user_agent'])

#     @classmethod
#     def cleanup_expired_tokens(cls):
#         """Remove expired tokens - call this in a cron job"""
#         expired_tokens = cls.objects.filter(expires_at__lt=timezone.now())
#         count = expired_tokens.count()
#         expired_tokens.delete()
#         return count

#     @classmethod
#     def get_valid_token(cls, token_uuid):
#         """Get a valid token by UUID"""
#         try:
#             token = cls.objects.select_related('user', 'client_invitation').get(
#                 token=token_uuid,
#                 is_used=False,
#                 expires_at__gt=timezone.now()
#             )
#             return token
#         except cls.DoesNotExist:
#             return None

#     def get_login_url(self):
#         """Generate the login URL"""
#         return f"{settings.FRONTEND_DOMAIN_URL}/client-admin/login/{self.token}/"

class ClientAdminLoginToken(models.Model):
    """
    Secure storage for client admin login tokens
    """
    token = models.UUIDField(
        default=uuid.uuid4, 
        unique=True, 
        editable=False,
        db_index=True,  # For faster lookups
        verbose_name=_('Token')
    )
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='client_login_tokens',
        verbose_name=_('User')
    )
    
    client_invitation = models.ForeignKey(
        'ClientInvitation',  # Reference to your existing model
        on_delete=models.CASCADE,
        related_name='login_tokens',
        verbose_name=_('Client Invitation')
    )
    
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('Created At')
    )
    
    expires_at = models.DateTimeField(
        verbose_name=_('Expires At')
    )
    
    is_used = models.BooleanField(
        default=False,
        verbose_name=_('Is Used')
    )
    
    used_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Used At')
    )
    
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_('IP Address')
    )
    
    user_agent = models.TextField(
        null=True,
        blank=True,
        verbose_name=_('User Agent')
    )

    class Meta:
        verbose_name = _('Client Admin Login Token')
        verbose_name_plural = _('Client Admin Login Tokens')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['user', 'is_used']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"Login Token for {self.user.email} - {'Used' if self.is_used else 'Valid'}"

    def save(self, *args, **kwargs):
        # Set expiration time (1 hour from creation)
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=1)
        super().save(*args, **kwargs)

    def is_valid(self):
        """Check if token is still valid"""
        return (
            not self.is_used and
            timezone.now() < self.expires_at
        )

    def is_expired(self):
        """Check if token has expired"""
        return timezone.now() >= self.expires_at

    def mark_as_used(self, ip_address=None, user_agent=None):
        """Mark token as used"""
        self.is_used = True
        self.used_at = timezone.now()
        if ip_address:
            self.ip_address = ip_address
        if user_agent:
            self.user_agent = user_agent
        self.save(update_fields=['is_used', 'used_at', 'ip_address', 'user_agent'])

    @classmethod
    def cleanup_expired_tokens(cls):
        """Remove expired tokens - call this in a cron job"""
        expired_tokens = cls.objects.filter(expires_at__lt=timezone.now())
        count = expired_tokens.count()
        expired_tokens.delete()
        return count

    @classmethod
    def get_valid_token(cls, token_uuid):
        """Get a valid token by UUID"""
        try:
            token = cls.objects.select_related('user', 'client_invitation').get(
                token=token_uuid,
                is_used=False,
                expires_at__gt=timezone.now()
            )
            return token
        except cls.DoesNotExist:
            return None

    def get_login_url(self):
        """Generate the login URL"""
        return f"{settings.FRONTEND_DOMAIN_URL}/client-admin/login/{self.token}/"