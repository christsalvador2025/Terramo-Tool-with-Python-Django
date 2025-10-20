from django.db import models
from django import forms
from cloudinary.models import CloudinaryField
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator, EmailValidator
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
 
DEFAULT_STAKEHOLDER_GROUP_NAMES = ["Management / Executive Board"]

 

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
            "Männlich",
            _("Männlich"),
        )
        FEMALE = (
            "Weiblich",
            _("Weiblich"),
        )
        OTHER = (
            "Divers",
            _("Divers"),
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
  
    # company_photo = models.ImageField(
    #     verbose_name=_("Company Photo"), 
    #     default="/company_default.png",
    #     # upload_to=client_image_path,
    #     upload_to="uploads/"
    # )

    company_photo = CloudinaryField(
        _("Company Photo"),
        blank=True,
        null=True,
    )
    company_photo_url = models.URLField(_("Company Photo URL"), blank=True, null=True)
    role = models.CharField(max_length=20, choices=CompanyRole.choices, default=CompanyRole.TERRAMO_CUSTOMER)

 
    """
    ------------------------------------------------------------------------------
    |   Contact Person
    ------------------------------------------------------------------------------
    """
    contact_person_first_name = models.CharField(_("Contact Person First Name"), max_length=200, null=True, blank=True)
    contact_person_last_name = models.CharField(_("Contact Person Last Name"),max_length=200, null=True, blank=True)
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
    # city = models.CharField(_("City"), max_length=50)
    land = CountryField(_("Land"), default=settings.DEFAULT_COUNTRY)
    email = models.EmailField(blank=True, null=True)
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
    expires_at = models.DateTimeField(null=True, blank=True)
    days_to_expire = models.PositiveIntegerField(default=7,verbose_name=_('Days to Expire'))
   

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
    
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def save(self, *args, **kwargs):
        # if not self.token:
        #     self.token = secrets.token_urlsafe(32)
        self.expires_at = timezone.now() + timedelta(days=self.days_to_expire)
        super().save(*args, **kwargs)

class ClientAdmin(TimeStampedModel):
   
    client = models.OneToOneField(Client, on_delete=models.CASCADE, related_name='client_admin')
    email = models.EmailField(unique=True, validators=[EmailValidator()])
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)
    invitation_used = models.OneToOneField(ClientInvitation, on_delete=models.CASCADE, null=True,blank=True, related_name='client_admin_invitation')
    
    class Meta:
     
        # unique_together = ['client', 'product']
        indexes = [
            models.Index(fields=['client', 'email']),
        ]
    
    def __str__(self):
        return f"{self.email} - {self.client.company_name}"

class InvitationStatus(models.TextChoices):
    NOT_ACCEPTED = 'not_accepted', _('Not Accepted')
    ACCEPTED = 'accepted', _('Accepted (Link Clicked)')
    REGISTERED = 'registered', _('Registered (Account Created)')



    
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
       
        unique_together = ['email', 'client'] 

    def __str__(self):
        return f"Invite for {self.email} to {self.client.company_name} (Status: {self.get_status_display()})"

    def get_invite_url(self):
 
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

 
"""
Super Final: ClientInvitation
"""
from datetime import timedelta
 

"""
Authentication: ----- Login Token

"""
 
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