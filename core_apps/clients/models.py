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
        upload_to=client_image_path,
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

class InvitationStatus(models.TextChoices):
    NOT_ACCEPTED = 'not_accepted', _('Not Accepted')
    ACCEPTED = 'accepted', _('Accepted (Link Clicked)')
    REGISTERED = 'registered', _('Registered (Account Created)')
    # You could add 'EXPIRED' but is_expired() method handles it better

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

