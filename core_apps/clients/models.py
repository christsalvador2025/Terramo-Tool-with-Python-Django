from django.db import models
from django import forms
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django_countries.fields import CountryField
import uuid
from core_apps.common.permissions import IsSuperAdmin, IsCompanyAdmin, IsSameCompany
from core_apps.common.models import TimeStampedModel
from core_apps.products.models import Product
from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth import login, authenticate, get_user_model

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
            "male",
            _("Male"),
        )
        FEMALE = (
            "female",
            _("Female"),
        )
    
    class CompanyRole(models.TextChoices):
        TERRAMO_CUSTOMER = "Terramo Customer", _("Terramo Customer")
    
   
    """
    ---------------------------------------
    |   Company Data
    ---------------------------------------
    """
    company_name = models.CharField(max_length=200, null=False, blank=True)
    date = models.DateField(default=timezone.now)
  
    company_photo = models.ImageField(
        verbose_name=_("Company Photo"), default="/company_default.png"
    )
    role = models.CharField(max_length=20, choices=CompanyRole.choices, default=CompanyRole.TERRAMO_CUSTOMER)

 
    """
    ---------------------------------------
    |   Contact Person
    ---------------------------------------
    """
    contact_person_first_name = models.CharField(_("Contact Person First Name"), max_length=200, null=False, blank=False)
    contact_person_last_name = models.CharField(_("Contact Person Last Name"),max_length=200, null=False, blank=True)
    gender = models.CharField(
        _("Gender"), max_length=8, choices=Gender.choices, default=Gender.MALE
    )
    # country = CountryField(_("Country"), default=settings.DEFAULT_COUNTRY)
    year_of_birth = models.PositiveIntegerField(blank=False, null=False, help_text="YYYY")
    

    """
    ------------------------------------
    |   Address Details
    ------------------------------------
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


