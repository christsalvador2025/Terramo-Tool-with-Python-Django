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
from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth import login, authenticate, get_user_model



class Product(TimeStampedModel):
    """Products that can be purchased by companies"""
    
    # class ProductType(models.TextChoices):
    #     ESG_CHECK = 'esg_check', 'ESG Check'
    #     STAKEHOLDER_ANALYSIS = 'stakeholder_analysis', 'Stakeholder Analysis'
    #     DOUBLE_MATERIALITY = 'double_materiality', 'Double Materiality'
    
    
    name = models.CharField(max_length=100)
    # type = models.CharField(max_length=30, choices=ProductType.choices)
    description = models.TextField(blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    is_active = models.BooleanField(default=True)
     
    class Meta:
        db_table = 'products'
        indexes = [
            models.Index(fields=['name', 'is_active']),
        ]
    
    def __str__(self):
        return self.name