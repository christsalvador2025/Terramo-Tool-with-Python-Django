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
from core_apps.clients.models import Client

from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth import login, authenticate, get_user_model

# User = get_user_model()
User = settings.AUTH_USER_MODEL

# Create your models here.


class StakeholderGroup(TimeStampedModel):

    client = models.ForeignKey(
        Client,
        on_delete=models.CASCADE, 
        related_name='stakeholder_groups'
    )
    name = models.CharField(max_length=100) 
    description = models.TextField(blank=True)
    unique_group_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False) 
    show_in_chart = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    class Meta:
        db_table = 'stakeholder_groups'
        unique_together = ['client', 'name'] # A company cannot have two groups with the same name
        ordering = ["client"]
        indexes = [
            models.Index(fields=['client', 'is_active']),
            models.Index(fields=['unique_group_token']), 
        ]

    def __str__(self):
        return f"{self.client.company_name} - {self.name}" 
    


class StakeholderInvitation(TimeStampedModel):
    """Track stakeholder invitations"""
    
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        ACCEPTED = 'accepted', 'Accepted'
        EXPIRED = 'expired', 'Expired'
    
 
    stakeholder_group = models.ForeignKey(StakeholderGroup, on_delete=models.CASCADE, related_name='invitations')
    email = models.EmailField()
    invite_token = models.UUIDField(default=uuid.uuid4, unique=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    sent_at = models.DateTimeField(auto_now_add=True)
    accepted_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    sent_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    class Meta:
        db_table = 'stakeholder_invitations'
        unique_together = ['stakeholder_group', 'email']
        indexes = [
            models.Index(fields=['invite_token']),
            models.Index(fields=['status', 'invite_token']),
        ]
