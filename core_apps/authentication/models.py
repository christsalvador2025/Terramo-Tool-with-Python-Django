# Project Structure:
# terramo_system/
# ├── manage.py
# ├── terramo_system/
# │   ├── __init__.py
# │   ├── settings.py
# │   ├── urls.py
# │   └── wsgi.py
# ├── authentication/
# │   ├── __init__.py
# │   ├── admin.py
# │   ├── apps.py
# │   ├── models.py
# │   ├── serializers.py
# │   ├── views.py
# │   ├── urls.py
# │   ├── permissions.py
# │   ├── utils.py
# │   └── migrations/
# ├── clients/
# │   ├── __init__.py
# │   ├── admin.py
# │   ├── apps.py
# │   ├── models.py
# │   ├── serializers.py
# │   ├── views.py
# │   ├── urls.py
# │   └── migrations/
# └── requirements.txt

# ==================== MODELS ====================

# authentication/models.py
from django.contrib.auth.models import AbstractUser, Group
from django.db import models
from django.utils import timezone
from django.core.validators import EmailValidator
import uuid
import secrets
from datetime import timedelta
from django.conf import settings

User = settings.AUTH_USER_MODEL
# class User(AbstractUser):
#     """Extended User model for Terramo Admin only"""
#     email = models.EmailField(unique=True)
#     role = models.CharField(
#         max_length=20,
#         choices=[('terramo_admin', 'Terramo Admin')],
#         default='terramo_admin'
#     )
    
#     USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = ['username']

#     def __str__(self):
#         return self.email

class Client(models.Model):
    """Client company model"""
    PRODUCT_CHOICES = [
        ('esg_check', 'ESG-Check'),
        ('stakeholder_analysis', 'Stakeholder Analysis'),
        ('materiality_analysis', 'Materiality Analysis'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company_name = models.CharField(max_length=255)
    company_contact_email = models.EmailField()
    date_required = models.DateField()
    
    # Product details - can select multiple
    products = models.JSONField(default=list)  # Store selected products as list
    
    # Contact person details
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    gender = models.CharField(
        max_length=40,
        choices=[
            ('male', 'Male'),
            ('female', 'Female'),
            ('other', 'Other'),
            ('prefer_not_to_say', 'Prefer not to say')
        ],
        blank=True
    )
    birth_year = models.IntegerField(null=True, blank=True)
    
    # Address details
    street = models.CharField(max_length=255)
    postal_code = models.CharField(max_length=20)
    city = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    
    # Contact details
    phone_number = models.CharField(max_length=20)
    mobile_number = models.CharField(max_length=20, blank=True)
    email = models.EmailField()
    
    # Additional info
    internal_processing_note = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    def __str__(self):
        return f"{self.company_name} - {self.first_name} {self.last_name}"

class ClientAdmin(models.Model):
    """Client Admin model - not in User table"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    client = models.OneToOneField(Client, on_delete=models.CASCADE, related_name='admin')
    email = models.EmailField(unique=True, validators=[EmailValidator()])
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.email} - {self.client.company_name}"

class StakeholderGroup(models.Model):
    """Stakeholder groups created by Client Admin"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='stakeholder_groups')
    created_by = models.ForeignKey(ClientAdmin, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['name', 'client']
    
    def __str__(self):
        return f"{self.name} - {self.client.company_name}"

class Stakeholder(models.Model):
    """Stakeholder model - not in User table"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(validators=[EmailValidator()])
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    group = models.ForeignKey(StakeholderGroup, on_delete=models.CASCADE, related_name='stakeholders')
    is_registered = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ['email', 'group']
    
    def __str__(self):
        return f"{self.email} - {self.group.name}"

class InvitationToken(models.Model):
    """Token model for invitations and login"""
    TOKEN_TYPES = [
        ('client_admin_invite', 'Client Admin Invitation'),
        ('stakeholder_invite', 'Stakeholder Invitation'),
        ('login_token', 'Login Token'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token = models.CharField(max_length=255, unique=True)
    token_type = models.CharField(max_length=25, choices=TOKEN_TYPES)
    
    # For client admin invitations
    client_admin = models.ForeignKey(
        ClientAdmin, 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True,
        related_name='invitation_tokens'
    )
    
    # For stakeholder invitations
    stakeholder = models.ForeignKey(
        Stakeholder,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='invitation_tokens'
    )
    
    email = models.EmailField()  # Target email for the token
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    
    def save(self, *args, **kwargs):
        if not self.token:
            self.token = secrets.token_urlsafe(32)
        if not self.expires_at:
            # Default expiration times
            if self.token_type == 'login_token':
                self.expires_at = timezone.now() + timedelta(hours=1)
            else:
                self.expires_at = timezone.now() + timedelta(days=7)
        super().save(*args, **kwargs)
    
    def is_valid(self):
        return not self.is_used and timezone.now() < self.expires_at
    
    def mark_as_used(self):
        self.is_used = True
        self.used_at = timezone.now()
        self.save()
    
    def __str__(self):
        return f"{self.token_type} - {self.email} - {'Valid' if self.is_valid() else 'Invalid'}"

class LoginSession(models.Model):
    """Track login sessions for non-User entities"""
    SESSION_TYPES = [
        ('client_admin', 'Client Admin'),
        ('stakeholder', 'Stakeholder'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session_key = models.CharField(max_length=255, unique=True)
    session_type = models.CharField(max_length=20, choices=SESSION_TYPES)
    
    # For client admin sessions
    client_admin = models.ForeignKey(
        ClientAdmin,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='login_sessions'
    )
    
    # For stakeholder sessions
    stakeholder = models.ForeignKey(
        Stakeholder,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='login_sessions'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    
    def save(self, *args, **kwargs):
        if not self.session_key:
            self.session_key = secrets.token_urlsafe(32)
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(days=30)  # 30 days session
        super().save(*args, **kwargs)
    
    def is_valid(self):
        return self.is_active and timezone.now() < self.expires_at
    
    def __str__(self):
        entity = self.client_admin or self.stakeholder
        return f"{self.session_type} - {entity} - {'Active' if self.is_valid() else 'Inactive'}"