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
from core_apps.clients.models import Client
import hashlib
from django.utils.translation import gettext_lazy as _
from core_apps.clients.models import Client
from core_apps.user_auth.models import User
# User = settings.AUTH_USER_MODEL
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

# class Client(models.Model):
#     """Client company model"""
#     PRODUCT_CHOICES = [
#         ('esg_check', 'ESG-Check'),
#         ('stakeholder_analysis', 'Stakeholder Analysis'),
#         ('materiality_analysis', 'Materiality Analysis'),
#     ]
    
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     company_name = models.CharField(max_length=255)
#     company_contact_email = models.EmailField()
#     date_required = models.DateField()
    
#     # Product details - can select multiple
#     products = models.JSONField(default=list)  # Store selected products as list
    
#     # Contact person details
#     first_name = models.CharField(max_length=100)
#     last_name = models.CharField(max_length=100)
#     gender = models.CharField(
#         max_length=40,
#         choices=[
#             ('male', 'Male'),
#             ('female', 'Female'),
#             ('other', 'Other'),
#             ('prefer_not_to_say', 'Prefer not to say')
#         ],
#         blank=True
#     )
#     birth_year = models.IntegerField(null=True, blank=True)
    
#     # Address details
#     street = models.CharField(max_length=255)
#     postal_code = models.CharField(max_length=20)
#     city = models.CharField(max_length=100)
#     country = models.CharField(max_length=100)
    
#     # Contact details
#     phone_number = models.CharField(max_length=20)
#     mobile_number = models.CharField(max_length=20, blank=True)
#     email = models.EmailField()
    
#     # Additional info
#     internal_processing_note = models.TextField(blank=True)
    
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)
#     created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
#     def __str__(self):
#         return f"{self.company_name} - {self.first_name} {self.last_name}"

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
    

"""
UPDATED STAKEHOLDERS: ------ START ------
"""
# models.py
import uuid
from django.db import models
# from django.contrib.auth.models import User
 
class StakeholderGroup(models.Model):
    """Stakeholder groups created by Client Admin"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='stakeholder_groups')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    invitation_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)

    class Meta:
        unique_together = ['name', 'client']
    
    def __str__(self):
        return f"{self.name} - {self.client.company_name}"
    
    def get_invite_full_url(self):
        return f"{settings.DOMAIN}/stakeholder/invite/{self.invitation_token}/"

class Stakeholder(models.Model):
    """Stakeholder model - not in User table"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(validators=[EmailValidator()])
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    group = models.ForeignKey(StakeholderGroup, on_delete=models.CASCADE, related_name='stakeholders')
    is_registered = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)
    user = models.OneToOneField(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='usr_stakeholder')
    
    class Meta:
        unique_together = ['email', 'group']
    
    def __str__(self):
        return f"{self.email} - {self.group.name}"

class StakeholderInvitation(models.Model):
    """Track stakeholder invitations"""
    
    STATUS_CHOICES = [
        ('sent', 'Sent'),
        ('clicked', 'Clicked'),
        ('email_verified', 'Email Verified'),
        ('completed', 'Registration Completed'),
        ('expired', 'Expired'),
    ]
    
    EMAIL_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('delivered', 'Delivered'),
        ('bounced', 'Bounced'),
        ('rejected', 'Rejected'),
        ('failed', 'Failed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    stakeholder_group = models.ForeignKey(StakeholderGroup, on_delete=models.CASCADE, related_name='invitations')
    email = models.EmailField(validators=[EmailValidator()])
    invitation_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='sent')
    email_status = models.CharField(max_length=20, choices=EMAIL_STATUS_CHOICES, default='pending')
    
    # Tracking fields
    sent_at = models.DateTimeField(auto_now_add=True)
    clicked_at = models.DateTimeField(null=True, blank=True)
    email_verified_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Additional fields
    sent_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_invitations')
    expires_at = models.DateTimeField()
    
    # Optional: 
    stakeholder = models.ForeignKey(Stakeholder, on_delete=models.SET_NULL, null=True, blank=True, related_name='invitations')
    
    class Meta:
        unique_together = ['email', 'stakeholder_group']
    
    def __str__(self):
        return f"Invitation to {self.email} for {self.stakeholder_group.name}"
    
    def get_invitation_url(self):
        return f"{settings.DOMAIN}/stakeholder/invite/{self.invitation_token}/"
    
    @property
    def is_expired(self):
       
        return timezone.now() > self.expires_at
"""
UPDATED STAKEHOLDERS: ----- END ------
"""


# class StakeholderGroup(models.Model):
#     """Stakeholder groups created by Client Admin"""
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     name = models.CharField(max_length=100)
#     client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='stakeholder_groups')
#     created_by = models.ForeignKey(User, on_delete=models.CASCADE)
#     created_at = models.DateTimeField(auto_now_add=True)
#     is_active = models.BooleanField(default=True)
#     invitation_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)

#     class Meta:
#         unique_together = ['name', 'client']
    
#     def __str__(self):
#         return f"{self.name} - {self.client.company_name}"
#     def get_invite_full_url(self):
#         return f"{settings.DOMAIN}/{self.invitation_token}/"
    
# class Stakeholder(models.Model):
#     """Stakeholder model - not in User table"""
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     email = models.EmailField(validators=[EmailValidator()])
#     first_name = models.CharField(max_length=100, blank=True)
#     last_name = models.CharField(max_length=100, blank=True)
#     group = models.ForeignKey(StakeholderGroup, on_delete=models.CASCADE, related_name='stakeholders')
#     is_registered = models.BooleanField(default=False)
#     created_at = models.DateTimeField(auto_now_add=True)
#     last_login = models.DateTimeField(null=True, blank=True)
    
#     class Meta:
#         unique_together = ['email', 'group']
    
#     def __str__(self):
#         return f"{self.email} - {self.group.name}"

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

# class InvitationTokenData(models.Model):
#     TOKEN_TYPES = [
#         ('client_admin_invite', 'Client Admin Invitation'),
#         ('stakeholder_invite', 'Stakeholder Invitation'),
#         ('login_token', 'Login Token'),
#     ]
    
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     token = models.UUIDField(default=uuid.uuid4, unique=True)
#     token_type = models.CharField(max_length=30, choices=TOKEN_TYPES)
#     email = models.EmailField(validators=[EmailValidator()])
    
#     # Foreign keys for different token types
#     client_admin = models.ForeignKey(ClientAdmin, on_delete=models.CASCADE, null=True, blank=True, related_name='clientadmin_invitation_tokens')
#     stakeholder = models.ForeignKey(Stakeholder, on_delete=models.CASCADE, null=True, blank=True, related_name='stakeholder_invitation_tokens')
#     created_by_user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='user_tokens_created')
#     created_by_client_admin = models.ForeignKey(ClientAdmin, on_delete=models.CASCADE, null=True, blank=True, related_name='tokens_created_by_client')
    
#     is_used = models.BooleanField(default=False)
#     is_active = models.BooleanField(default=True)
#     expires_at = models.DateTimeField()
#     used_at = models.DateTimeField(null=True, blank=True)
#     created_at = models.DateTimeField(auto_now_add=True)
    
#     def save(self, *args, **kwargs):
#         if not self.expires_at:
#             if self.token_type == 'login_token':
#                 self.expires_at = timezone.now() + timedelta(hours=1)  # 1 hour for login tokens
#             else:
#                 self.expires_at = timezone.now() + timedelta(days=7)  # 7 days for invitation tokens
#         super().save(*args, **kwargs)
    
#     def is_expired(self):
#         return timezone.now() > self.expires_at
    
#     def is_valid(self):
#         return self.is_active and not self.is_used and not self.is_expired()
    
#     def mark_as_used(self):
#         self.is_used = True
#         self.used_at = timezone.now()
#         self.save()
    
#     class Meta:
#         unique_together = ['token', 'token_type']
    
#     def __str__(self):
#         return f"{self.get_token_type_display()} - {self.email}"
    
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
    



"""
Token BASE Authentication
"""

class TokenManager(models.Manager):
    """Custom manager for token operations"""
    
    def create_token(self, user, token_type, expires_in_hours=1, metadata=None):
        """Create a new token"""
        # Generate cryptographically secure token
        raw_token = secrets.token_urlsafe(32)
        
        # Hash the token for storage (never store raw tokens)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        expires_at = timezone.now() + timedelta(hours=expires_in_hours)
        
        token = self.create(
            user=user,
            token_type=token_type,
            token_hash=token_hash,
            expires_at=expires_at,
            metadata=metadata or {}
        )
        
        # Return both the model instance and raw token
        # Raw token is only available here - never stored
        return token, raw_token
    
    def get_valid_token(self, raw_token, token_type=None):
        """Get valid token by raw token string"""
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        queryset = self.filter(
            token_hash=token_hash,
            is_active=True,
            expires_at__gt=timezone.now(),
            used_at__isnull=True
        )
        
        if token_type:
            queryset = queryset.filter(token_type=token_type)
        
        return queryset.first()
    
    def cleanup_expired(self):
        """Remove expired tokens"""
        expired_count = self.filter(
            expires_at__lt=timezone.now()
        ).delete()[0]
        return expired_count
    
    def revoke_user_tokens(self, user, token_type=None):
        """Revoke all tokens for a user"""
        queryset = self.filter(user=user, is_active=True)
        if token_type:
            queryset = queryset.filter(token_type=token_type)
        
        return queryset.update(
            is_active=False,
            revoked_at=timezone.now()
        )


class AuthToken(models.Model):
    """
    Secure token model for various authentication purposes
    
    Features:
    - Supports multiple token types (login, password reset, email verification, etc.)
    - Cryptographically secure token generation
    - Token hashing (never store raw tokens)
    - Automatic expiration
    - Usage tracking and audit trail
    - Rate limiting support
    - IP and device tracking
    """
    
    class TokenType(models.TextChoices):
        LOGIN = 'login', _('Login Link')
        PASSWORD_RESET = 'password_reset', _('Password Reset')
        EMAIL_VERIFICATION = 'email_verification', _('Email Verification')
        ACCOUNT_ACTIVATION = 'account_activation', _('Account Activation')
        TWO_FACTOR = 'two_factor', _('Two Factor Authentication')
        API_ACCESS = 'api_access', _('API Access')
    
    class TokenStatus(models.TextChoices):
        ACTIVE = 'active', _('Active')
        USED = 'used', _('Used')
        EXPIRED = 'expired', _('Expired')
        REVOKED = 'revoked', _('Revoked')
    
    # ============================================================================
    # CORE FIELDS
    # ============================================================================
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4, 
        editable=False
    )
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='auth_tokens',
        verbose_name=_("User")
    )
    
    token_type = models.CharField(
        _("Token Type"),
        max_length=20,
        choices=TokenType.choices,
        db_index=True
    )
    
    token_hash = models.CharField(
        _("Token Hash"),
        max_length=64,  # SHA256 hash length
        unique=True,
        db_index=True,
        help_text=_("Hashed version of the actual token")
    )
    
    # ============================================================================
    # TIME TRACKING
    # ============================================================================
    created_at = models.DateTimeField(
        _("Created At"),
        auto_now_add=True,
        db_index=True
    )
    
    expires_at = models.DateTimeField(
        _("Expires At"),
        db_index=True,
        help_text=_("When this token expires")
    )
    
    used_at = models.DateTimeField(
        _("Used At"),
        null=True,
        blank=True,
        help_text=_("When this token was successfully used")
    )
    
    revoked_at = models.DateTimeField(
        _("Revoked At"),
        null=True,
        blank=True,
        help_text=_("When this token was revoked")
    )
    
    last_attempted_at = models.DateTimeField(
        _("Last Attempted At"),
        null=True,
        blank=True,
        help_text=_("Last time someone tried to use this token")
    )
    
    # ============================================================================
    # STATUS AND SECURITY
    # ============================================================================
    is_active = models.BooleanField(
        _("Active"),
        default=True,
        db_index=True
    )
    
    attempt_count = models.PositiveSmallIntegerField(
        _("Attempt Count"),
        default=0,
        help_text=_("Number of times this token was attempted")
    )
    
    max_attempts = models.PositiveSmallIntegerField(
        _("Max Attempts"),
        default=3,
        help_text=_("Maximum number of attempts before token is revoked")
    )
    
    # ============================================================================
    # TRACKING AND METADATA
    # ============================================================================
    created_ip = models.GenericIPAddressField(
        _("Created IP"),
        null=True,
        blank=True,
        help_text=_("IP address when token was created")
    )
    
    used_ip = models.GenericIPAddressField(
        _("Used IP"),
        null=True,
        blank=True,
        help_text=_("IP address when token was used")
    )
    
    user_agent = models.TextField(
        _("User Agent"),
        blank=True,
        help_text=_("Browser user agent when token was used")
    )
    
    metadata = models.JSONField(
        _("Metadata"),
        default=dict,
        blank=True,
        help_text=_("Additional data related to this token")
    )
    
    # Custom manager
    objects = TokenManager()
    
    class Meta:
        verbose_name = _('Authentication Token')
        verbose_name_plural = _('Authentication Tokens')
        ordering = ['-created_at']
        
        indexes = [
            models.Index(fields=['user', 'token_type'], name='token_user_type_idx'),
            models.Index(fields=['token_type', 'is_active'], name='token_type_active_idx'),
            models.Index(fields=['expires_at', 'is_active'], name='token_expires_active_idx'),
            models.Index(fields=['created_at'], name='token_created_idx'),
        ]
        
        constraints = [
            # Prevent too many active tokens per user per type
            models.UniqueConstraint(
                fields=['user', 'token_type'],
                condition=models.Q(is_active=True, token_type='login'),
                name='one_active_login_token_per_user'
            ),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.get_token_type_display()} ({self.status})"
    
    # ============================================================================
    # PROPERTIES
    # ============================================================================
    @property
    def status(self):
        """Get current token status"""
        if not self.is_active:
            if self.revoked_at:
                return self.TokenStatus.REVOKED
            return self.TokenStatus.EXPIRED
        
        if self.used_at:
            return self.TokenStatus.USED
        
        if self.is_expired:
            return self.TokenStatus.EXPIRED
        
        return self.TokenStatus.ACTIVE
    
    @property
    def is_expired(self):
        """Check if token is expired"""
        return timezone.now() > self.expires_at
    
    @property
    def is_valid(self):
        """Check if token is valid for use"""
        return (
            self.is_active 
            and not self.is_expired 
            and not self.used_at 
            and self.attempt_count < self.max_attempts
        )
    
    @property
    def time_until_expiry(self):
        """Get time until expiration"""
        if self.is_expired:
            return timedelta(0)
        return self.expires_at - timezone.now()
    
    @property
    def expires_in_minutes(self):
        """Get minutes until expiration"""
        delta = self.time_until_expiry
        return int(delta.total_seconds() / 60)
    
    # ============================================================================
    # METHODS
    # ============================================================================
    def use_token(self, ip_address=None, user_agent=None):
        """Mark token as used"""
        if not self.is_valid:
            return False
        
        self.used_at = timezone.now()
        self.used_ip = ip_address
        self.user_agent = user_agent
        self.save()
        return True
    
    def record_attempt(self, ip_address=None):
        """Record a usage attempt"""
        self.attempt_count += 1
        self.last_attempted_at = timezone.now()
        
        if ip_address and not self.used_ip:
            self.used_ip = ip_address
        
        # Auto-revoke if too many attempts
        if self.attempt_count >= self.max_attempts:
            self.revoke()
        else:
            self.save()
    
    def revoke(self, reason=None):
        """Revoke the token"""
        self.is_active = False
        self.revoked_at = timezone.now()
        
        if reason:
            self.metadata['revoked_reason'] = reason
        
        self.save()
    
    def extend_expiry(self, hours=1):
        """Extend token expiry"""
        if self.is_valid:
            self.expires_at = timezone.now() + timedelta(hours=hours)
            self.save()
    
    def clean(self):
        """Validate token"""
        from django.core.exceptions import ValidationError
        
        # Ensure expiry is in the future
        if self.expires_at and self.expires_at <= timezone.now():
            raise ValidationError({
                'expires_at': _('Expiry date must be in the future.')
            })
        
        # Validate max attempts
        if self.max_attempts <= 0:
            raise ValidationError({
                'max_attempts': _('Max attempts must be greater than 0.')
            })


# =============================================================================
# LOGIN TOKEN SPECIFIC MODEL (Optional - for additional login-specific features)
# =============================================================================
from core_apps.common.models import TimeStampedModel
class EmailLoginToken(TimeStampedModel):
    """
    Table for requested
    """
    
class LoginToken(models.Model):
    """
    Specialized login token with additional features
    This extends the base AuthToken for login-specific functionality
    """
    
    auth_token = models.OneToOneField(
        AuthToken,
        on_delete=models.CASCADE,
        primary_key=True,
        limit_choices_to={'token_type': AuthToken.TokenType.LOGIN}
    )
    
    # ============================================================================
    # LOGIN-SPECIFIC FIELDS
    # ============================================================================
    redirect_url = models.URLField(
        _("Redirect URL"),
        blank=True,
        help_text=_("URL to redirect to after successful login")
    )
    
    login_method = models.CharField(
        _("Login Method"),
        max_length=20,
        choices=[
            ('email_link', _('Email Link')),
            ('sms_link', _('SMS Link')),
            ('qr_code', _('QR Code')),
        ],
        default='email_link'
    )
    
    device_info = models.JSONField(
        _("Device Info"),
        default=dict,
        blank=True,
        help_text=_("Information about the device requesting login")
    )
    
    # Geographic location (optional)
    location_data = models.JSONField(
        _("Location Data"),
        default=dict,
        blank=True,
        help_text=_("Geographic location data when token was created/used")
    )
    
    # Security flags
    requires_2fa = models.BooleanField(
        _("Requires 2FA"),
        default=False,
        help_text=_("Whether this login requires two-factor authentication")
    )
    
    is_suspicious = models.BooleanField(
        _("Suspicious Activity"),
        default=False,
        help_text=_("Flagged for suspicious activity")
    )
    
    class Meta:
        verbose_name = _('Login Token')
        verbose_name_plural = _('Login Tokens')
    
    def __str__(self):
        return f"Login token for {self.auth_token.user.email}"
    
    @property
    def user(self):
        """Get the user associated with this login token"""
        return self.auth_token.user
    
    def generate_login_url(self, base_url=None):
        """Generate the complete login URL"""
        if not base_url:
            base_url = settings.FRONTEND_DOMAIN_URL
        
        # Note: You'll need to implement a way to get the raw token
        # This is just for demonstration
        return f"{base_url}/auth/login-with-token/{self.auth_token.id}/"


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def create_login_token(user, expires_in_hours=1, ip_address=None, 
                      redirect_url=None, device_info=None):
    """
    Utility function to create a login token
    """
    # Revoke any existing active login tokens for this user
    AuthToken.objects.revoke_user_tokens(user, AuthToken.TokenType.LOGIN)
    
    # Create new auth token
    auth_token, raw_token = AuthToken.objects.create_token(
        user=user,
        token_type=AuthToken.TokenType.LOGIN,
        expires_in_hours=expires_in_hours,
        metadata={'created_for': 'login_request'}
    )
    
    # Set the IP address if provided
    if ip_address:
        auth_token.created_ip = ip_address
        auth_token.save()
    
    # Create login-specific token (optional)
    login_token = LoginToken.objects.create(
        auth_token=auth_token,
        redirect_url=redirect_url or '',
        device_info=device_info or {}
    )
    
    return login_token, raw_token


def verify_login_token(raw_token, ip_address=None, user_agent=None):
    """
    Utility function to verify and use a login token
    """
    auth_token = AuthToken.objects.get_valid_token(
        raw_token=raw_token,
        token_type=AuthToken.TokenType.LOGIN
    )
    
    if not auth_token:
        return None, "Invalid or expired token"
    
    # Record the attempt
    auth_token.record_attempt(ip_address)
    
    if not auth_token.is_valid:
        return None, "Token has been revoked due to too many attempts"
    
    # Use the token
    success = auth_token.use_token(ip_address, user_agent)
    
    if success:
        return auth_token.user, None
    else:
        return None, "Failed to use token"


# =============================================================================
# CLEANUP TASK (for periodic cleanup)
# =============================================================================

def cleanup_expired_tokens():
    """
    Function to clean up expired tokens
    Run this periodically (e.g., daily cron job)
    """
 
  
    
    # Remove tokens expired more than 30 days ago
    cleanup_date = timezone.now() - timedelta(days=30)
    
    deleted_count = AuthToken.objects.filter(
        expires_at__lt=cleanup_date
    ).delete()[0]
    
    return deleted_count


"""
AUTHENTICATION FOR STAKEHOLDERS
"""
class StakeholderLoginToken(models.Model):
    """
    Secure storage for stakeholder login tokens
    """
    token = models.UUIDField(
        default=uuid.uuid4, 
        unique=True, 
        editable=False,
        db_index=True,
        verbose_name=_('Token')
    )
    
    stakeholder = models.ForeignKey(
        'Stakeholder',
        on_delete=models.CASCADE,
        related_name='login_tokens',
        verbose_name=_('Stakeholder')
    )
    
    stakeholder_invitation = models.ForeignKey(
        'StakeholderInvitation',
        on_delete=models.CASCADE,
        related_name='login_tokens',
        null=True,
        blank=True,
        verbose_name=_('Stakeholder Invitation')
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
        verbose_name = _('Stakeholder Login Token')
        verbose_name_plural = _('Stakeholder Login Tokens')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['stakeholder', 'is_used']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"Login Token for {self.stakeholder.email} - {'Used' if self.is_used else 'Valid'}"

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
            token = cls.objects.select_related('stakeholder', 'stakeholder_invitation').get(
                token=token_uuid,
                is_used=False,
                expires_at__gt=timezone.now()
            )
            return token
        except cls.DoesNotExist:
            return None

    def get_login_url(self):
        """Generate the login URL"""
        return f"{settings.FRONTEND_DOMAIN_URL}/stakeholder/login/{self.token}/"