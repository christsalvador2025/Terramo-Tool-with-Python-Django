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
    # client = models.ForeignKey(Client, on_delete=models.CASCADE, null=True,blank=True, related_name='stakeholder_groups')
    client = models.ForeignKey(
        Client,  
        on_delete=models.CASCADE, 
        related_name='stakeholder_groups',
        null=True, 
        blank=True,
        help_text="Leave empty for templates"
    )
    is_global = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    invitation_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    disable_the_invitation = models.BooleanField(verbose_name=_('Disable the Invitaion'), default=False)
    show_in_table = models.BooleanField(default=False)
    class Meta:
        unique_together = ['name', 'client']
        ordering = ["-is_global", "-name"]
    
    def __str__(self):
        display_str = None
        if self.is_global:
            display_str = "Global: Terramo Admin"
        else:
            display_str =  f"{self.name} - {self.client.company_name}"
        return display_str
    
    def get_invite_full_url(self):
        invite_url = f"{settings.FRONTEND_DOMAIN_URL}/stakeholder/accept-invitation/{self.invitation_token}/"
        if self.created_by.role == "terramo_admin" and self.is_global:
            return invite_url
        return f"{invite_url}client/{self.client.id}"
    
    def save(self, *args, **kwargs):
        # always set the show_in_table to True for global StakeholderGroups
        if self.is_global:
            self.show_in_table = True
       
        super().save(*args, **kwargs)
        
class Stakeholder(models.Model):
    """Stakeholder model - not in User table"""
    # request_count = models.PositiveIntegerField(default=0)
    # last_requested_at = models.DateTimeField(auto_now=True)
    # blocked_until = models.DateTimeField(null=True, blank=True)

    
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
    client = models.ForeignKey(
        Client,
        on_delete=models.CASCADE,
        related_name='clientstakeholders',
        blank=True,
        null=True,
        help_text="Which client this stakeholder belongs to"
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)
    user = models.OneToOneField(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='usr_stakeholder')
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['email', 'group']
    
    def __str__(self):
        return f"{self.email} - {self.group.name}"
    
    # def is_blocked(self):
    #     return self.blocked_until and self.blocked_until > timezone.now()

    # def increment_request(self):
    #     self.request_count += 1
    #     self.last_requested_at = timezone.now()
    #     self.save()

    # def reset_count_if_needed(self):
    #     """Reset daily or after X minutes."""
    #     if timezone.now() - self.last_requested_at > timedelta(minutes=30):
    #         self.request_count = 0
    #         self.save()

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
        return f"{settings.FRONTEND_DOMAIN_URL}/stakeholder/accept-invitation/{self.invitation_token}/"
    
    @property
    def is_expired(self):
       
        return timezone.now() > self.expires_at
"""
UPDATED STAKEHOLDERS: ----- END ------
"""




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
    # need tochange -- id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token = models.UUIDField(
        default=uuid.uuid4, 
        unique=True, 
        editable=False,
        db_index=True,
        verbose_name=_('Token')
    )
    
    stakeholder = models.ForeignKey(
        Stakeholder,
        on_delete=models.CASCADE,
        related_name='login_tokens',
        verbose_name=_('Stakeholder')
    )
    
    stakeholder_invitation = models.ForeignKey(
        StakeholderInvitation,
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
        """Get a valid token by UUID --- validating"""
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





# ========================================================================================================
# |     START: UPDATED OPTIMIZED STAKEHOLDER GROUPS                                                      |
# ========================================================================================================
"""
Optimized Stakeholder Management Models
Following Django best practices for multi-tenant application
"""
import uuid
from django.db import models
from django.core.exceptions import ValidationError
from django.db.models import Q


class StakeholderGroupManager(models.Manager):
    """Custom manager for stakeholder groups with useful querysets"""
    
    def templates(self):
        """Return only template groups"""
        return self.filter(client__isnull=True, template__isnull=True, is_active=True)
    
    def for_client(self, client):
        """Return all groups available to a specific client (templates + their own)"""
        return self.filter(
            Q(client=client) | Q(client__isnull=True, template__isnull=True),
            is_active=True
        ).distinct()
    
    def client_only(self, client):
        """Return groups that belong specifically to a client (not templates)"""
        return self.filter(client=client, is_active=True)
    
    def client_custom(self, client):
        """Return only custom groups created by the client"""
        return self.filter(client=client, template__isnull=True, is_active=True)
    
    def client_instances(self, client):
        """Return only instances created from templates for the client"""
        return self.filter(client=client, template__isnull=False, is_active=True)
    
    def available_to_client(self, client):
        """Return all groups that client can use to create stakeholders"""
        # Templates are globally available + client's own groups
        return self.filter(
            Q(client__isnull=True, template__isnull=True) |  # Global templates
            Q(client=client),  # Client's own groups
            is_active=True
        ).distinct()


class StakeholderGroupTerramo(models.Model):
    """
    Stakeholder groups that can be either:
    - Templates: client=None, template=None (created by terramo_admin)
    - Client instances: client=Client, template=Template (deployed from templates)
    - Custom groups: client=Client, template=None (created by client_admin)
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, db_index=True)
    description = models.TextField(blank=True, help_text="Optional description")
    
    # Nullable for template groups, specific client for instances
    client = models.ForeignKey(
        Client,  
        on_delete=models.CASCADE, 
        related_name='stakeholder_groups_terramo',
        null=True, 
        blank=True,
        help_text="Leave empty for templates"
    )
    
    # Self-referencing for template relationship
    template = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='instances',
        help_text="Template this group was created from"
    )
    
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='created_stakeholder_groups'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True, db_index=True)
    
    # Additional fields for better functionality
    sort_order = models.PositiveIntegerField(default=0, help_text="Display order")
    
    # Manager
    objects = StakeholderGroupManager()

    class Meta:
        db_table = 'stakeholder_group_terramo'
        constraints = [
            # Templates: unique names globally
            models.UniqueConstraint(
                fields=['name'],
                condition=Q(client__isnull=True, template__isnull=True),
                name='unique_template_terramogroup_name'
            ),
            # Client groups: unique names per client
            models.UniqueConstraint(
                fields=['name', 'client'],
                condition=Q(client__isnull=False),
                name='unique_client_terramo_group_name'
            ),
        ]
        
        indexes = [
            models.Index(fields=['client', 'is_active']),
            models.Index(fields=['template']),
            models.Index(fields=['is_active', 'sort_order']),
            models.Index(fields=['created_at']),
        ]
        
        ordering = ['sort_order', 'name']
    
    def __str__(self):
        if self.is_template:
            return f"Template: {self.name}"
        elif self.client:
            return f"{self.client.company_name} - {self.name}"
        return self.name
    
    def clean(self):
        """Model validation"""
        super().clean()
        
        # Validate template logic
        if self.template and self.client is None:
            raise ValidationError("Groups with templates must have a client")
        
        # Validate template cannot reference itself
        if self.template == self:
            raise ValidationError("Template cannot reference itself")
    
    @property
    def is_template(self):
        """Returns True if this is a template"""
        return self.client is None and self.template is None
    
    @property
    def is_custom(self):
        """Returns True if this is a custom client group"""
        return self.client is not None and self.template is None
    
    @property
    def is_from_template(self):
        """Returns True if this was created from a template"""
        return self.template is not None
    
    @property
    def group_type(self):
        """Return human-readable group type"""
        if self.is_template:
            return "Template"
        elif self.is_custom:
            return "Custom"
        elif self.is_from_template:
            return "From Template"
        return "Unknown"
    
    def can_add_stakeholders(self):
        """Check if stakeholders can be added to this group"""
        # Templates (global groups) can have stakeholders from any client
        # Client groups can have stakeholders
        return True
    
    def can_be_used_by_client(self, client):
        """Check if this group can be used by a specific client"""
        if self.is_template:
            return True  # Templates are available to all clients
        return self.client == client  # Client groups only for that client
    
    def get_effective_client_for_stakeholder(self, stakeholder_client=None):
        """
        For templates: return the stakeholder's client
        For client groups: return the group's client
        """
        if self.is_template:
            return stakeholder_client
        return self.client
    
    def can_be_modified_by_user(self, user):
        """Check if user can modify this group"""
        if not user or not user.is_authenticated:
            return False
            
        if hasattr(user, 'role'):
            if user.role == 'terramo_admin':
                return True
            elif user.role == 'client_admin' and self.client == getattr(user, 'client', None):
                return True
        return False
    
    def can_add_stakeholders(self):
        """Check if stakeholders can be added to this group"""
        # Templates (global groups) can have stakeholders from any client
        # Client groups can have stakeholders
        return True
    
    def can_be_used_by_client(self, client):
        """Check if this group can be used by a specific client"""
        if self.is_template:
            return True  # Templates are available to all clients
        return self.client == client  # Client groups only for that client
    
    def get_effective_client_for_stakeholder(self, stakeholder_client=None):
        """
        For templates: return the stakeholder's client
        For client groups: return the group's client
        """
        if self.is_template:
            return stakeholder_client
        return self.client
    
    def can_be_deleted_by_user(self, user):
        """Check if user can delete this group"""
        if not self.can_be_modified_by_user(user):
            return False
        
        # Check if group has stakeholders
        if self.stakeholders.exists():
            return False
            
        return True
    
    def get_stakeholder_count(self):
        """Get number of active stakeholders in this group"""
        return self.stakeholders.filter(is_active=True).count()
    
    def get_stakeholder_count_for_client(self, client):
        """Get number of active stakeholders for a specific client in this group"""
        return self.stakeholders.filter(client=client, is_active=True).count()
    
    def get_stakeholder_users(self, client):
        """Get number of active stakeholders for a specific client in this group"""
        return self.stakeholders.filter(client=client, is_active=True)
  
    def get_pending_invitations_count(self):
        """Get number of pending invitations"""
        return self.invitations.filter(is_active=True, expires_at__gt=timezone.now()).count()
    
    @classmethod
    def create_stakeholder_in_group(cls, group, client, email, **stakeholder_data):
        """Helper method to create a stakeholder in a group with proper validation"""
        if not group.can_be_used_by_client(client):
            raise ValueError(f"Client {client} cannot use group {group}")
        
        # For template groups, any client can add stakeholders
        # For client groups, only that client can add stakeholders
        stakeholder_data.update({
            'group': group,
            'client': client,
            'email': email
        })
        
        return StakeholderTerramo.objects.create(**stakeholder_data)


class StakeholderGroupInvitationManager(models.Manager):
    """Custom manager for invitations"""
    
    def active(self):
        """Return only active, non-expired invitations"""
        return self.filter(
            is_active=True,
            expires_at__gt=timezone.now()
        )
    
    def expired(self):
        """Return expired invitations"""
        return self.filter(expires_at__lte=timezone.now())
    
    def for_group(self, group):
        """Return invitations for a specific group"""
        return self.filter(stakeholder_group=group)


class StakeholderGroupInvitationTerramo(models.Model):
    """
    Temporary invitation links for stakeholder groups
    Generated on-demand with expiration
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    stakeholder_group = models.ForeignKey(
        StakeholderGroupTerramo,
        on_delete=models.CASCADE,
        related_name='invitations'
    )
    
    # Unique invitation token
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    
    # Who created this invitation
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_stakeholder_invitations'
    )
    
    # Timing
    created_at = models.DateTimeField(auto_now_add=True)
    # expires_at = models.DateTimeField()
    expires_at = models.DateTimeField(null=True, blank=True)
    days_to_expire = models.PositiveIntegerField(default=7,verbose_name=_('Days to Expire'))

    # Status
    is_active = models.BooleanField(default=True, db_index=True)
    
    # Usage tracking
    used_at = models.DateTimeField(null=True, blank=True)
    used_by_email = models.EmailField(null=True, blank=True)
    
    # Custom message for this invitation
    message = models.TextField(
        blank=True,
        help_text="Custom invitation message"
    )
    
    # Max usage (0 = unlimited)
    max_uses = models.PositiveIntegerField(default=1, help_text="Maximum number of uses (0 = unlimited)")
    current_uses = models.PositiveIntegerField(default=0)
    
    # Manager
    objects = StakeholderGroupInvitationManager()

    class Meta:
        db_table = 'stakeholder_group_invitation_terramo'
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['expires_at', 'is_active']),
            models.Index(fields=['stakeholder_group', 'is_active']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f"Invitation for {self.stakeholder_group} (expires {self.expires_at.strftime('%Y-%m-%d %H:%M')})"
    
    def clean(self):
        """Model validation"""
        super().clean()
        
        if self.expires_at and self.expires_at <= timezone.now():
            raise ValidationError("Expiry date must be in the future")
    
    @property
    def is_expired(self):
        """Check if invitation has expired"""
        return timezone.now() > self.expires_at
    
    @property
    def is_valid(self):
        """Check if invitation is still valid"""
        if not self.is_active or self.is_expired:
            return False
            
        # Check usage limits
        if self.max_uses > 0 and self.current_uses >= self.max_uses:
            return False
            
        return True
    
    @property
    def remaining_uses(self):
        """Get remaining uses (None if unlimited)"""
        if self.max_uses == 0:
            return None
        return max(0, self.max_uses - self.current_uses)
    
    def get_invitation_url(self):
        """Generate the full invitation URL"""
        base_url = getattr(settings, 'FRONTEND_DOMAIN_URL', 'http://localhost:3000')
        return f"{base_url}/stakeholder/accept-invitation/{self.token}/"
    
    def mark_as_used(self, email=None):
        """Mark invitation as used"""
        if not self.is_valid:
            raise ValidationError("Cannot use invalid invitation")
            
        self.current_uses += 1
        if email:
            self.used_by_email = email
        
        # Mark as used for single-use invitations
        if self.max_uses == 1:
            self.used_at = timezone.now()
            
        self.save(update_fields=['current_uses', 'used_by_email', 'used_at'])
    
    def save(self, *args, **kwargs):
        """Override save to set default expiry"""
        # Set expiry time if not provided (7 days from creation)
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(days=self.days_to_expire or 7)
        super().save(*args, **kwargs)
    
    @classmethod
    def create_invitation(cls, stakeholder_group, created_by, hours_valid=24, message="", max_uses=1):
        """Create a new invitation with expiry"""
        expires_at = timezone.now() + timedelta(hours=hours_valid)
        
        return cls.objects.create(
            stakeholder_group=stakeholder_group,
            created_by=created_by,
            expires_at=expires_at,
            message=message,
            max_uses=max_uses
        )
    
    @classmethod
    def cleanup_expired(cls):
        """Remove expired invitations"""
        expired_count, _ = cls.objects.filter(
            expires_at__lt=timezone.now()
        ).delete()
        return expired_count


class StakeholderTerramoManager(models.Manager):
    """Custom manager for stakeholders"""
    
    def active(self):
        """Return only active stakeholders"""
        return self.filter(is_active=True)
    
    def registered(self):
        """Return only registered stakeholders"""
        return self.filter(is_registered=True)
    
    def pending(self):
        """Return stakeholders with pending status"""
        return self.filter(status='pending')
    
    def for_client(self, client):
        """Return stakeholders for a specific client"""
        return self.filter(group__client=client)
    
    def for_group(self, group):
        """Return stakeholders for a specific group"""
        return self.filter(group=group)


class StakeholderTerramo(models.Model):
    """Stakeholder model - separate from User table for flexibility"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('invited', 'Invited'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('inactive', 'Inactive'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(validators=[EmailValidator()], db_index=True)
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    
    group = models.ForeignKey(
        StakeholderGroupTerramo, 
        on_delete=models.CASCADE, 
        related_name='stakeholders'
    )
    
    # IMPORTANT: For template groups, this indicates which client the stakeholder belongs to
    client = models.ForeignKey(
        Client,
        on_delete=models.CASCADE,
        related_name='stakeholders',
        help_text="Which client this stakeholder belongs to"
    )
    
    is_registered = models.BooleanField(default=False, db_index=True)
    is_active = models.BooleanField(default=True, db_index=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', db_index=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    # User relationship (optional - for registered stakeholders)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='stakeholder_profile'
    )
    
    # Track which invitation was used
    invitation_used = models.ForeignKey(
        StakeholderGroupInvitationTerramo,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resulting_stakeholders'
    )
    
    # Additional fields
    phone = models.CharField(max_length=20, blank=True)
    organization = models.CharField(max_length=200, blank=True)
    role_in_organization = models.CharField(max_length=100, blank=True)
    
    # Manager
    objects = StakeholderTerramoManager()
    
    class Meta:
        db_table = 'stakeholder_terramo'
        constraints = [
            models.UniqueConstraint(
                fields=['email', 'group', 'client'],
                name='unique_stakeholder_per_group_client'
            ),
        ]
        indexes = [
            models.Index(fields=['email', 'is_active']),
            models.Index(fields=['group', 'client', 'status']),
            models.Index(fields=['client', 'is_active']),
            models.Index(fields=['is_registered', 'is_active']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['last_name', 'first_name', 'email']
    
    def __str__(self):
        return f"{self.full_name} ({self.email}) - {self.group.name}"
    
    def clean(self):
        """Model validation"""
        super().clean()
        
        # Validate that client can use this group
        if self.group and not self.group.can_be_used_by_client(self.client):
            raise ValidationError("Client cannot use this stakeholder group")
        
        # For client-specific groups, stakeholder must belong to same client
        if self.group and not self.group.is_template and self.group.client != self.client:
            raise ValidationError("Stakeholder client must match group client")
        
        # Validate status transitions
        if self.pk:  # Existing object
            old_instance = StakeholderTerramo.objects.get(pk=self.pk)
            if old_instance.status == 'approved' and self.status == 'pending':
                raise ValidationError("Cannot change status from approved back to pending")
    
    @property
    def full_name(self):
        """Get full name or email if name is empty"""
        name = f"{self.first_name} {self.last_name}".strip()
        return name if name else self.email
    
    @property
    def display_name(self):
        """Get display name for UI"""
        if self.first_name or self.last_name:
            return self.full_name
        return self.email.split('@')[0]  # Use email prefix if no name
    
    @property
    def effective_client(self):
        """Get the client this stakeholder belongs to"""
        return self.client
    
    def can_be_modified_by_user(self, user):
        """Check if user can modify this stakeholder"""
        if not user or not user.is_authenticated:
            return False
            
        if hasattr(user, 'role'):
            if user.role == 'terramo_admin':
                return True
            elif user.role == 'client_admin' and self.client == getattr(user, 'client', None):
                return True
        return False
    
    def approve(self, approved_by=None):
        """Approve stakeholder"""
        self.status = 'approved'
        self.save(update_fields=['status', 'updated_at'])
    
    def reject(self, rejected_by=None):
        """Reject stakeholder"""
        self.status = 'rejected'
        self.save(update_fields=['status', 'updated_at'])
    
    def deactivate(self):
        """Deactivate stakeholder"""
        self.is_active = False
        self.status = 'inactive'
        self.save(update_fields=['is_active', 'status', 'updated_at'])
    
    def reactivate(self):
        """Reactivate stakeholder"""
        self.is_active = True
        if self.status == 'inactive':
            self.status = 'approved'  # or whatever default active status
        self.save(update_fields=['is_active', 'status', 'updated_at'])
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = timezone.now()
        self.save(update_fields=['last_login'])


# Additional utility models/functions can be added here
class StakeholderActivityLog(models.Model):
    """Log stakeholder activities for auditing"""
    
    stakeholder = models.ForeignKey(
        StakeholderTerramo,
        on_delete=models.CASCADE,
        related_name='activity_logs'
    )
    
    action = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    performed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        db_table = 'stakeholder_activity_log'
        indexes = [
            models.Index(fields=['stakeholder', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
        ]
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.stakeholder.email} - {self.action} at {self.timestamp}"
# =======================================================================================================
# |     END: UPDATED OPTIMIZED STAKEHOLDER GROUPS                                                       |
# =======================================================================================================