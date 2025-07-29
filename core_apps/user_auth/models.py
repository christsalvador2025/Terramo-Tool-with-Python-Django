import uuid
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import AbstractUser, UserManager as BaseUserManager
from django.db.models import UniqueConstraint
from django.db.models.functions import Lower
from django.utils.translation import gettext_lazy as _
from .managers import UserManager
from django.conf import settings

# Assuming your Client model is in 'core_apps.clients.models'
# We'll import it here, but ensure there are no circular imports if Client also imports CustomUser
# For simplicity, I'll place Client model in core_apps/clients/models.py first.
# If you have a TimeStampedModel base class, inherit from it.
# For this example, I'll add created_at and updated_at directly to CustomUser and Invitation.


# Custom Manager to handle email as the primary identifier (USERNAME_FIELD)
# class CustomUserManager(BaseUserManager):
#     def create_user(self, email, password=None, **extra_fields):
#         if not email:
#             raise ValueError(_('The Email field must be set'))
#         email = self.normalize_email(email)
#         user = self.model(email=email, **extra_fields)
#         user.set_password(password)
#         user.save(using=self._db)
#         return user

#     def create_superuser(self, email, password=None, **extra_fields):
#         extra_fields.setdefault('is_staff', True)
#         extra_fields.setdefault('is_superuser', True)
#         extra_fields.setdefault('is_active', True)
#         extra_fields.setdefault('role', UserRole.TERRAMO_ADMIN) # Default superuser to Terramo Admin

#         if extra_fields.get('is_staff') is not True:
#             raise ValueError(_('Superuser must have is_staff=True.'))
#         if extra_fields.get('is_superuser') is not True:
#             raise ValueError(_('Superuser must have is_superuser=True.'))
        
#         # Superusers (Terramo Admins) do not have a client
#         if 'client' in extra_fields:
#             del extra_fields['client'] # Ensure client is not set for superusers

#         return self.create_user(email, password, **extra_fields)

# class UserRole(models.TextChoices):
#     TERRAMO_ADMIN = 'terramo_admin', 'Terramo Admin'
#     CLIENT_ADMIN = 'client_admin', 'Client Admin'
#     STAKEHOLDER = 'stakeholder', 'Stakeholder'
class UserRole(models.TextChoices):
    TERRAMO_ADMIN = 'terramo_admin', 'Terramo Admin'
    CLIENT_ADMIN = 'client_admin', 'Client Admin'
    STAKEHOLDER = 'stakeholder', 'Stakeholder'
class User(AbstractUser):
    
    class AccountStatus(models.TextChoices):
        ACTIVE = "active", _("Active")
        INACTIVE = "inactive", _("Inactive")
        LOCKED = "locked", _("Locked")

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    username = models.CharField(_("Username"), max_length=12, unique=True)
    
    # email = models.EmailField(_('email address'), unique=False, blank=False, null=False, db_index=True) 
    email = models.EmailField(_("Email"), unique=True, db_index=True)
    # ^ unique=False here because uniqueness is enforced with client via UniqueConstraint

    role = models.CharField(max_length=20, choices=UserRole.choices, default=UserRole.STAKEHOLDER)
    
    # Client ForeignKey: null=True, blank=True allows Terramo Admins to have no client
    client = models.ForeignKey(
        'clients.Client', # Use string reference to avoid circular import
        on_delete=models.CASCADE, 
        null=True,        
        blank=True,       
        related_name='client_users'
    )
    date_joined = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    account_status = models.CharField(
        _("Account Status"),
        max_length=10,
        choices=AccountStatus.choices,
        default=AccountStatus.ACTIVE,
    )
    failed_login_attempts = models.PositiveSmallIntegerField(default=0)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager() 
    
    # Set email as the primary login field
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = [
        "first_name",
        "last_name"
    ] # No other fields are required for creating a user

    class Meta(AbstractUser.Meta): 
        # Unique email per client, case-insensitive
        constraints = [
            UniqueConstraint(
                fields=['email', 'client'],
                name='unique_email_per_client_constraint'
            ),
            UniqueConstraint(
                Lower('email'),
                'client',
                name='unique_lower_email_per_client_constraint'
            )
        ]
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def __str__(self):
        return self.email # Represent user by email
    def handle_failed_login_attempts(self) -> None:
        self.failed_login_attempts += 1
        self.last_failed_login = timezone.now()
        if self.failed_login_attempts >= settings.LOGIN_ATTEMPTS:
            self.account_status = self.AccountStatus.LOCKED
            self.save()
            # send_account_locked_email(self)
        self.save()
    # Helper properties for easy role checking
    @property
    def is_terramo_admin(self):
        return self.role == UserRole.TERRAMO_ADMIN

    @property
    def is_client_admin(self):
        return self.role == UserRole.CLIENT_ADMIN

    @property
    def is_stakeholder(self):
        return self.role == UserRole.STAKEHOLDER
    
    @property
    def full_name(self) -> str:
        full_name = f"{self.first_name} {self.last_name}"
        return full_name.title().strip()