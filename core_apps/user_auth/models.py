import uuid
from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from core_apps.companydata.models import Company
from .emails import send_account_locked_email
from .managers import UserManager
# from core_apps.company.models import Company
# from core_apps.companydata.models import Company
class User(AbstractUser):
    # uncomment if needed
    # class SecurityQuestions(models.TextChoices):
    #     MAIDEN_NAME = (
    #         "maiden_name",
    #         _("What is your mother's maiden name?"),
    #     )
    #     FAVORITE_COLOR = (
    #         "favorite_color",
    #         _("What is your favorite color?"),
    #     )
    #     BIRTH_CITY = ("birth_city", _("What is the city where you were born?"))
    #     CHILDHOOD_FRIEND = (
    #         "childhood_friend",
    #         _("What is the name of your childhood best friend?"),
    #     )
    class UserRole(models.TextChoices):
        SUPER_ADMIN = 'super_admin', 'Super Admin'
        COMPANY_ADMIN = 'company_admin', 'Company Admin'
        COMPANY_USER = 'company_user', 'Company User'
        STAKEHOLDER = 'stakeholder', 'Stakeholder'

    class AccountStatus(models.TextChoices):
        ACTIVE = "active", _("Active")
        INACTIVE = "inactive", _("Inactive")
        LOCKED = "locked", _("Locked")

    # pkid = models.BigAutoField(primary_key=True, editable=False)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    username = models.CharField(_("Username"), max_length=12, unique=True)
    # uncomment if needed.
    # security_question = models.CharField(
    #     _("Security Question"),
    #     max_length=30,
    #     choices=SecurityQuestions.choices,
    # ) 
    # security_answer = models.CharField(_("Security Answer"), max_length=30)
    email = models.EmailField(_("Email"), unique=True, db_index=True)
    first_name = models.CharField(_("First Name"), max_length=30)
    middle_name = models.CharField(
        _("Middle Name"), max_length=30, blank=True, null=True
    )
    last_name = models.CharField(_("Last Name"), max_length=30)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, null=True, blank=True, related_name='users')
    role = models.CharField(max_length=20, choices=UserRole.choices, default=UserRole.COMPANY_USER)
    # is_company_admin = models.BooleanField(_("Is Company Admin"), default=False)
    # is_decision_maker = models.BooleanField(_("Is Decision Maker"), default=False)
    # company = models.ForeignKey(
    #     Company, on_delete=models.CASCADE, related_name="users", blank=True, null=True
    # )

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
    # override
    objects = UserManager()
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = [
        "first_name",
        "last_name",
        # "id_no",
        # "security_question",
        # "security_answer",
    ]

    def handle_failed_login_attempts(self) -> None:
        self.failed_login_attempts += 1
        self.last_failed_login = timezone.now()
        if self.failed_login_attempts >= settings.LOGIN_ATTEMPTS:
            self.account_status = self.AccountStatus.LOCKED
            self.save()
            send_account_locked_email(self)
        self.save()

    def reset_failed_login_attempts(self) -> None:
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.account_status = self.AccountStatus.ACTIVE
        self.save()

    def unlock_account(self) -> None:
        if self.account_status == self.AccountStatus.LOCKED:
            self.account_status = self.AccountStatus.ACTIVE
            self.failed_login_attempts = 0
            self.last_failed_login = None
            self.save()

    @property
    def is_locked_out(self) -> bool:
        if self.account_status == self.AccountStatus.LOCKED:
            if (
                self.last_failed_login
                and (timezone.now() - self.last_failed_login)
                > settings.LOCKOUT_DURATION
            ):
                self.unlock_account()
                return False
            return True
        return False

    @property
    def full_name(self) -> str:
        full_name = f"{self.first_name} {self.last_name}"
        return full_name.title().strip()

    class Meta:
        verbose_name = _("User")
        verbose_name_plural = _("Users")
        ordering = ["-date_joined"]

    def has_role(self, role_name: str) -> bool:
        return hasattr(self, "role") and self.role == role_name

    def __str__(self) -> str:
        return f"{self.full_name}"
