from typing import Any

from cloudinary.models import CloudinaryField
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from django_countries.fields import CountryField
from phonenumber_field.modelfields import PhoneNumberField

from core_apps.common.models import TimeStampedModel
# from core_apps.accounts.models import BankAccount

User = get_user_model()


class Profile(TimeStampedModel):
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

    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    title = models.CharField(
        _("Salutation"), max_length=5, choices=Salutation.choices, default=Salutation.MR
    )
    gender = models.CharField(
        _("Gender"), max_length=8, choices=Gender.choices, default=Gender.MALE
    )
    date_of_birth = models.DateField(
        _("Date of Birth"), default=settings.DEFAULT_BIRTH_DATE
    )
    country_of_birth = CountryField(
        _("Country of Birth"), default=settings.DEFAULT_COUNTRY
    )
    place_of_birth = models.CharField(
        _("Place of Birth"), max_length=50, default="Unknown"
    )
    
    nationality = models.CharField(_("Nationality"), max_length=30, default="Unknown")
    phone_number = PhoneNumberField(
        _("Phone Number"), max_length=30, default=settings.DEFAULT_PHONE_NUMBER
    )
    address = models.CharField(_("Address"), max_length=100, default="Unknown")
    city = models.CharField(_("City"), max_length=50, default="Unknown")
    country = CountryField(_("Country"), default=settings.DEFAULT_COUNTRY)
    employer_name = models.CharField(
        _("Employer Name"),
        max_length=50,
        blank=True,
        null=True,
    )
   

    def save(self, *args: Any, **kwargs: Any) -> None:
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.title} {self.user.first_name}'s Profile"

