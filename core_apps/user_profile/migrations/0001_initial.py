# Generated by Django 4.2.15 on 2025-07-11 02:49

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django_countries.fields
import phonenumber_field.modelfields
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Profile",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "title",
                    models.CharField(
                        choices=[("mr", "Mr"), ("mrs", "Mrs"), ("miss", "Miss")],
                        default="mr",
                        max_length=5,
                        verbose_name="Salutation",
                    ),
                ),
                (
                    "gender",
                    models.CharField(
                        choices=[("male", "Male"), ("female", "Female")],
                        default="male",
                        max_length=8,
                        verbose_name="Gender",
                    ),
                ),
                (
                    "date_of_birth",
                    models.DateField(
                        default=datetime.date(1900, 1, 1), verbose_name="Date of Birth"
                    ),
                ),
                (
                    "country_of_birth",
                    django_countries.fields.CountryField(
                        default="US", max_length=2, verbose_name="Country of Birth"
                    ),
                ),
                (
                    "place_of_birth",
                    models.CharField(
                        default="Unknown", max_length=50, verbose_name="Place of Birth"
                    ),
                ),
                (
                    "nationality",
                    models.CharField(
                        default="Unknown", max_length=30, verbose_name="Nationality"
                    ),
                ),
                (
                    "phone_number",
                    phonenumber_field.modelfields.PhoneNumberField(
                        default="+250784123456",
                        max_length=30,
                        region=None,
                        verbose_name="Phone Number",
                    ),
                ),
                (
                    "address",
                    models.CharField(
                        default="Unknown", max_length=100, verbose_name="Address"
                    ),
                ),
                (
                    "city",
                    models.CharField(
                        default="Unknown", max_length=50, verbose_name="City"
                    ),
                ),
                (
                    "country",
                    django_countries.fields.CountryField(
                        default="US", max_length=2, verbose_name="Country"
                    ),
                ),
                (
                    "employer_name",
                    models.CharField(
                        blank=True,
                        max_length=50,
                        null=True,
                        verbose_name="Employer Name",
                    ),
                ),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="profile",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
    ]
