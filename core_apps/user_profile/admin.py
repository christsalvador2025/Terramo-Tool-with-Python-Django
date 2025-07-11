from django.contrib import admin
from cloudinary.forms import CloudinaryFileField
from django import forms
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import Profile


class ProfileAdminForm(forms.ModelForm):
    # photo = CloudinaryFileField(
    #     options={"crop": "thumb", "width": 200, "height": 200, "folder": "bank_photos"},
    #     required=False,
    # )

    class Meta:
        model = Profile
        fields = "__all__"



@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    form = ProfileAdminForm
    list_display = [
        "user",
        "full_name",
        "country_name",
        "country_code",
        "phone_number",
        "email",

    ]
    list_display_links = ["user"]
    list_filter = ["gender", "country"]
    search_fields = [
        "user__email", 
        "user__first_name",
        "user__last_name",
        "phone_number",
    ]
    readonly_fields = ["user"]
    fieldsets = (
        (
            _("Personal Information"),
            {
                "fields": (
                    "user",

                    "title",
                    "gender",
                    "date_of_birth",
                )
            },
        ),
        (
            _("Contact Information"),
            {"fields": ("phone_number", "address", "city", "country")},
        ),
        
    )


    def full_name(self, obj) -> str:
        return obj.user.full_name

    full_name.short_description = _("Full name")

    def email(self, obj) -> str:
        return obj.user.email

    email.short_description = _("Email")

    def country_name(self, obj):
        return obj.country.name if obj.country else "-"
    country_name.short_description = "Country"

    def country_code(self, obj):
        return obj.country.code if obj.country else "-"
    country_code.short_description = "ISO Code"

 
