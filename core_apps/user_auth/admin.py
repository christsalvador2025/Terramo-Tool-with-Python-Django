from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from .models import User
from .forms import UserChangeForm, UserCreationForm


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm
    model = User
    list_display = [
        "id",
        "email",
        "username",
        "first_name",
        "last_name",
        # "client",
        "role",
  
        "is_active"
        
    ]
    list_filter = ["email", "is_staff", "is_active"]
    


    # fieldsets will show the editable form in the admin dashboards
    fieldsets = (
        (
            _("Login Credentials"),
            {
                "fields": (
         
                    "email",
                    "password",
                    
                )
            },
        ),
        (
            _("Personal Information"),
            {"fields": ("first_name", "last_name")},
        ),
        (
            _("Account Status"),
            {
                "fields": (
                    "account_status",
                    # "client",
                    "role",
                    # "is_company_admin",
                    # "is_decision_maker",
                    # "company",
                    "failed_login_attempts",
                    "last_failed_login",
                )
            },
        ),
        
        # (
        #     _("Permissions and Groups"),
        #     {
        #         "fields": (
        #             "is_active",
        #             "is_staff",
        #             "is_superuser",
        #             "groups",
        #             "user_permissions",
        #         )
        #     },
        # ),
        (
            _("Important dates"),
            {
                "fields": (
                    "last_login",
                    "date_joined",
                )
            },
        ),
    )
    search_fields = ["email", "username", "first_name", "last_name"]
    ordering = ["email"]
