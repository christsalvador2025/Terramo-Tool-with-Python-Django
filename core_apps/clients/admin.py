from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from .models import Client, ClientProduct

@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "company_name",
        "email",
        "land",
    ]
    fieldsets = (
        
        ('Company Information', { 
            'fields': ('company_name', 'date', 'company_photo', 'role',)
        }),
        ('Contact Person', { 
            'fields': ('contact_person_first_name', 'contact_person_last_name', 'gender', 'year_of_birth', ),
            'description': 'Information about the primary contact for this client.', 
        }),
        ('Address Details', { 
            'fields': ('street', 'zip_code', 'location', 'landline_number', 'mobile_phone_number', 'city', 'land','email',),
            'description': 'Information about the address of the client', 
        }),
        (None, {"fields": ("is_active",'miscellaneous',)}),
    )

    readonly_fields = ["id", "invitation_token"]
    list_filter = ["company_name"]

@admin.register(ClientProduct)
class ClientProductAdmin(admin.ModelAdmin):

    list_display = [
        "id",
        "client",
        "product",
        "purchased_at",
        'expires_at'

    ]
    list_filter = ["client", "product"]