from django.contrib import admin
from cloudinary.forms import CloudinaryFileField
from django import forms
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from core_apps.common.admin_mixins import SuperuserOnlyAdmin
from .models import Product,Company, CompanyProduct,ESGCategory,ESGQuestion,StakeholderGroup,StakeholderUser,ESGResponse,ESGResponseComment,StakeholderInvitation,AuditLog


@admin.register(Company)
class CompanyAdmin(SuperuserOnlyAdmin):
    list_display = [
        "id",
        "name",
        "contact_person_name",
        "contact_person_email",
    ]
    fieldsets = (
        (None, { # This is the first fieldset, "None" means no heading
            'fields': ('name', 'email', 'phone', 'address', 'is_active', 'country','created_by',)
        }),
        ('Contact Person', { # This is your new fieldset with a heading
            'fields': ('contact_person_name', 'contact_person_email', 'contact_person_phone'),
            'description': 'Information about the primary contact for this company.', # Optional: adds a small description
            # 'classes': ('collapse',), # Optional: Makes this section collapsible by default
        }),
    )

@admin.register(Product)
class ProductAdmin(SuperuserOnlyAdmin):
    list_display = [
        "id",
        "name",
        "price",
    ]


@admin.register(CompanyProduct)
class CompanyProductAdmin(SuperuserOnlyAdmin):

    list_display = [
        "id",
        "company",
        "product",
        "purchased_at",
        'expires_at'

    ]
    # fieldsets = (
    
    # (None, {  
    #     'fields': ('company', 'product', 'purchased_at', 'expires_at', 'is_active'),
    #     'description': 'Purchased product information.'  
    # }),
    # )
@admin.register(ESGCategory)
class ESGCategoryAdmin(SuperuserOnlyAdmin):
    list_display = [
        "id",
        "name",
        "type",
    ]


@admin.register(ESGQuestion)
class ESGQuestionAdmin(SuperuserOnlyAdmin):
    list_display = [
        "id",
        "category",
        "measure_key",
        "question_text",
        "question_type",
    ]


@admin.register(StakeholderGroup)
class StakeholderGroupAdmin(SuperuserOnlyAdmin):
    list_display = [
        "id",
        "company",
        "name",
        "invite_token",
        "is_active",
    ]
    list_filter = ["company", "name", "is_active"]
    readonly_fields = ["invite_token"]
    
@admin.register(StakeholderUser)
class StakeholderUserAdmin(SuperuserOnlyAdmin):
    pass

@admin.register(ESGResponse)
class ESGResponseAdmin(SuperuserOnlyAdmin):
    list_display = [
        "id",
        "company",
        "question",
        "user",
    ]

@admin.register(ESGResponseComment)
class ESGResponseCommentAdmin(SuperuserOnlyAdmin):
    pass

@admin.register(StakeholderInvitation)
class StakeholderInvitationAdmin(SuperuserOnlyAdmin):
    list_display = [
        "id",
        "stakeholder_group",
        "email",
        "token",
        "status",
        "sent_at",
        "accepted_at",
        "expires_at",
    ]
    
    readonly_fields = ["token"]

@admin.register(AuditLog)
class AuditLogAdmin(SuperuserOnlyAdmin):
    list_display = [
        "id",
        "user",
        "action",
        "model_name",
        "object_id",
        "ip_address",
        "user_agent",
        "timestamp",
    ]
 
    # list_display = [
    #     "id",
    #     "company_name",
    #     "created_by_name",
    #     "updated_by_name",
    #     "created_at",
    #     "updated_at",
    # ]

    # def created_by_name(self, obj):
    #     return obj.created_by.get_full_name() if obj.created_by else "-"
    # created_by_name.short_description = 'Created By'

    # def updated_by_name(self, obj):
    #     return obj.updated_by.get_full_name() if obj.updated_by else "-"
    # updated_by_name.short_description = 'Updated By'

    
    
    # # list_display_links = ["user"]
    # list_filter = ["company_name", "created_by", "updated_by"]
    # search_fields = [
    #     "company_name", 
    #     "created_at",
    # ]
    # readonly_fields = ["created_by"]
    # fieldsets = (
    #     (
    #         _("Company Information"),
    #         {
    #             "fields": (
    #                 "company_name",
    #                 "photo",
    #                 "company_description",
    #                 "created_by",
    #             )
    #         },
    #     ),
       
        
    # )