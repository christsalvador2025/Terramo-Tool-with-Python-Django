# models.py
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django_countries.fields import CountryField
import uuid
from core_apps.common.permissions import IsSuperAdmin, IsCompanyAdmin, IsSameCompany
from core_apps.common.models import TimeStampedModel


# class UserTerramo(AbstractUser):
#     """Extended User model with role-based access"""
    
#     class UserRole(models.TextChoices):
#         SUPER_ADMIN = 'super_admin', 'Super Admin'
#         COMPANY_ADMIN = 'company_admin', 'Company Admin'
#         COMPANY_USER = 'company_user', 'Company User'
#         STAKEHOLDER = 'stakeholder', 'Stakeholder'
    
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     role = models.CharField(max_length=20, choices=UserRole.choices, default=UserRole.COMPANY_USER)
#     company = models.ForeignKey('CompanyTerramo', on_delete=models.CASCADE, null=True, blank=True, related_name='users')
#     is_active = models.BooleanField(default=True)
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)
    
#     class Meta:
#         db_table = 'users'
#         indexes = [
#             models.Index(fields=['role', 'company']),
#             models.Index(fields=['email']),
#         ]

DEFAULT_STAKEHOLDER_GROUP_NAMES = [
    "Customers",
    "Employees",
    "Society",
    "Industry Representatives",
    "Owners",
]

class Product(TimeStampedModel):
    """Products that can be purchased by companies"""
    
    class ProductType(models.TextChoices):
        ESG_CHECK = 'esg_check', 'ESG Check'
        STAKEHOLDER_ANALYSIS = 'stakeholder_analysis', 'Stakeholder Analysis'
        DOUBLE_MATERIALITY = 'double_materiality', 'Double Materiality'
    
    
    name = models.CharField(max_length=100)
    type = models.CharField(max_length=30, choices=ProductType.choices)
    description = models.TextField(blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    is_active = models.BooleanField(default=True)
     
    class Meta:
        db_table = 'products'
        indexes = [
            models.Index(fields=['type', 'is_active']),
        ]
    
    def __str__(self):
        return self.name

class Company(TimeStampedModel):
    """Company/Customer entity"""
    
   
    name = models.CharField(max_length=200)
    email = models.EmailField()
    phone = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    contact_person_name = models.CharField(max_length=100)
    contact_person_email = models.EmailField()
    contact_person_phone = models.CharField(max_length=20, blank=True)
    
    country = CountryField(
        _("Country"), default=settings.DEFAULT_COUNTRY
    )
    # Product subscriptions
    products = models.ManyToManyField(Product, through='CompanyProduct', related_name='companies')
    
    is_active = models.BooleanField(default=True)
     
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_companies')
    
    class Meta:
        db_table = 'companies'
        verbose_name_plural = 'Companies'
        ordering = ['name', 'email']
        unique_together = ["name", "country"]
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['email']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return self.name

class CompanyProduct(TimeStampedModel):
    """Through model for Company-Product relationship"""
    
    
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    purchased_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'company_products'
        unique_together = ['company', 'product']
        indexes = [
            models.Index(fields=['company', 'is_active']),
        ]

class ESGCategory(models.Model):
    """ESG Categories: Environmental, Social, Corporate Governance"""
    
    class CategoryType(models.TextChoices):
        ENVIRONMENTAL = 'environmental', 'Environmental'
        SOCIAL = 'social', 'Social'
        CORPORATE_GOVERNANCE = 'corporate_governance', 'Corporate Governance'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    type = models.CharField(max_length=30, choices=CategoryType.choices)
    description = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'esg_categories'
        verbose_name_plural = 'ESG Categories'
        ordering = ['order', 'name']
        indexes = [
            models.Index(fields=['type', 'is_active']),
        ]
    
    def __str__(self):
        return self.name

class ESGQuestion(TimeStampedModel):
    """ESG Survey Questions"""
    
    class QuestionType(models.TextChoices):
        MULTIPLE_CHOICE = 'multiple_choice', 'Multiple Choice'
        SINGLE_CHOICE = 'single_choice', 'Single Choice'
        TEXT = 'text', 'Text'
        RATING = 'rating', 'Rating'
        BOOLEAN = 'boolean', 'Yes/No'
    
     
    category = models.ForeignKey(ESGCategory, on_delete=models.CASCADE, related_name='questions')
    measure_key = models.CharField(max_length=100,null=True,blank=True,default=None)
    question_text = models.TextField(null=True,blank=True,default=None)
    question_description = models.TextField(null=True,blank=True,default=None, help_text="This description is also visible in the frontend through the question mark icon beside each question when hovered." )
    question_type = models.CharField(max_length=20, choices=QuestionType.choices, default=QuestionType.MULTIPLE_CHOICE)
    options = models.JSONField(default=list, blank=True)  # For multiple choice questions
    is_required = models.BooleanField(default=False)
    # order = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
     
    
    class Meta:
        db_table = 'esg_questions'
        ordering = ['category', 'measure_key']
        unique_together = ['measure_key', 'question_text']
        indexes = [
            models.Index(fields=['category', 'is_active']),
        ]
        
    def __str__(self):
        return self.question_text
    
class StakeholderGroup(TimeStampedModel):
    # These are groups of stakeholders for a specific company (e.g., "Company A's Employees").
    # This is where the 'default groups' will be created for each company.

    
    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE, # If the company is deleted, delete its stakeholder groups
        related_name='stakeholder_groups'
    )
    name = models.CharField(max_length=100) # e.g., "Management", "Employees", "Customers"
    description = models.TextField(blank=True)
    invite_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False) # UNIQUE TOKEN FOR THIS GROUP. This is what's copied from the admin UI.
    is_active = models.BooleanField(default=True)
    
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)

    class Meta:
        db_table = 'stakeholder_groups'
        unique_together = ['company', 'name'] # A company cannot have two groups with the same name
        ordering = ["company"]
        indexes = [
            models.Index(fields=['company', 'is_active']),
            models.Index(fields=['invite_token']), # Helps find group by invite token
        ]

    def __str__(self):
        return f"{self.company.name} - {self.name}" # e.g., "Acme Corp - Employees"

class StakeholderUser(models.Model):
    # This model connects a User (who has the 'stakeholder' role) to one or more StakeholderGroups.
    # A single User might participate in multiple groups for a company (e.g., "Employee" and "Shareholder").

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    stakeholder_group = models.ForeignKey(
        StakeholderGroup,
        on_delete=models.CASCADE, # If group deleted, remove this link
        related_name='stakeholder_users' # Lets you get all users in a group
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE, # If user deleted, remove this link
        related_name='stakeholder_memberships' # Lets you get all groups a user belongs to
    )
    joined_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        # db_table = 'stakeholder_users'
        unique_together = ['stakeholder_group', 'user'] # A user can join a specific group only once
        indexes = [
            models.Index(fields=['stakeholder_group', 'is_active']),
        ]

    def __str__(self):
        return f"{self.user.email} in {self.stakeholder_group.name}"
# class StakeholderGroup(models.Model):
#     """Stakeholder Groups for each company"""
    
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     company = models.ForeignKey(CompanyTerramo, on_delete=models.CASCADE, related_name='stakeholder_groups')
#     name = models.CharField(max_length=100)  # e.g., "Management", "Employees", "Customers"
#     description = models.TextField(blank=True)
#     invite_token = models.UUIDField(default=uuid.uuid4, unique=True)
#     is_active = models.BooleanField(default=True)
#     created_at = models.DateTimeField(auto_now_add=True)
#     created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    
#     class Meta:
#         db_table = 'stakeholder_groups'
#         unique_together = ['company', 'name']
#         indexes = [
#             models.Index(fields=['company', 'is_active']),
#             models.Index(fields=['invite_token']),
#         ]
#         ordering = ['company']
    
#     def __str__(self):
#         return f"{self.name}"




# class StakeholderUser(models.Model):
#     """Users within stakeholder groups"""
    
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     stakeholder_group = models.ForeignKey(StakeholderGroup, on_delete=models.CASCADE, related_name='stakeholder_users')
#     user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='stakeholder_memberships')
#     joined_at = models.DateTimeField(auto_now_add=True)
#     is_active = models.BooleanField(default=True)
    
#     class Meta:
#         db_table = 'stakeholder_users'
#         unique_together = ['stakeholder_group', 'user']
#         indexes = [
#             models.Index(fields=['stakeholder_group', 'is_active']),
#         ]

class ESGResponse(TimeStampedModel):
    """ESG Survey Responses"""
    
    class Priority(models.TextChoices):
        LOW = 'low', 'Low'
        MEDIUM = 'medium', 'Medium'
        HIGH = 'high', 'High'
        CRITICAL = 'critical', 'Critical'
    
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        IN_PROGRESS = 'in_progress', 'In Progress'
        COMPLETED = 'completed', 'Completed'
        REVIEWED = 'reviewed', 'Reviewed'
    
    
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='esg_responses')
    question = models.ForeignKey(ESGQuestion, on_delete=models.CASCADE, related_name='responses')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='esg_responses')
    
    # Response data
    answer = models.JSONField(null=True,blank=True)  
    priority = models.CharField(max_length=10, choices=Priority.choices, null=True, blank=True, default=Priority.LOW)
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.PENDING)
    comment = models.TextField(blank=True)
    
    # Metadata
     
     
    
    class Meta:
        db_table = 'esg_responses'
        unique_together = ['company', 'question', 'user']
        indexes = [
            models.Index(fields=['company', 'question']),
            models.Index(fields=['user', 'status']),
            models.Index(fields=['priority']),
        ]
    def __str__(self):
        return f"{self.company} - {self.user}"
class ESGResponseComment(TimeStampedModel):
    """Comments on ESG Responses"""
    
    
    response = models.ForeignKey(ESGResponse, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='esg_comments')
    comment = models.TextField()
    is_internal = models.BooleanField(default=False)  # Internal comments for admins only
    
    
    class Meta:
        db_table = 'esg_response_comments'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['response', 'created_at']),
        ]
    def __str__(self):
        return f"{self.user}"
    
class StakeholderInvitation(models.Model):
    """Track stakeholder invitations"""
    
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        ACCEPTED = 'accepted', 'Accepted'
        EXPIRED = 'expired', 'Expired'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    stakeholder_group = models.ForeignKey(StakeholderGroup, on_delete=models.CASCADE, related_name='invitations')
    email = models.EmailField()
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    sent_at = models.DateTimeField(auto_now_add=True)
    accepted_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    sent_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    
    class Meta:
        db_table = 'stakeholder_invitations'
        unique_together = ['stakeholder_group', 'email']
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['status', 'expires_at']),
        ]

class AuditLog(models.Model):
    """Audit trail for important actions"""
    
    class Action(models.TextChoices):
        CREATE = 'create', 'Create'
        UPDATE = 'update', 'Update'
        DELETE = 'delete', 'Delete'
        LOGIN = 'login', 'Login'
        LOGOUT = 'logout', 'Logout'
        INVITE_SENT = 'invite_sent', 'Invite Sent'
        RESPONSE_SUBMITTED = 'response_submitted', 'Response Submitted'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='audit_logs')
    action = models.CharField(max_length=20, choices=Action.choices)
    model_name = models.CharField(max_length=50)
    object_id = models.UUIDField(null=True, blank=True)
    changes = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'audit_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['model_name', 'object_id']),
        ]

# Signal handlers for audit logging
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

@receiver(post_save, sender=ESGResponse)
def log_esg_response_changes(sender, instance, created, **kwargs):
    """Log ESG response changes"""
    if created:
        AuditLog.objects.create(
            user=instance.user,
            action=AuditLog.Action.CREATE,
            model_name='ESGResponse',
            object_id=instance.id,
            changes={'question_id': str(instance.question.id), 'answer': instance.answer}
        )

@receiver(post_save, sender=Company)
def log_company_changes(sender, instance, created, **kwargs):
    """Log company changes"""
    if created:
        AuditLog.objects.create(
            user=instance.created_by,
            action=AuditLog.Action.CREATE,
            model_name='Company',
            object_id=instance.id,
            changes={'name': instance.name, 'email': instance.email}
        )