import uuid
from django.db import models
from django.conf import settings  
from core_apps.common.permissions import IsTerramoAdmin, IsCompanyAdmin, IsSameCompany
from core_apps.common.models import TimeStampedModel
from core_apps.products.models import Product
from core_apps.clients.models import Client
from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth import login, authenticate, get_user_model

# User = get_user_model()
User = get_user_model()


# class ESGCategory(TimeStampedModel):
#     """ESG Categories: Environmental, Social, Corporate Governance"""

#     class CategoryType(models.TextChoices):
#         ENVIRONMENTAL = 'environmental', 'Environmental'
#         SOCIAL = 'social', 'Social'
#         CORPORATE_GOVERNANCE = 'corporate_governance', 'Corporate Governance'

    
#     name = models.CharField(max_length=100, unique=True, help_text="Unique name for the ESG category (e.g., 'Climate Change')")
#     type = models.CharField(max_length=30, choices=CategoryType.choices, help_text="The broad ESG type this category belongs to.")
#     description = models.TextField(blank=True, help_text="Detailed description of the ESG category.")
#     order = models.PositiveIntegerField(default=0, help_text="Display order of the category.")
#     is_active = models.BooleanField(default=True, help_text="Whether this category is currently active and visible.")

#     class Meta:
#         db_table = 'esg_categories'
#         verbose_name_plural = 'ESG Categories'
#         ordering = ['order', 'name'] # Order categories by their 'order' field, then by name.
#         indexes = [
#             models.Index(fields=['type', 'is_active']), # Efficient lookup by type and active status.
#         ]

#     def __str__(self):
#         return self.name

# class ESGQuestion(TimeStampedModel):
#     """ESG Survey Questions"""

#     class QuestionType(models.TextChoices):
#         MULTIPLE_CHOICE = 'multiple_choice', 'Multiple Choice'
#         SINGLE_CHOICE = 'single_choice', 'Single Choice'
#         TEXT = 'text', 'Text'
#         RATING = 'rating', 'Rating'
#         BOOLEAN = 'boolean', 'Yes/No'

#     category = models.ForeignKey(ESGCategory, on_delete=models.CASCADE, related_name='questions', help_text="The ESG category this question belongs to.")
#     measure_key = models.CharField(
#         max_length=100,
#         help_text="An unique identifier for the specific metric/measure (e.g., 'GHG_Scope1'). Useful for reporting."
#     )
#     question_text = models.TextField(
#         help_text="The main text of the survey question."
#     ) # Made required
#     question_description = models.TextField(
#         blank=True,
#         help_text="This description is also visible in the frontend through the question mark icon beside each question when hovered."
#     )
#     question_type = models.CharField(max_length=20, choices=QuestionType.choices, default=QuestionType.MULTIPLE_CHOICE, help_text="The type of answer expected for this question.")
#     options = models.JSONField(default=list, blank=True, help_text="JSON data for question options (e.g., choices for multiple choice, min/max for rating).")
#     is_required = models.BooleanField(default=False, help_text="If true, this question must be answered in a submission.")
#     order = models.PositiveIntegerField(default=0, help_text="Display order of the question within its category.")
#     is_active = models.BooleanField(default=True, help_text="Whether this question is currently active and visible.")

#     # Added for the 'Show in Chart' toggle on the Stakeholder Analysis table
#     # This presumes a question can be flagged for display in the materiality matrix.
#     show_in_chart = models.BooleanField(default=False, help_text="If true, this question's data can be displayed in the materiality chart.")


#     class Meta:
#         db_table = 'esg_questions'
#         # Order by category order, then category name, then question order, then measure key.
#         ordering = ['category__order', 'category__name', 'order', 'measure_key']
#         # Ensures that a measure_key is unique within a specific category.
#         # If measure_key is globally unique, use `unique=True` on measure_key instead and remove this unique_together.
#         unique_together = ['category', 'measure_key']
#         indexes = [
#             models.Index(fields=['category', 'is_active']), # Efficient lookup for active questions in a category.
#             models.Index(fields=['measure_key']), # Useful if you often search questions by their measure_key.
#             models.Index(fields=['show_in_chart']), # For quick filtering of chartable questions.
#         ]
#         verbose_name_plural = 'ESG Questions'

#     def __str__(self):
#         # Provides a clear identification for the question, including its category.
#         return f"[{self.category.name}] {self.question_text[:70]}{'...' if len(self.question_text) > 70 else ''}"

# # --- Survey Submission & Response Models ---

# class SurveySubmission(TimeStampedModel):
#     """Represents a single completed or in-progress survey submission by a company/user."""

#     # Re-using Status choices from ESGResponse below for consistency in overall submission status.
#     # Defining it here for direct use within this model.
#     class Status(models.TextChoices):
#         PENDING = 'pending', 'Pending'
#         IN_PROGRESS = 'in_progress', 'In Progress'
#         COMPLETED = 'completed', 'Completed'
#         REVIEWED = 'reviewed', 'Reviewed'
#         NEEDS_REVISION = 'needs_revision', 'Needs Revision' # Added for workflow if a submission needs re-work

#     company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='survey_submissions', help_text="The company this survey submission belongs to.")
#     submitted_by = models.ForeignKey(
#         settings.AUTH_USER_MODEL,
#         on_delete=models.SET_NULL, # If user is deleted, submission remains but link is null
#         null=True, blank=True,
#         related_name='my_submissions',
#         help_text="The user who initiated or is primarily responsible for this submission."
#     )
#     status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING, help_text="Overall status of this survey submission.")

#     # Example for periodic surveys (e.g., annual submissions):
#     # submission_year = models.PositiveSmallIntegerField(null=True, blank=True, help_text="The year of the survey submission.")
#     # You might add a unique_together = ['company', 'submission_year'] if only one submission per company per year.

#     class Meta:
#         db_table = 'esg_survey_submissions'
#         verbose_name_plural = 'Survey Submissions'
#         # No `unique_together` by default, allowing multiple submissions per company/user,
#         # distinguished by `created_at` or a potential `submission_year`.
#         indexes = [
#             models.Index(fields=['company', 'status']), # Efficiently find submissions for a company by status.
#             models.Index(fields=['submitted_by']), # Find all submissions by a specific user.
#         ]
#         ordering = ['-created_at'] # Newest submissions first

#     def __str__(self):
#         # A more descriptive string representation including company and user.
#         user_info = self.submitted_by.get_full_name() or self.submitted_by.username or self.submitted_by.email if self.submitted_by else "N/A User"
#         return f"Submission for {self.company.name} by {user_info} (Status: {self.get_status_display()})"


# class ESGResponse(TimeStampedModel):
#     """Individual answers to ESG Survey Questions within a specific Survey Submission."""

#     # Define specific status and priority for individual answers if different from submission level.
#     # Otherwise, you could potentially remove these or inherit/derive them.
#     class Priority(models.TextChoices):
#         LOW = 'low', 'Low'
#         MEDIUM = 'medium', 'Medium'
#         HIGH = 'high', 'High'
#         CRITICAL = 'critical', 'Critical'

#     class Status(models.TextChoices):
#         NOT_APPLICABLE = 'not_applicable', 'Not Applicable'
#         ANSWERED = 'answered', 'Answered'
#         PENDING = 'pending', 'Pending' # Question is part of submission but not yet answered
#         NEEDS_REVIEW = 'needs_review', 'Needs Review' # Specific answer needs human review

#     submission = models.ForeignKey(SurveySubmission, on_delete=models.CASCADE, related_name='responses', help_text="The overall survey submission this answer belongs to.")
#     question = models.ForeignKey(ESGQuestion, on_delete=models.CASCADE, related_name='responses', help_text="The specific question being answered.")

#     # Response data
#     answer = models.JSONField(
#         null=True, blank=True, # Allows for answers to be optional or pending
#         help_text="JSON representation of the answer (e.g., string, list of strings, number, boolean)."
#     )
#     priority = models.CharField(max_length=10, choices=Priority.choices, null=True, blank=True, default=Priority.LOW,
#                                 help_text="Priority assigned to this specific question's response (e.g., for follow-up).")
#     status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING,
#                               help_text="Status of this individual question's response within the submission (e.g., 'Answered', 'Needs Review').")
#     comment = models.TextField(blank=True, help_text="Internal notes or explanations for this specific answer.")

#     class Meta:
#         db_table = 'esg_responses'
#         verbose_name_plural = 'ESG Responses'
#         # Ensures that a question can only be answered once within a specific submission.
#         unique_together = ['submission', 'question']
#         indexes = [
#             models.Index(fields=['submission', 'status']), # Find all answers for a submission by their individual status.
#             models.Index(fields=['question', 'status']), # Find all answers for a specific question by their status.
#             models.Index(fields=['priority']), # For quick filtering by priority across all responses.
#         ]
#         # Ordering for retrieving answers within a submission in a logical sequence.
#         ordering = ['submission', 'question__category__order', 'question__order']

#     def __str__(self):
#         # A more detailed string for individual responses.
#         sub_info = f"Sub ID: {self.submission.id}" # Or self.submission.company.name for more context
#         return f"{sub_info} - Q: {self.question.question_text[:50]}{'...' if len(self.question.question_text) > 50 else ''}"


# class ESGResponseComment(TimeStampedModel):
#     """Comments related to specific ESG Responses."""

#     response = models.ForeignKey(ESGResponse, on_delete=models.CASCADE, related_name='comments', help_text="The ESG response this comment is attached to.")
#     user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='esg_comments', help_text="The user who created this comment.")
#     comment = models.TextField(help_text="The actual text of the comment.")
#     is_internal = models.BooleanField(default=False, help_text="If true, this comment is for internal staff/admins only.")

#     class Meta:
#         db_table = 'esg_response_comments'
#         verbose_name_plural = 'ESG Response Comments'
#         # Ordering comments from oldest to newest for a natural thread display.
#         ordering = ['created_at']
#         indexes = [
#             models.Index(fields=['response', 'created_at']), # Efficiently fetch comments for a specific response.
#             models.Index(fields=['user', 'is_internal']), # Useful for auditing comments by user or internal status.
#         ]

#     def __str__(self):
#         # Provides context for the comment including who made it and on which response.
#         user_info = self.user.get_full_name() or self.user.username or self.user.email
#         return f"Comment by {user_info} on Response ID {self.response.id}"


"""
--------------------------------------------------------------------------------
"""



# class ESGCategory(TimeStampedModel):
#     """ESG Categories: Environmental, Social, Corporate Governance"""
    
#     name = models.CharField(max_length=100)
#     description = models.TextField(blank=True)
#     order = models.PositiveIntegerField(default=0)
#     is_active = models.BooleanField(default=True)
    
#     class Meta:
#         db_table = 'esg_categories'
#         verbose_name_plural = 'ESG Categories'
#         ordering = ['order', 'name']
#         indexes = [
#             models.Index(fields=['type', 'is_active']),
#         ]
    
#     def __str__(self):
#         return self.name

# class ESGQuestion(TimeStampedModel):
#     """ESG Survey Questions"""
    
#     class QuestionType(models.TextChoices):
#         MULTIPLE_CHOICE = 'multiple_choice', 'Multiple Choice'
#         SINGLE_CHOICE = 'single_choice', 'Single Choice'
#         TEXT = 'text', 'Text'
#         RATING = 'rating', 'Rating'
#         BOOLEAN = 'boolean', 'Yes/No'
    
     
#     category = models.ForeignKey(ESGCategory, on_delete=models.CASCADE, related_name='questions')
#     measure_key = models.CharField(max_length=100,null=True,blank=True,default=None)
#     question_text = models.TextField(null=True,blank=True,default=None)
#     question_description = models.TextField(null=True,blank=True,default=None, help_text="This description is also visible in the frontend through the question mark icon beside each question when hovered." )
#     question_type = models.CharField(max_length=20, choices=QuestionType.choices, default=QuestionType.MULTIPLE_CHOICE)
#     options = models.JSONField(default=list, blank=True)  
#     is_required = models.BooleanField(default=False)
#     order = models.PositiveIntegerField(default=0)
#     is_active = models.BooleanField(default=True)
     
    
#     class Meta:
#         db_table = 'esg_questions'
#         ordering = ['category', 'measure_key']
#         # unique_together = ['measure_key', 'question_text']
#         unique_together = ['category', 'measure_key', 'order']
#         indexes = [
#             models.Index(fields=['category', 'is_active']),
#         ]
        
    
#     def __str__(self):
#         return self.question_text
    

# Priorität: Priority

# 0... nicht relevant: 0... not relevant

# 1... wenig Priorität: 1... low priority

# 2... wichtig: 2... important

# 3... sehr wichtig: 3... very important

# Status Quo: Status Quo

# 0... nicht gestartet: 0... not started

# 1... gestartet: 1... started

# 2... fortgeschritten: 2... advanced / in progress

# 3... abgeschlossen: 3... completed



# class ESGResponse(TimeStampedModel):
#     """ESG Survey Responses"""
#     class PRIORITY(models.TextChoices):
#         NOT_RELEVANT = (
#             "0 - nicht relevant",
#             _("0 - not relevant"),
#         )
#         LOW_PRIORITY = (
#             "1 - wenig Priorität",
#             _("Female"),
#         )
    
#     class Priority(models.TextChoices):
#         LOW = 'low', 'Low'
#         MEDIUM = 'medium', 'Medium'
#         HIGH = 'high', 'High'
#         CRITICAL = 'critical', 'Critical'
    
#     class Status(models.TextChoices):
#         PENDING = 'pending', 'Pending'
#         IN_PROGRESS = 'in_progress', 'In Progress'
#         COMPLETED = 'completed', 'Completed'
#         REVIEWED = 'reviewed', 'Reviewed'
    
#     class STATUS(models.TextChoices):
#         PENDING = (
#             "pending",
#             _("Pending"),
#         )
#         DRAFT = (
#             "1 - wenig Priorität",
#             _("Female"),
#         )
    
#     company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='esg_responses')
#     question = models.ForeignKey(ESGQuestion, on_delete=models.CASCADE, related_name='responses')
#     user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='esg_responses')
    
#     # Response data
#     answer = models.JSONField(null=True,blank=True)  
#     priority = models.CharField(max_length=10, choices=Priority.choices, null=True, blank=True, default=Priority.LOW)
#     status = models.CharField(max_length=15, choices=Status.choices, default=Status.PENDING)
#     comment = models.TextField(blank=True)
    
#     # Metadata
     
     
    
#     class Meta:
#         db_table = 'esg_responses'
#         unique_together = ['company', 'question', 'user']
#         indexes = [
#             models.Index(fields=['company', 'question']),
#             models.Index(fields=['user', 'status']),
#             models.Index(fields=['priority']),
#         ]
#     def __str__(self):
#         return f"{self.company} - {self.user}"
# class ESGResponseComment(TimeStampedModel):
#     """Comments on ESG Responses"""
    
    
#     response = models.ForeignKey(ESGResponse, on_delete=models.CASCADE, related_name='comments')
#     user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='esg_comments')
#     comment = models.TextField()
#     is_internal = models.BooleanField(default=False)  # Internal comments for admins only
    
    
#     class Meta:
#         db_table = 'esg_response_comments'
#         ordering = ['-created_at']
#         indexes = [
#             models.Index(fields=['response', 'created_at']),
#         ]
#     def __str__(self):
#         return f"{self.user}"
    

"""
-------------------------------------------------------------------------------------------
"""








from django.db import models, transaction
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator
from django.utils import timezone
from django.db.models import Max, F
import uuid


class BaseModel(models.Model):
    """Abstract base model with common fields"""
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='%(class)s_created'
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='%(class)s_updated'
    )
    
    class Meta:
        abstract = True


class ESGCategory(BaseModel):
    """ESG Categories: Environment, Social, Corporate Governance"""
    
    ENVIRONMENT = 'E'
    SOCIAL = 'S'
    GOVERNANCE = 'G'
    
    CATEGORY_CHOICES = [
        (ENVIRONMENT, 'Environment'),
        (SOCIAL, 'Social'),
        (GOVERNANCE, 'Corporate Governance'),
    ]
    
    code = models.CharField(
        max_length=1, 
        choices=CATEGORY_CHOICES, 
        unique=True,
        primary_key=True
    )
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'esg_categories'
        verbose_name = 'ESG Category'
        verbose_name_plural = 'ESG Categories'
        ordering = ['code']
    
    def __str__(self):
        return f"{self.code} - {self.name}"


class ESGYear(models.Model):
    """Years for ESG questionnaires"""
    year = models.PositiveIntegerField(
        unique=True,
        validators=[MinValueValidator(2020)]
    )
    is_active = models.BooleanField(default=True)
    is_current = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'esg_years'
        ordering = ['-year']
    
    def __str__(self):
        return str(self.year)
    
    def save(self, *args, **kwargs):
        if self.is_current:
            # Ensure only one year can be current
            ESGYear.objects.filter(is_current=True).update(is_current=False)
        super().save(*args, **kwargs)


class ESGQuestionManager(models.Manager):
    """Custom manager for ESG Questions"""
    
    def get_next_order(self, category, year):
        """Get the next order number for a category and year"""
        last_order = self.filter(
            category=category, 
            year=year
        ).aggregate(Max('order'))['order__max']
        return (last_order or 0) + 1
    
    def reorder_questions(self, category, year, question_id, new_order):
        """Reorder questions when order is updated"""
        with transaction.atomic():
            # Get the question being moved
            question = self.get(id=question_id, category=category, year=year)
            old_order = question.order
            
            if old_order == new_order:
                return question
            
            # Get all questions in the same category and year
            questions = self.filter(
                category=category, 
                year=year
            ).exclude(id=question_id).order_by('order')
            
            # Update orders
            if old_order < new_order:
                # Moving down: shift up questions between old and new position
                questions.filter(
                    order__gt=old_order,
                    order__lte=new_order
                ).update(order=F('order') - 1)
            else:
                # Moving up: shift down questions between new and old position
                questions.filter(
                    order__gte=new_order,
                    order__lt=old_order
                ).update(order=F('order') + 1)
            
            # Update the question's order
            question.order = new_order
            question.save()
            
            # Regenerate measure IDs for all questions in this category/year
            self._regenerate_measure_ids(category, year)
            
            return question
    
    def _regenerate_measure_ids(self, category, year):
        """Regenerate measure IDs based on current order"""
        questions = self.filter(
            category=category, 
            year=year
        ).order_by('order')
        
        for index, question in enumerate(questions, 1):
            new_measure_id = f"{category.code}-{index}"
            if question.measure_id != new_measure_id:
                question.measure_id = new_measure_id
                question.save(update_fields=['measure_id'])


class ESGQuestion(BaseModel):
    """ESG Questions/Measures"""
    
    PRIORITY_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    STATUS_CHOICES = [
        ('not_started', 'Not Started'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('on_hold', 'On Hold'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    measure_id = models.CharField(max_length=20, unique=True, editable=False)
    category = models.ForeignKey(
        ESGCategory, 
        on_delete=models.CASCADE,
        related_name='questions'
    )
    year = models.ForeignKey(
        ESGYear, 
        on_delete=models.CASCADE,
        related_name='questions'
    )
    measure = models.TextField()  # The actual question text
    order = models.PositiveIntegerField()
    priority = models.CharField(
        max_length=10, 
        choices=PRIORITY_CHOICES,
        default='medium'
    )
    status_quo = models.CharField(
        max_length=20, 
        choices=STATUS_CHOICES,
        default='not_started'
    )
    is_active = models.BooleanField(default=True)
    
    objects = ESGQuestionManager()
    
    class Meta:
        db_table = 'esg_questions'
        unique_together = [['category', 'year', 'order']]
        ordering = ['category', 'year', 'order']
        indexes = [
            models.Index(fields=['category', 'year']),
            models.Index(fields=['measure_id']),
            models.Index(fields=['year', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.measure_id} - {self.measure[:50]}..."
    
    def save(self, *args, **kwargs):
        if not self.order:
            self.order = ESGQuestion.objects.get_next_order(
                self.category, 
                self.year
            )
        
        if not self.measure_id:
            self.measure_id = f"{self.category.code}-{self.order}"
        
        super().save(*args, **kwargs)


class ESGResponse(BaseModel):
    """User responses to ESG questions"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    question = models.ForeignKey(
        ESGQuestion, 
        on_delete=models.CASCADE,
        related_name='responses'
    )
    # client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='client_esg_responses')
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE,
        related_name='user_esg_responses'
    )
    comment = models.TextField(blank=True)
    priority = models.CharField(
        max_length=10, 
        choices=ESGQuestion.PRIORITY_CHOICES,
        blank=True
    )
    status_quo = models.CharField(
        max_length=20, 
        choices=ESGQuestion.STATUS_CHOICES,
        blank=True
    )
    is_draft = models.BooleanField(default=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'esg_responses'
        unique_together = [['question', 'user']]
        indexes = [
            models.Index(fields=['user', 'question']),
            models.Index(fields=['question', 'is_draft']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.question.measure_id}"
    
    def submit(self):
        """Submit the response"""
        if self.is_draft:
            self.is_draft = False
            self.submitted_at = timezone.now()
            self.save()


class ESGSummary(BaseModel):
    """Summary of ESG responses by category and year"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE,
        related_name='esg_summaries'
    )
    year = models.ForeignKey(
        ESGYear, 
        on_delete=models.CASCADE,
        related_name='summaries'
    )
    category = models.ForeignKey(
        ESGCategory, 
        on_delete=models.CASCADE,
        related_name='summaries'
    )
    
    # Summary statistics
    total_questions = models.PositiveIntegerField(default=0)
    completed_questions = models.PositiveIntegerField(default=0)
    in_progress_questions = models.PositiveIntegerField(default=0)
    not_started_questions = models.PositiveIntegerField(default=0)
    
    # Priority breakdown
    high_priority_count = models.PositiveIntegerField(default=0)
    medium_priority_count = models.PositiveIntegerField(default=0)
    low_priority_count = models.PositiveIntegerField(default=0)
    
    completion_percentage = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=0.00
    )
    
    last_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'esg_summaries'
        unique_together = [['user', 'year', 'category']]
        indexes = [
            models.Index(fields=['user', 'year']),
            models.Index(fields=['year', 'category']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.year.year} - {self.category.name}"
    
    def calculate_summary(self):
        """Calculate and update summary statistics"""
        responses = ESGResponse.objects.filter(
            user=self.user,
            question__year=self.year,
            question__category=self.category
        )
        
        questions = ESGQuestion.objects.filter(
            year=self.year,
            category=self.category,
            is_active=True
        )
        
        self.total_questions = questions.count()
        
        # Count by status
        status_counts = responses.values('status_quo').count()
        self.completed_questions = status_counts.get('completed', 0)
        self.in_progress_questions = status_counts.get('in_progress', 0)
        self.not_started_questions = self.total_questions - responses.count()
        
        # Count by priority
        priority_counts = responses.values('priority').count()
        self.high_priority_count = priority_counts.get('high', 0)
        self.medium_priority_count = priority_counts.get('medium', 0)
        self.low_priority_count = priority_counts.get('low', 0)
        
        # Calculate completion percentage
        if self.total_questions > 0:
            self.completion_percentage = (
                self.completed_questions / self.total_questions
            ) * 100
        else:
            self.completion_percentage = 0
        
        self.save()


class ESGAuditLog(models.Model):
    """Audit log for tracking changes to ESG questions and responses"""
    
    ACTION_CHOICES = [
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('reorder', 'Reorder'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='esg_audit_logs'
    )
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    model_name = models.CharField(max_length=50)
    object_id = models.CharField(max_length=100)
    changes = models.JSONField(default=dict)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        db_table = 'esg_audit_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['model_name', 'object_id']),
            models.Index(fields=['user', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.user} - {self.action} - {self.model_name} - {self.timestamp}"