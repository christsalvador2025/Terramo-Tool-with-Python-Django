from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
import uuid
from core_apps.authentication.models import Stakeholder
from core_apps.clients.models import Client
User = settings.AUTH_USER_MODEL
from core_apps.common.models import TimeStampedModel


class ESGYearManager(models.Manager):
    def get_current(self):
        """Get the current active year"""
        try:
            return self.get(is_current=True)
        except self.model.DoesNotExist:
            return self.filter(is_active=True).first()
        
    def get_available_years(self):
        """Get all available years for dropdowns"""
        return self.filter(is_active=True).values_list('year', flat=True).order_by('-year')
        
class ESGYear(TimeStampedModel):
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
    objects = ESGYearManager()
    
    @classmethod
    def get_current_year(cls):
        """Get current ESG year"""
        try:
            return cls.objects.get(is_current=True)
        except cls.DoesNotExist:
            return cls.objects.filter(is_active=True).first()
    
    @classmethod
    def get_available_years_list(cls):
        """Get list of available years as tuples for choices"""
        return [(year, str(year)) for year in cls.objects.get_available_years()]
    
class ESGCategory(TimeStampedModel):
    """ ESG Category """
    name = models.CharField(max_length=50,unique=True)
    display_name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    
    
    class Meta:
        db_table = 'esg_categories'
        verbose_name_plural = 'ESG Categories'
        ordering = ['name']
    
    def __str__(self):
        return self.display_name


class ESGQuestion(TimeStampedModel):
    """ESG Questions/Measures for each category"""
    
    category = models.ForeignKey(ESGCategory, on_delete=models.CASCADE, related_name='questions')
    measure = models.TextField()    
    index_code = models.CharField(max_length=10)  # E-1, S-1, G-1, etc.
    desription = models.TextField(null=True, blank=True) 
    order = models.PositiveIntegerField(default=0)  
 
    is_active = models.BooleanField(default=True)
    year = models.ForeignKey(ESGYear, on_delete=models.CASCADE, related_name='year_questions')
   
    
    class Meta:
        db_table = 'esg_questions'
        verbose_name_plural = 'ESG Questions'
        ordering = ['category', 'order', 'index_code']
        unique_together = ['category', 'index_code']
    
    def __str__(self):
        return f"{self.index_code}: {self.measure[:50]}..."

    def get_user_response(self, user):
        """Get the response for this question by a specific user"""
        try:
            return self.responses.get(user=user)
        except ESGQuestionResponse.DoesNotExist:
            return None
    
    def get_client_responses(self, client):
        """Get all responses for this question from a specific client"""
        return self.responses.filter(user__client=client)
    
class ESGQuestionResponse(TimeStampedModel):
    """Question responses to ESG survey"""
    PRIORITY_CHOICES = [
        (0, 'Not Started'),
        (1, 'Low Priority'),
        (2, 'Medium Priority'), 
        (3, 'High Priority'),
        (4, 'Very High Priority'),
    ]
    
    STATUS_QUO_CHOICES = [
        (0, 'Not Started'),
        (1, 'Poor'),
        (2, 'Fair'),
        (3, 'Good'),
        (4, 'Excellent'),
    ]
    
    RESPONSE_STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('submitted', 'Submitted'),
        ('reviewed', 'Reviewed'),
    ]
    QUESTIONNAIRE_TYPES_CHOICES = [
        ('client_admin', 'Client Admin'),
        ('stakeholder', 'Stakeholder'),
    ]
    
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
    questionnaire_type = models.CharField(max_length=20, choices=QUESTIONNAIRE_TYPES_CHOICES, default='stakeholder')
    # Response fields
    priority = models.PositiveIntegerField(
        choices=PRIORITY_CHOICES, 
        default=None,
        blank=True,
        null=True,
        validators=[MinValueValidator(0), MaxValueValidator(4)]
    )
    status_quo = models.PositiveIntegerField(
        choices=STATUS_QUO_CHOICES, 
        default=None,
        blank=True,
        null=True,
        validators=[MinValueValidator(0), MaxValueValidator(4)]
    )
    comment = models.TextField(blank=True, null=True)
    
    # Response metadata
    status = models.CharField(max_length=20, choices=RESPONSE_STATUS_CHOICES, default='draft')
    responded_at = models.DateTimeField(null=True, blank=True)
   
    class Meta:
        db_table = 'esg_question_responses'
        verbose_name_plural = 'ESGQuestion Responses'
        ordering = ['-updated_at']
        unique_together = ['question', 'user', ]
    
    def __str__(self):
        return f"{self.user.email} - {self.question.index_code}"
    
    def save(self, *args, **kwargs):
        # Auto-set responded_at when status changes to submitted
        if self.status == 'submitted' and not self.responded_at:
            self.responded_at = timezone.now()
        super().save(*args, **kwargs)
    
    @property
    def is_answered(self):
        """Check if the question has been meaningfully answered"""
        
        return self.priority is not None or self.status_quo is not None or bool(self.comment)
    
    @property
    def completion_score(self):
        """Calculate completion score (0-1)"""
        score = 0
        if self.status != 'draft':
             

            if self.priority is not None:
                if self.priority > 0:
                    score += 0.4
            if self.status_quo is not None:
                if self.status_quo > 0:
                    score += 0.4
            if self.comment:
                score += 0.2
            return score
        return score

    @property
    def client(self):
        return self.user.client


class ESGSurvey(models.Model):
    """Survey instance for a client"""
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('archived', 'Archived'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='esg_surveys')
    title = models.CharField(max_length=200, default="ESG-Check")
    year = models.PositiveIntegerField(default=timezone.now().year)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    description = models.TextField(blank=True, null=True)
    start_date = models.DateTimeField(null=True, blank=True)
    end_date = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'esg_surveys'
        verbose_name_plural = 'ESG Surveys'
        ordering = ['-year', '-created_at']
        unique_together = ['client', 'year']
    
    def __str__(self):
        return f"{self.client.company_name} - {self.title} {self.year}"


class ESGSurveyQuestion(models.Model):
    """Questions assigned to a specific survey (allows customization per client)"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    survey = models.ForeignKey(ESGSurvey, on_delete=models.CASCADE, related_name='survey_questions')
    question = models.ForeignKey(ESGQuestion, on_delete=models.CASCADE)
    order = models.PositiveIntegerField(default=0)  # Custom ordering per survey
    is_required = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'esg_survey_questions'
        verbose_name_plural = 'ESG Survey Questions'
        ordering = ['survey', 'question__category', 'order']
        unique_together = ['survey', 'question']
    
    def __str__(self):
        return f"{self.survey} - {self.question.index_code}"


class StakeholderResponse(models.Model):
    """Stakeholder responses to ESG survey"""
    PRIORITY_CHOICES = [
        (0, 'Not Started'),
        (1, 'Low Priority'),
        (2, 'Medium Priority'), 
        (3, 'High Priority'),
        (4, 'Very High Priority'),
    ]
    
    STATUS_QUO_CHOICES = [
        (0, 'Not Started'),
        (1, 'Poor'),
        (2, 'Fair'),
        (3, 'Good'),
        (4, 'Excellent'),
    ]
    
    RESPONSE_STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('submitted', 'Submitted'),
        ('reviewed', 'Reviewed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    survey = models.ForeignKey(ESGSurvey, on_delete=models.CASCADE, related_name='responses')
    stakeholder = models.ForeignKey(Stakeholder, on_delete=models.CASCADE, related_name='esg_responses')
    survey_question = models.ForeignKey(ESGSurveyQuestion, on_delete=models.CASCADE)
    
    # Response fields
    priority = models.PositiveIntegerField(
        choices=PRIORITY_CHOICES, 
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(4)]
    )
    status_quo = models.PositiveIntegerField(
        choices=STATUS_QUO_CHOICES, 
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(4)]
    )
    comment = models.TextField(blank=True, null=True)
    
    # Response metadata
    status = models.CharField(max_length=20, choices=RESPONSE_STATUS_CHOICES, default='draft')
    responded_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'stakeholder_responses'
        verbose_name_plural = 'Stakeholder Responses'
        ordering = ['-updated_at']
        unique_together = ['survey', 'stakeholder', 'survey_question']
    
    def __str__(self):
        return f"{self.stakeholder.email} - {self.survey_question.question.index_code}"
    
    def save(self, *args, **kwargs):
        # Auto-set responded_at when status changes to submitted
        if self.status == 'submitted' and not self.responded_at:
            self.responded_at = timezone.now()
        super().save(*args, **kwargs)


class ClientResponse(models.Model):
    """Client admin responses to ESG survey (separate from stakeholders)"""
    PRIORITY_CHOICES = [
        (0, 'Not Started'),
        (1, 'Low Priority'),
        (2, 'Medium Priority'), 
        (3, 'High Priority'),
        (4, 'Very High Priority'),
    ]
    
    STATUS_QUO_CHOICES = [
        (0, 'Not Started'),
        (1, 'Poor'),
        (2, 'Fair'),
        (3, 'Good'),
        (4, 'Excellent'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    survey = models.ForeignKey(ESGSurvey, on_delete=models.CASCADE, related_name='client_responses')
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Client admin user
    survey_question = models.ForeignKey(ESGSurveyQuestion, on_delete=models.CASCADE)
    
    # Response fields
    priority = models.PositiveIntegerField(
        choices=PRIORITY_CHOICES, 
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(4)]
    )
    status_quo = models.PositiveIntegerField(
        choices=STATUS_QUO_CHOICES, 
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(4)]
    )
    comment = models.TextField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'client_responses'
        verbose_name_plural = 'Client Responses'
        ordering = ['-updated_at']
        unique_together = ['survey', 'user', 'survey_question']
    
    def __str__(self):
        return f"{self.user.username} - {self.survey_question.question.index_code}"


class ESGAnalytics(models.Model):
    """Pre-calculated analytics for dashboard performance"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    survey = models.OneToOneField(ESGSurvey, on_delete=models.CASCADE, related_name='analytics')
    
    # Category averages
    environment_priority_avg = models.FloatField(default=0.0)
    environment_status_quo_avg = models.FloatField(default=0.0)
    social_priority_avg = models.FloatField(default=0.0)
    social_status_quo_avg = models.FloatField(default=0.0)
    governance_priority_avg = models.FloatField(default=0.0)
    governance_status_quo_avg = models.FloatField(default=0.0)
    
    # Overall metrics
    total_responses = models.PositiveIntegerField(default=0)
    completion_rate = models.FloatField(default=0.0)
    
    # Timestamps
    last_calculated = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'esg_analytics'
        verbose_name_plural = 'ESG Analytics'
    
    def __str__(self):
        return f"Analytics for {self.survey}"