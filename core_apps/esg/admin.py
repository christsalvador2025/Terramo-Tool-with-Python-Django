# # admin.py
# from django.contrib import admin
# from django.db import models
# from django.forms import Textarea
# from .models import (
#     ESGCategory, ESGQuestion, ESGSurvey, ESGSurveyQuestion,
#     StakeholderResponse, ClientResponse, ESGAnalytics,ESGQuestionResponse, ESGYear
# )

# from core_apps.clients.models import Client 
# from core_apps.authentication.models import Stakeholder


# @admin.register(ESGYear)
# class ESGYearAdmin(admin.ModelAdmin):
#     list_display = ['id', 'year', 'is_active', 'is_current']


# @admin.register(ESGQuestionResponse)
# class ESGQuestionResponseAdmin(admin.ModelAdmin):
#     list_display = ['id', 'user', 'priority', 'status_quo', 'status']

# @admin.register(ESGCategory)
# class ESGCategoryAdmin(admin.ModelAdmin):
#     list_display = ['display_name', 'name', 'is_active', 'created_at']
#     list_filter = ['is_active', 'created_at']
#     search_fields = ['display_name', 'name']
#     readonly_fields = ['created_at']
    
#     fieldsets = (
#         ('Basic Information', {
#             'fields': ('name', 'display_name', 'description')
#         }),
#         ('Status', {
#             'fields': ('is_active',)
#         }),
#         ('Metadata', {
#             'fields': ('created_at',),
#             'classes': ('collapse',)
#         }),
#     )


# @admin.register(ESGQuestion)
# class ESGQuestionAdmin(admin.ModelAdmin):
#     list_display = ['index_code', 'category', 'questionnaire_type', 'year', 'measure_preview', 'order', 'is_active']
#     list_filter = ['category', 'is_active', 'created_at']
#     search_fields = ['index_code', 'measure']
#     readonly_fields = ['created_at', 'updated_at']
#     list_editable = ['order', 'is_active']
#     ordering = ['category__name', 'order', 'index_code']
    
#     formfield_overrides = {
#         models.TextField: {'widget': Textarea(attrs={'rows': 3, 'cols': 80})},
#     }
    
#     fieldsets = (
#         ('Basic Information', {
#             'fields': ('category', 'index_code', 'measure', 'questionnaire_type', 'year')
#         }),
#         ('Settings', {
#             'fields': ('order', 'is_active')
#         }),
#         ('Metadata', {
#             'fields': ('created_at', 'updated_at'),
#             'classes': ('collapse',)
#         }),
#     )
    
#     def measure_preview(self, obj):
#         return obj.measure[:100] + "..." if len(obj.measure) > 100 else obj.measure
#     measure_preview.short_description = 'Measure'


# class ESGSurveyQuestionInline(admin.TabularInline):
#     model = ESGSurveyQuestion
#     extra = 0
#     fields = ['question', 'order', 'is_required', 'is_active']
#     readonly_fields = ['question']
#     ordering = ['order']


# @admin.register(ESGSurvey)
# class ESGSurveyAdmin(admin.ModelAdmin):
#     list_display = ['title', 'client', 'year', 'status', 'created_by', 'created_at']
#     list_filter = ['status', 'year', 'created_at']
#     search_fields = ['title', 'client__company_name']
#     readonly_fields = ['created_at', 'updated_at']
#     inlines = [ESGSurveyQuestionInline]
    
#     fieldsets = (
#         ('Basic Information', {
#             'fields': ('client', 'title', 'year', 'description')
#         }),
#         ('Settings', {
#             'fields': ('status', 'start_date', 'end_date')
#         }),
#         ('Metadata', {
#             'fields': ('created_by', 'created_at', 'updated_at'),
#             'classes': ('collapse',)
#         }),
#     )
    
#     def save_model(self, request, obj, form, change):
#         if not change:  # Only set created_by on creation
#             obj.created_by = request.user
#         super().save_model(request, obj, form, change)


# @admin.register(StakeholderResponse)
# class StakeholderResponseAdmin(admin.ModelAdmin):
#     list_display = [
#         'stakeholder_email', 'survey_title', 'question_code', 
#         'priority', 'status_quo', 'status', 'updated_at'
#     ]
#     list_filter = ['status', 'priority', 'status_quo', 'created_at', 'survey__client']
#     search_fields = [
#         'stakeholder__email', 'survey__title', 
#         'survey_question__question__index_code'
#     ]
#     readonly_fields = ['created_at', 'updated_at', 'responded_at']
    
#     fieldsets = (
#         ('Response Details', {
#             'fields': ('survey', 'stakeholder', 'survey_question')
#         }),
#         ('Answers', {
#             'fields': ('priority', 'status_quo', 'comment')
#         }),
#         ('Status', {
#             'fields': ('status', 'responded_at')
#         }),
#         ('Metadata', {
#             'fields': ('created_at', 'updated_at'),
#             'classes': ('collapse',)
#         }),
#     )
    
#     def stakeholder_email(self, obj):
#         return obj.stakeholder.email
#     stakeholder_email.short_description = 'Stakeholder'
    
#     def survey_title(self, obj):
#         return f"{obj.survey.title} ({obj.survey.year})"
#     survey_title.short_description = 'Survey'
    
#     def question_code(self, obj):
#         return obj.survey_question.question.index_code
#     question_code.short_description = 'Question'


# @admin.register(ClientResponse)
# class ClientResponseAdmin(admin.ModelAdmin):
#     list_display = [
#         'user_email', 'survey_title', 'question_code', 
#         'priority', 'status_quo', 'updated_at'
#     ]
#     list_filter = ['priority', 'status_quo', 'created_at', 'survey__client']
#     search_fields = [
#         'user__email', 'survey__title', 
#         'survey_question__question__index_code'
#     ]
#     readonly_fields = ['created_at', 'updated_at']
    
#     fieldsets = (
#         ('Response Details', {
#             'fields': ('survey', 'user', 'survey_question')
#         }),
#         ('Answers', {
#             'fields': ('priority', 'status_quo', 'comment')
#         }),
#         ('Metadata', {
#             'fields': ('created_at', 'updated_at'),
#             'classes': ('collapse',)
#         }),
#     )
    
#     def user_email(self, obj):
#         return obj.user.email
#     user_email.short_description = 'User'
    
#     def survey_title(self, obj):
#         return f"{obj.survey.title} ({obj.survey.year})"
#     survey_title.short_description = 'Survey'
    
#     def question_code(self, obj):
#         return obj.survey_question.question.index_code
#     question_code.short_description = 'Question'


# @admin.register(ESGAnalytics)
# class ESGAnalyticsAdmin(admin.ModelAdmin):
#     list_display = [
#         'survey', 'total_responses', 'completion_rate', 'last_calculated'
#     ]
#     list_filter = ['last_calculated', 'survey__client']
#     search_fields = ['survey__title', 'survey__client__company_name']
#     readonly_fields = ['last_calculated']
    
#     fieldsets = (
#         ('Survey', {
#             'fields': ('survey',)
#         }),
#         ('Environment Metrics', {
#             'fields': ('environment_priority_avg', 'environment_status_quo_avg'),
#             'classes': ('collapse',)
#         }),
#         ('Social Metrics', {
#             'fields': ('social_priority_avg', 'social_status_quo_avg'),
#             'classes': ('collapse',)
#         }),
#         ('Governance Metrics', {
#             'fields': ('governance_priority_avg', 'governance_status_quo_avg'),
#             'classes': ('collapse',)
#         }),
#         ('Overall Metrics', {
#             'fields': ('total_responses', 'completion_rate')
#         }),
#         ('Metadata', {
#             'fields': ('last_calculated',)
#         }),
#     )


# # Admin actions
# @admin.action(description='Recalculate analytics for selected surveys')
# def recalculate_analytics(modeladmin, request, queryset):
#     for survey in queryset:
#         # Trigger analytics recalculation
#         from django.db.models import Avg, Count, Q
        
#         analytics, created = ESGAnalytics.objects.get_or_create(
#             survey=survey,
#             defaults={'total_responses': 0, 'completion_rate': 0.0}
#         )
        
#         # Calculate category averages
#         categories = ['environment', 'social', 'governance']
#         for category in categories:
#             responses = survey.responses.filter(
#                 survey_question__question__category__name=category,
#                 status='submitted'
#             ).aggregate(
#                 priority_avg=Avg('priority'),
#                 status_quo_avg=Avg('status_quo')
#             )
            
#             setattr(analytics, f'{category}_priority_avg', responses['priority_avg'] or 0.0)
#             setattr(analytics, f'{category}_status_quo_avg', responses['status_quo_avg'] or 0.0)
        
#         # Update overall metrics
#         analytics.total_responses = survey.responses.filter(status='submitted').count()
#         analytics.save()

# # Add the action to ESGSurvey admin
# ESGSurveyAdmin.actions = [recalculate_analytics]


# esg/admin.py
from django.contrib import admin
from .models import ESGYear, ESGCategory, ESGQuestion, ESGQuestionResponse
from django.db import models
from django.forms import Textarea

@admin.register(ESGYear)
class ESGYearAdmin(admin.ModelAdmin):
    """Admin configuration for the ESGYear model."""
    list_display = ['year', 'is_active', 'is_current', 'created_at']
    list_filter = ['is_active', 'is_current']
    search_fields = ['year']
    ordering = ['-year']


@admin.register(ESGCategory)
class ESGCategoryAdmin(admin.ModelAdmin):
    """Admin configuration for the ESGCategory model."""
    list_display = ['name', 'display_name', 'is_active', 'created_at']
    list_filter = ['is_active']
    search_fields = ['name', 'display_name']
    ordering = ['name']


@admin.register(ESGQuestion)
class ESGQuestionAdmin(admin.ModelAdmin):
    """Admin configuration for the ESGQuestion model."""
    # Note: The 'questionnaire_type' field was commented out in your ESGQuestion model,
    # so we've removed it from the list_display and list_filter to avoid an error.
    list_display = ['index_code', 'category', 'measure_short', 'year', 'is_active', 'order']
    list_filter = ['category', 'year', 'is_active']
    search_fields = ['index_code', 'measure']
    ordering = ['category', 'order', 'index_code']
    list_per_page = 50
    
    formfield_overrides = {
        models.TextField: {'widget': Textarea(attrs={'rows': 3, 'cols': 80})},
    }
    def measure_short(self, obj):
        """Truncates the measure text for display in the list view."""
        return obj.measure[:100] + '...' if len(obj.measure) > 100 else obj.measure
    measure_short.short_description = 'Measure'
    

@admin.register(ESGQuestionResponse)
class ESGQuestionResponseAdmin(admin.ModelAdmin):
    """Admin configuration for the ESGQuestionResponse model."""
    list_display = [
        'user', 'question_index', 'category', 'priority_display', 
        'status_quo_display', 'status', 'responded_at'
    ]
    list_filter = [
        'status', 'priority', 'status_quo', 'question__category', 
        'question__year', 'responded_at'
    ]
    search_fields = ['user__email', 'question__index_code', 'question__measure']
    ordering = ['-updated_at']
    readonly_fields = ['responded_at', 'created_at', 'updated_at']
    list_per_page = 50
    
    def question_index(self, obj):
        """Displays the question's index code."""
        return obj.question.index_code
    question_index.short_description = 'Question Index'
    
    def category(self, obj):
        """Displays the category's display name."""
        return obj.question.category.display_name
    category.short_description = 'Category'
    
    def priority_display(self, obj):
        """Displays the human-readable priority choice."""
        return obj.get_priority_display()
    priority_display.short_description = 'Priority'
    
    def status_quo_display(self, obj):
        """Displays the human-readable status quo choice."""
        return obj.get_status_quo_display()
    status_quo_display.short_description = 'Status Quo'
    
    def get_queryset(self, request):
        """Optimizes the queryset to reduce database queries."""
        qs = super().get_queryset(request)
        return qs.select_related('user', 'question', 'question__category', 'question__year')
