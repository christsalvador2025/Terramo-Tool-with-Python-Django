
 
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
    list_display = ['name', 'display_name','category_prefix', 'is_active', 'created_at']
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
        'question__year', 'responded_at', 'user'
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
