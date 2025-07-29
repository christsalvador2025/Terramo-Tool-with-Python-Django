from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.db.models import Count, Q
from django.contrib.admin import SimpleListFilter
from django.http import HttpResponseRedirect
from django.contrib import messages
from django.urls import path
from django.template.response import TemplateResponse
from .models import (
    ESGCategory, ESGYear, ESGQuestion, ESGResponse, 
    ESGSummary, ESGAuditLog
)


class YearFilter(SimpleListFilter):
    """Custom filter for years"""
    title = 'Year'
    parameter_name = 'year'
    
    def lookups(self, request, model_admin):
        years = ESGYear.objects.filter(is_active=True).values_list('year', 'year')
        return years
    
    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(year__year=self.value())
        return queryset


class CategoryFilter(SimpleListFilter):
    """Custom filter for categories"""
    title = 'Category'
    parameter_name = 'category'
    
    def lookups(self, request, model_admin):
        categories = ESGCategory.objects.filter(is_active=True).values_list('code', 'name')
        return categories
    
    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(category__code=self.value())
        return queryset


class ESGResponseInline(admin.TabularInline):
    """Inline for ESG Responses"""
    model = ESGResponse
    extra = 0
    readonly_fields = ['user', 'submitted_at', 'created_at']
    fields = ['user', 'priority', 'status_quo', 'comment', 'is_draft', 'submitted_at']
    
    def has_add_permission(self, request, obj=None):
        return False


@admin.register(ESGCategory)
class ESGCategoryAdmin(admin.ModelAdmin):
    list_display = ['code', 'name', 'is_active', 'question_count', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'description']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('code', 'name', 'description', 'is_active')
        }),
        ('Audit Information', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def question_count(self, obj):
        """Show total questions for this category"""
        count = obj.questions.filter(is_active=True).count()
        return format_html(
            '<span style="color: #28a745; font-weight: bold;">{}</span>',
            count
        )
    question_count.short_description = 'Active Questions'
    
    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related('questions')


@admin.register(ESGYear)
class ESGYearAdmin(admin.ModelAdmin):
    list_display = ['year', 'is_active', 'is_current', 'question_count', 'response_count']
    list_filter = ['is_active', 'is_current']
    ordering = ['-year']
    
    def question_count(self, obj):
        """Show total questions for this year"""
        count = obj.questions.filter(is_active=True).count()
        return format_html(
            '<span style="color: #007bff; font-weight: bold;">{}</span>',
            count
        )
    question_count.short_description = 'Questions'
    
    def response_count(self, obj):
        """Show total responses for this year"""
        count = ESGResponse.objects.filter(question__year=obj).count()
        return format_html(
            '<span style="color: #6c757d; font-weight: bold;">{}</span>',
            count
        )
    response_count.short_description = 'Responses'
    
    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related('questions')


@admin.register(ESGQuestion)
class ESGQuestionAdmin(admin.ModelAdmin):
    list_display = [
        'measure_id', 'category', 'year', 'measure_preview', 
        'priority', 'status_quo', 'order', 'response_count', 
        'is_active', 'created_at'
    ]
    list_filter = [CategoryFilter, YearFilter, 'priority', 'status_quo', 'is_active']
    search_fields = ['measure_id', 'measure']
    readonly_fields = ['measure_id', 'created_at', 'updated_at', 'created_by', 'updated_by']
    ordering = ['category', 'year', 'order']
    
    fieldsets = (
        ('Question Information', {
            'fields': ('measure_id', 'category', 'year', 'measure', 'order')
        }),
        ('Settings', {
            'fields': ('priority', 'status_quo', 'is_active')
        }),
        ('Audit Information', {
            'fields': ('created_at', 'updated_at', 'created_by', 'updated_by'),
            'classes': ('collapse',)
        }),
    )
    
    inlines = [ESGResponseInline]
    
    def measure_preview(self, obj):
        """Show truncated measure text"""
        return format_html(
            '<div style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">{}</div>',
            obj.measure[:100] + '...' if len(obj.measure) > 100 else obj.measure
        )
    measure_preview.short_description = 'Measure'
    
    def response_count(self, obj):
        """Show response count for this question"""
        count = obj.responses.count()
        if count > 0:
            url = reverse('admin:esg_esgresponse_changelist') + f'?question__id__exact={obj.id}'
            return format_html(
                '<a href="{}" style="color: #28a745; font-weight: bold;">{}</a>',
                url, count
            )
        return format_html('<span style="color: #dc3545;">0</span>')
    response_count.short_description = 'Responses'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'category', 'year'
        ).prefetch_related('responses')
    
    def save_model(self, request, obj, form, change):
        if not change:  # Creating new object
            obj.created_by = request.user
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)
    
    # Custom admin actions
    actions = ['make_active', 'make_inactive', 'set_high_priority', 'set_medium_priority']
    
    def make_active(self, request, queryset):
        updated = queryset.update(is_active=True)
        messages.success(request, f'{updated} questions marked as active.')
    make_active.short_description = "Mark selected questions as active"
    
    def make_inactive(self, request, queryset):
        updated = queryset.update(is_active=False)
        messages.success(request, f'{updated} questions marked as inactive.')
    make_inactive.short_description = "Mark selected questions as inactive"
    
    def set_high_priority(self, request, queryset):
        updated = queryset.update(priority='high')
        messages.success(request, f'{updated} questions set to high priority.')
    set_high_priority.short_description = "Set selected questions to high priority"
    
    def set_medium_priority(self, request, queryset):
        updated = queryset.update(priority='medium')
        messages.success(request, f'{updated} questions set to medium priority.')
    set_medium_priority.short_description = "Set selected questions to medium priority"


@admin.register(ESGResponse)
class ESGResponseAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'user_client','question_measure_id', 'question_category', 
        'priority', 'status_quo', 'is_draft', 'submitted_at', 'created_at'
    ]
    list_filter = [
        'is_draft', 'priority', 'status_quo', 
        CategoryFilter, YearFilter, 'created_at'
    ]
    search_fields = ['user__username', 'question__measure_id', 'comment']
    readonly_fields = ['submitted_at', 'created_at', 'updated_at', 'created_by', 'updated_by']
    
    fieldsets = (
        ('Response Information', {
            'fields': ('user', 'question',)
        }),
        ('Assessment', {
            'fields': ('priority', 'status_quo',  'comment', 'is_draft', 'submitted_at')
        }),
        ('Audit Information', {
            'fields': ('created_at', 'updated_at', 'created_by', 'updated_by'),
            'classes': ('collapse',)
        }),
    )
    
    def question_measure_id(self, obj):
        """Show question measure ID"""
        return obj.question.measure_id
    question_measure_id.short_description = 'Measure ID'
    question_measure_id.admin_order_field = 'question__measure_id'
    
    def question_category(self, obj):
        """Show question category"""
        return obj.question.category.name
    question_category.short_description = 'Category'
    question_category.admin_order_field = 'question__category__name'

    def user_client(self, obj):
        """Show user company"""
        return obj.user.client.company_name
    user_client.short_description = 'Client'
    user_client.admin_order_field = 'user__client__company_name'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'user', 'question__category', 'question__year'
        )
    
    def save_model(self, request, obj, form, change):
        if not change:  # Creating new object
            obj.created_by = request.user
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)
    
    # Custom admin actions
    actions = ['submit_responses', 'mark_as_draft']
    
    def submit_responses(self, request, queryset):
        updated = 0
        for response in queryset.filter(is_draft=True):
            response.submit()
            updated += 1
        messages.success(request, f'{updated} responses submitted.')
    submit_responses.short_description = "Submit selected draft responses"
    
    def mark_as_draft(self, request, queryset):
        updated = queryset.update(is_draft=True, submitted_at=None)
        messages.success(request, f'{updated} responses marked as draft.')
    mark_as_draft.short_description = "Mark selected responses as draft"


@admin.register(ESGSummary)
class ESGSummaryAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'year', 'category', 'completion_percentage', 
        'total_questions', 'completed_questions', 'last_updated'
    ]
    list_filter = [CategoryFilter, YearFilter, 'last_updated']
    search_fields = ['user__username']
    readonly_fields = [
        'total_questions', 'completed_questions', 'in_progress_questions',
        'not_started_questions', 'high_priority_count', 'medium_priority_count',
        'low_priority_count', 'completion_percentage', 'last_updated',
        'created_at', 'updated_at'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('user', 'year', 'category')
        }),
        ('Question Statistics', {
            'fields': (
                'total_questions', 'completed_questions', 
                'in_progress_questions', 'not_started_questions',
                'completion_percentage'
            )
        }),
        ('Priority Breakdown', {
            'fields': ('high_priority_count', 'medium_priority_count', 'low_priority_count')
        }),
        ('Timestamps', {
            'fields': ('last_updated', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'year', 'category')
    
    # Custom admin actions
    actions = ['recalculate_summaries']
    
    def recalculate_summaries(self, request, queryset):
        updated = 0
        for summary in queryset:
            summary.calculate_summary()
            updated += 1
        messages.success(request, f'{updated} summaries recalculated.')
    recalculate_summaries.short_description = "Recalculate selected summaries"


@admin.register(ESGAuditLog)
class ESGAuditLogAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'action', 'model_name', 'object_id', 
        'timestamp', 'ip_address'
    ]
    list_filter = ['action', 'model_name', 'timestamp']
    search_fields = ['user__username', 'object_id']
    readonly_fields = ['user', 'action', 'model_name', 'object_id', 'changes', 'timestamp', 'ip_address']
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser  # Only superusers can delete audit logs


# Custom admin site configuration
admin.site.site_header = "ESG Questionnaire Administration"
admin.site.site_title = "ESG Admin"
admin.site.index_title = "Welcome to ESG Questionnaire Administration"