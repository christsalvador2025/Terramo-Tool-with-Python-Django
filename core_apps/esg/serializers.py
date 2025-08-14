# # esg/serializers.py
# from rest_framework import serializers
# from .models import ESGYear, ESGCategory, ESGQuestion, ESGQuestionResponse


# class ESGYearSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = ESGYear
#         fields = ['year', 'is_active', 'is_current']


# class ESGCategorySerializer(serializers.ModelSerializer):
#     class Meta:
#         model = ESGCategory
#         fields = ['id', 'name', 'display_name', 'description', 'is_active']


# class ESGQuestionSerializer(serializers.ModelSerializer):
#     category_name = serializers.CharField(source='category.display_name', read_only=True)
    
#     class Meta:
#         model = ESGQuestion
#         fields = [
#             'id', 'category', 'category_name', 'measure', 'index_code', 
#             'order', 'is_active', 'year'
#         ]
#         # The 'questionnaire_type' field is removed from this serializer.


# class ESGQuestionResponseSerializer(serializers.ModelSerializer):
#     question_measure = serializers.CharField(source='question.measure', read_only=True)
#     question_index_code = serializers.CharField(source='question.index_code', read_only=True)
#     user_email = serializers.CharField(source='user.email', read_only=True)
#     priority_display = serializers.CharField(source='get_priority_display', read_only=True)
#     status_quo_display = serializers.CharField(source='get_status_quo_display', read_only=True)
    
#     class Meta:
#         model = ESGQuestionResponse
#         fields = [
#             'id', 'question', 'question_measure', 'question_index_code',
#             'user', 'user_email', 'priority', 'priority_display',
#             'status_quo', 'status_quo_display', 'comment', 'status',
#             'questionnaire_type', # Added this field
#             'responded_at', 'created_at', 'updated_at'
#         ]
#         read_only_fields = ['responded_at', 'created_at', 'updated_at', 'user', 'questionnaire_type'] # user and questionnaire_type are read-only here since the backend sets them automatically.

#     def create(self, validated_data):
#         # Auto-assign user from request context
#         request = self.context.get('request')
#         user = None
#         if request and hasattr(request, 'user') and request.user.is_authenticated:
#             user = request.user
#             validated_data['user'] = user

#         # Auto-assign questionnaire_type based on the user's role
#         if user and user.role in ['stakeholder', 'client_admin']:
#             validated_data['questionnaire_type'] = user.role
        
#         return super().create(validated_data)


# class ESGDashboardSerializer(serializers.Serializer):
#     """Serializer for ESG dashboard data"""
#     category = ESGCategorySerializer()
#     questions = ESGQuestionSerializer(many=True)
#     responses = ESGQuestionResponseSerializer(many=True)
    
    
# class ESGSummarySerializer(serializers.Serializer):
#     """Summary data for charts and reports"""
#     total_questions = serializers.IntegerField()
#     answered_questions = serializers.IntegerField()
#     completion_percentage = serializers.FloatField()
#     category_breakdown = serializers.DictField()
#     priority_distribution = serializers.DictField()
#     status_quo_distribution = serializers.DictField()


from rest_framework import serializers
# from django.contrib.auth import get_user_model
from django.conf import settings
from .models import (
    ESGYear, ESGCategory, ESGQuestion, ESGQuestionResponse,
    ESGSurvey, ESGSurveyQuestion, StakeholderResponse,
    ClientResponse, ESGAnalytics
)
from core_apps.authentication.models import Stakeholder
from core_apps.clients.models import Client

# User = get_user_model()
User = settings.AUTH_USER_MODEL


class ESGYearSerializer(serializers.ModelSerializer):
    class Meta:
        model = ESGYear
        fields = ['id', 'year', 'is_active', 'is_current', 'created_at', 'updated_at']


class ESGCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ESGCategory
        fields = ['id', 'name', 'display_name', 'description', 'is_active', 'created_at', 'updated_at']


class ESGQuestionSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.display_name', read_only=True)
    year_value = serializers.IntegerField(source='year.year', read_only=True)
    
    class Meta:
        model = ESGQuestion
        fields = [
            'id', 'category', 'category_name', 'measure', 'index_code',
            'desription', 'order', 'is_active', 'year', 'year_value',
            'created_at', 'updated_at'
        ]


class ESGQuestionResponseSerializer(serializers.ModelSerializer):
    question_detail = ESGQuestionSerializer(source='question', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    priority_display = serializers.CharField(source='get_priority_display', read_only=True)
    status_quo_display = serializers.CharField(source='get_status_quo_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    questionnaire_type_display = serializers.CharField(source='get_questionnaire_type_display', read_only=True)
    
    class Meta:
        model = ESGQuestionResponse
        fields = [
            'id', 'question', 'question_detail', 'user', 'user_email',
            'questionnaire_type', 'questionnaire_type_display',
            'priority', 'priority_display', 'status_quo', 'status_quo_display',
            'comment', 'status', 'status_display', 'responded_at',
            'is_answered', 'completion_score', 'created_at', 'updated_at'
        ]
        read_only_fields = ['user', 'responded_at', 'is_answered', 'completion_score']


class ESGSurveySerializer(serializers.ModelSerializer):
    client_name = serializers.CharField(source='client.company_name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = ESGSurvey
        fields = [
            'id', 'client', 'client_name', 'title', 'year', 'status', 'status_display',
            'description', 'start_date', 'end_date', 'created_by', 'created_by_name',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_by']


class ESGSurveyQuestionSerializer(serializers.ModelSerializer):
    question_detail = ESGQuestionSerializer(source='question', read_only=True)
    survey_title = serializers.CharField(source='survey.title', read_only=True)
    
    class Meta:
        model = ESGSurveyQuestion
        fields = [
            'id', 'survey', 'survey_title', 'question', 'question_detail',
            'order', 'is_required', 'is_active'
        ]


class StakeholderResponseSerializer(serializers.ModelSerializer):
    stakeholder_email = serializers.CharField(source='stakeholder.email', read_only=True)
    stakeholder_name = serializers.CharField(source='stakeholder.get_full_name', read_only=True)
    survey_question_detail = ESGSurveyQuestionSerializer(source='survey_question', read_only=True)
    priority_display = serializers.CharField(source='get_priority_display', read_only=True)
    status_quo_display = serializers.CharField(source='get_status_quo_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = StakeholderResponse
        fields = [
            'id', 'survey', 'stakeholder', 'stakeholder_email', 'stakeholder_name',
            'survey_question', 'survey_question_detail', 'priority', 'priority_display',
            'status_quo', 'status_quo_display', 'comment', 'status', 'status_display',
            'responded_at', 'created_at', 'updated_at'
        ]
        read_only_fields = ['stakeholder', 'responded_at']


class ClientResponseSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.CharField(source='user.get_full_name', read_only=True)
    survey_question_detail = ESGSurveyQuestionSerializer(source='survey_question', read_only=True)
    priority_display = serializers.CharField(source='get_priority_display', read_only=True)
    status_quo_display = serializers.CharField(source='get_status_quo_display', read_only=True)
    
    class Meta:
        model = ClientResponse
        fields = [
            'id', 'survey', 'user', 'user_email', 'user_name',
            'survey_question', 'survey_question_detail',
            'priority', 'priority_display', 'status_quo', 'status_quo_display',
            'comment', 'created_at', 'updated_at'
        ]
        read_only_fields = ['user']


class ESGAnalyticsSerializer(serializers.ModelSerializer):
    survey_detail = ESGSurveySerializer(source='survey', read_only=True)
    
    class Meta:
        model = ESGAnalytics
        fields = [
            'id', 'survey', 'survey_detail', 'environment_priority_avg',
            'environment_status_quo_avg', 'social_priority_avg',
            'social_status_quo_avg', 'governance_priority_avg',
            'governance_status_quo_avg', 'total_responses',
            'completion_rate', 'last_calculated'
        ]


# Dashboard specific serializers
class ESGDashboardSerializer(serializers.Serializer):
    """Serializer for ESG Dashboard data"""
    categories = ESGCategorySerializer(many=True, read_only=True)
    questions_by_category = serializers.DictField(read_only=True)
    user_responses = serializers.DictField(read_only=True)
    completion_stats = serializers.DictField(read_only=True)


class ESGChartDataSerializer(serializers.Serializer):
    """Serializer for ESG Chart visualization data"""
    category = serializers.CharField()
    questions = serializers.ListField(
        child=serializers.DictField()
    )


class StakeholderListSerializer(serializers.ModelSerializer):
    """Simplified serializer for stakeholder listing"""
    class Meta:
        model = Stakeholder
        fields = ['id', 'email', 'first_name', 'last_name', 'is_active']


class ClientListSerializer(serializers.ModelSerializer):
    """Simplified serializer for client listing"""
    class Meta:
        model = Client
        fields = ['id', 'company_name', 'is_active']


# Bulk update serializers
class BulkESGResponseUpdateSerializer(serializers.Serializer):
    """Serializer for bulk updating ESG responses"""
    responses = serializers.ListField(
        child=serializers.DictField()
    )
    
    def validate_responses(self, value):
        required_fields = ['question_id', 'priority', 'status_quo']
        for response in value:
            for field in required_fields:
                if field not in response:
                    raise serializers.ValidationError(
                        f"Missing required field '{field}' in response"
                    )
        return value