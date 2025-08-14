# esg/serializers.py
from rest_framework import serializers
from .models import ESGYear, ESGCategory, ESGQuestion, ESGQuestionResponse


class ESGYearSerializer(serializers.ModelSerializer):
    class Meta:
        model = ESGYear
        fields = ['year', 'is_active', 'is_current']


class ESGCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ESGCategory
        fields = ['id', 'name', 'display_name', 'description', 'is_active']


class ESGQuestionSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.display_name', read_only=True)
    
    class Meta:
        model = ESGQuestion
        fields = [
            'id', 'category', 'category_name', 'measure', 'index_code', 
            'order', 'is_active', 'year'
        ]
        # The 'questionnaire_type' field is removed from this serializer.


class ESGQuestionResponseSerializer(serializers.ModelSerializer):
    question_measure = serializers.CharField(source='question.measure', read_only=True)
    question_index_code = serializers.CharField(source='question.index_code', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    priority_display = serializers.CharField(source='get_priority_display', read_only=True)
    status_quo_display = serializers.CharField(source='get_status_quo_display', read_only=True)
    
    class Meta:
        model = ESGQuestionResponse
        fields = [
            'id', 'question', 'question_measure', 'question_index_code',
            'user', 'user_email', 'priority', 'priority_display',
            'status_quo', 'status_quo_display', 'comment', 'status',
            'questionnaire_type', # Added this field
            'responded_at', 'created_at', 'updated_at'
        ]
        read_only_fields = ['responded_at', 'created_at', 'updated_at', 'user', 'questionnaire_type'] # user and questionnaire_type are read-only here since the backend sets them automatically.

    def create(self, validated_data):
        # Auto-assign user from request context
        request = self.context.get('request')
        user = None
        if request and hasattr(request, 'user') and request.user.is_authenticated:
            user = request.user
            validated_data['user'] = user

        # Auto-assign questionnaire_type based on the user's role
        if user and user.role in ['stakeholder', 'client_admin']:
            validated_data['questionnaire_type'] = user.role
        
        return super().create(validated_data)


class ESGDashboardSerializer(serializers.Serializer):
    """Serializer for ESG dashboard data"""
    category = ESGCategorySerializer()
    questions = ESGQuestionSerializer(many=True)
    responses = ESGQuestionResponseSerializer(many=True)
    
    
class ESGSummarySerializer(serializers.Serializer):
    """Summary data for charts and reports"""
    total_questions = serializers.IntegerField()
    answered_questions = serializers.IntegerField()
    completion_percentage = serializers.FloatField()
    category_breakdown = serializers.DictField()
    priority_distribution = serializers.DictField()
    status_quo_distribution = serializers.DictField()