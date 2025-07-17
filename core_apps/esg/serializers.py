from rest_framework import serializers
from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone
from .models import (
    ESGCategory, ESGYear, ESGQuestion, ESGResponse, 
    ESGSummary, ESGAuditLog
)


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'full_name']
        read_only_fields = ['id', 'username']
    
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.username


class ESGCategorySerializer(serializers.ModelSerializer):
    """Serializer for ESG Categories"""
    question_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ESGCategory
        fields = ['code', 'name', 'description', 'is_active', 'question_count']
        read_only_fields = ['code']
    
    def get_question_count(self, obj):
        """Get active question count for this category"""
        return obj.questions.filter(is_active=True).count()


class ESGYearSerializer(serializers.ModelSerializer):
    """Serializer for ESG Years"""
    question_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ESGYear
        fields = ['year', 'is_active', 'is_current', 'question_count']
    
    def get_question_count(self, obj):
        """Get total question count for this year"""
        return obj.questions.filter(is_active=True).count()
    
    def validate_year(self, value):
        """Validate year is reasonable"""
        current_year = timezone.now().year
        if value < 2020 or value > current_year + 10:
            raise serializers.ValidationError(
                f"Year must be between 2020 and {current_year + 10}"
            )
        return value


class ESGQuestionListSerializer(serializers.ModelSerializer):
    """Serializer for ESG Questions - List view"""
    category = ESGCategorySerializer(read_only=True)
    year = ESGYearSerializer(read_only=True)
    response_count = serializers.SerializerMethodField()
    user_response = serializers.SerializerMethodField()
    
    class Meta:
        model = ESGQuestion
        fields = [
            'id', 'measure_id', 'category', 'year', 'measure', 
            'order', 'priority', 'status_quo', 'is_active',
            'response_count', 'user_response', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'measure_id', 'created_at', 'updated_at']
    
    def get_response_count(self, obj):
        """Get total response count for this question"""
        return obj.responses.count()
    
    def get_user_response(self, obj):
        """Get current user's response to this question"""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            try:
                response = obj.responses.get(user=request.user)
                return ESGResponseSerializer(response, context=self.context).data
            except ESGResponse.DoesNotExist:
                return None
        return None


class ESGQuestionDetailSerializer(serializers.ModelSerializer):
    """Serializer for ESG Questions - Detail view"""
    category = ESGCategorySerializer(read_only=True)
    year = ESGYearSerializer(read_only=True)
    created_by = UserSerializer(read_only=True)
    updated_by = UserSerializer(read_only=True)
    responses = serializers.SerializerMethodField()
    
    class Meta:
        model = ESGQuestion
        fields = [
            'id', 'measure_id', 'category', 'year', 'measure', 
            'order', 'priority', 'status_quo', 'is_active',
            'created_by', 'updated_by', 'created_at', 'updated_at',
            'responses'
        ]
        read_only_fields = ['id', 'measure_id', 'created_at', 'updated_at']
    
    def get_responses(self, obj):
        """Get all responses for this question"""
        responses = obj.responses.select_related('user').all()
        return ESGResponseSerializer(responses, many=True, context=self.context).data


class ESGQuestionCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating ESG Questions"""
    category_code = serializers.CharField(write_only=True)
    year_value = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = ESGQuestion
        fields = [
            'measure', 'priority', 'status_quo', 'is_active',
            'category_code', 'year_value'
        ]
    
    def validate_category_code(self, value):
        """Validate category exists"""
        try:
            ESGCategory.objects.get(code=value, is_active=True)
            return value
        except ESGCategory.DoesNotExist:
            raise serializers.ValidationError("Invalid category code")
    
    def validate_year_value(self, value):
        """Validate year exists"""
        try:
            ESGYear.objects.get(year=value, is_active=True)
            return value
        except ESGYear.DoesNotExist:
            raise serializers.ValidationError("Invalid year")
    
    def create(self, validated_data):
        """Create question with proper category and year"""
        category_code = validated_data.pop('category_code')
        year_value = validated_data.pop('year_value')
        
        category = ESGCategory.objects.get(code=category_code)
        year = ESGYear.objects.get(year=year_value)
        
        question = ESGQuestion.objects.create(
            category=category,
            year=year,
            **validated_data
        )
        return question


class ESGQuestionReorderSerializer(serializers.Serializer):
    """Serializer for reordering questions"""
    new_order = serializers.IntegerField(min_value=1)
    
    def validate_new_order(self, value):
        """Validate new order is within bounds"""
        question = self.instance
        max_order = ESGQuestion.objects.filter(
            category=question.category,
            year=question.year,
            is_active=True
        ).count()
        
        if value > max_order:
            raise serializers.ValidationError(
                f"Order cannot be greater than {max_order}"
            )
        return value
    
    def update(self, instance, validated_data):
        """Update question order"""
        new_order = validated_data['new_order']
        
        # Use the custom manager method for reordering
        updated_question = ESGQuestion.objects.reorder_questions(
            category=instance.category,
            year=instance.year,
            question_id=instance.id,
            new_order=new_order
        )
        
        return updated_question


class ESGResponseSerializer(serializers.ModelSerializer):
    """Serializer for ESG Responses"""
    user = UserSerializer(read_only=True)
    question = ESGQuestionListSerializer(read_only=True)
    question_id = serializers.UUIDField(write_only=True)
    
    class Meta:
        model = ESGResponse
        fields = [
            'id', 'user', 'question', 'question_id', 'comment',
            'priority', 'status_quo', 'is_draft', 'submitted_at',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'user', 'submitted_at', 'created_at', 'updated_at']
    
    def validate_question_id(self, value):
        """Validate question exists and is active"""
        try:
            question = ESGQuestion.objects.get(id=value, is_active=True)
            return value
        except ESGQuestion.DoesNotExist:
            raise serializers.ValidationError("Invalid question ID")
    
    def create(self, validated_data):
        """Create response with current user"""
        question_id = validated_data.pop('question_id')
        question = ESGQuestion.objects.get(id=question_id)
        
        # Get or create response for this user and question
        response, created = ESGResponse.objects.get_or_create(
            user=self.context['request'].user,
            question=question,
            defaults=validated_data
        )
        
        if not created:
            # Update existing response
            for attr, value in validated_data.items():
                setattr(response, attr, value)
            response.save()
        
        return response
    
    def update(self, instance, validated_data):
        """Update response"""
        validated_data.pop('question_id', None)  # Remove question_id if present
        return super().update(instance, validated_data)


class ESGResponseSubmitSerializer(serializers.Serializer):
    """Serializer for submitting responses"""
    response_ids = serializers.ListField(
        child=serializers.UUIDField(),
        allow_empty=False
    )
    
    def validate_response_ids(self, value):
        """Validate all response IDs belong to current user"""
        user = self.context['request'].user
        responses = ESGResponse.objects.filter(
            id__in=value,
            user=user,
            is_draft=True
        )
        
        if len(responses) != len(value):
            raise serializers.ValidationError(
                "Some responses are invalid or already submitted"
            )
        
        return value
    
    def save(self):
        """Submit all responses"""
        response_ids = self.validated_data['response_ids']
        user = self.context['request'].user
        
        with transaction.atomic():
            responses = ESGResponse.objects.filter(
                id__in=response_ids,
                user=user,
                is_draft=True
            )
            
            for response in responses:
                response.submit()
            
            # Update summaries for affected categories
            categories = set()
            years = set()
            
            for response in responses:
                categories.add(response.question.category)
                years.add(response.question.year)
            
            for category in categories:
                for year in years:
                    summary, created = ESGSummary.objects.get_or_create(
                        user=user,
                        year=year,
                        category=category
                    )
                    summary.calculate_summary()
            
            return responses


class ESGSummarySerializer(serializers.ModelSerializer):
    """Serializer for ESG Summary"""
    user = UserSerializer(read_only=True)
    year = ESGYearSerializer(read_only=True)
    category = ESGCategorySerializer(read_only=True)
    
    class Meta:
        model = ESGSummary
        fields = [
            'id', 'user', 'year', 'category',
            'total_questions', 'completed_questions', 
            'in_progress_questions', 'not_started_questions',
            'high_priority_count', 'medium_priority_count', 'low_priority_count',
            'completion_percentage', 'last_updated', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'total_questions', 'completed_questions', 
            'in_progress_questions', 'not_started_questions',
            'high_priority_count', 'medium_priority_count', 'low_priority_count',
            'completion_percentage', 'last_updated', 'created_at', 'updated_at'
        ]


class ESGDashboardSerializer(serializers.Serializer):
    """Serializer for ESG Dashboard data"""
    year = ESGYearSerializer(read_only=True)
    categories = serializers.SerializerMethodField()
    overall_completion = serializers.SerializerMethodField()
    total_questions = serializers.SerializerMethodField()
    completed_questions = serializers.SerializerMethodField()
    
    def get_categories(self, obj):
        """Get summary data for all categories"""
        user = self.context['request'].user
        summaries = ESGSummary.objects.filter(
            user=user,
            year=obj
        ).select_related('category')
        
        return ESGSummarySerializer(summaries, many=True, context=self.context).data
    
    def get_overall_completion(self, obj):
        """Calculate overall completion percentage"""
        user = self.context['request'].user
        summaries = ESGSummary.objects.filter(user=user, year=obj)
        
        if not summaries.exists():
            return 0.0
        
        total_questions = sum(s.total_questions for s in summaries)
        completed_questions = sum(s.completed_questions for s in summaries)
        
        if total_questions == 0:
            return 0.0
        
        return round((completed_questions / total_questions) * 100, 2)
    
    def get_total_questions(self, obj):
        """Get total questions for this year"""
        user = self.context['request'].user
        summaries = ESGSummary.objects.filter(user=user, year=obj)
        return sum(s.total_questions for s in summaries)
    
    def get_completed_questions(self, obj):
        """Get completed questions for this year"""
        user = self.context['request'].user
        summaries = ESGSummary.objects.filter(user=user, year=obj)
        return sum(s.completed_questions for s in summaries)


class ESGAuditLogSerializer(serializers.ModelSerializer):
    """Serializer for ESG Audit Log"""
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = ESGAuditLog
        fields = [
            'id', 'user', 'action', 'model_name', 'object_id',
            'changes', 'timestamp', 'ip_address'
        ]
        read_only_fields = ['id', 'timestamp']


class ESGBulkResponseSerializer(serializers.Serializer):
    """Serializer for bulk response operations"""
    responses = serializers.ListField(
        child=serializers.DictField(),
        allow_empty=False
    )
    
    def validate_responses(self, value):
        """Validate response data"""
        validated_responses = []
        
        for response_data in value:
            # Validate each response
            serializer = ESGResponseSerializer(
                data=response_data,
                context=self.context
            )
            if serializer.is_valid():
                validated_responses.append(serializer.validated_data)
            else:
                raise serializers.ValidationError(
                    f"Invalid response data: {serializer.errors}"
                )
        
        return validated_responses
    
    def save(self):
        """Save all responses"""
        responses_data = self.validated_data['responses']
        user = self.context['request'].user
        created_responses = []
        
        with transaction.atomic():
            for response_data in responses_data:
                question_id = response_data.pop('question_id')
                question = ESGQuestion.objects.get(id=question_id)
                
                response, created = ESGResponse.objects.get_or_create(
                    user=user,
                    question=question,
                    defaults=response_data
                )
                
                if not created:
                    for attr, value in response_data.items():
                        setattr(response, attr, value)
                    response.save()
                
                created_responses.append(response)
        
        return created_responses