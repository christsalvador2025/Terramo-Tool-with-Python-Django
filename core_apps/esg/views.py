# esg/views.py
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.db.models import Count, Q
from .models import ESGYear, ESGCategory, ESGQuestion, ESGQuestionResponse
from .serializers import (
    ESGYearSerializer, ESGCategorySerializer, ESGQuestionSerializer,
    ESGQuestionResponseSerializer, ESGDashboardSerializer, ESGSummarySerializer
)


class ESGYearViewSet(viewsets.ModelViewSet):
    queryset = ESGYear.objects.all()
    serializer_class = ESGYearSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.role == 'terramo_admin':
            return ESGYear.objects.all()
        return ESGYear.objects.filter(is_active=True)


class ESGCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ESGCategory.objects.filter(is_active=True)
    serializer_class = ESGCategorySerializer
    permission_classes = [permissions.IsAuthenticated]


class ESGQuestionViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ESGQuestionSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = None
    def get_queryset(self):
        queryset = ESGQuestion.objects.filter(is_active=True)
        
        year = self.request.query_params.get('year')
        category = self.request.query_params.get('category')
        
        if year:
            queryset = queryset.filter(year__year=year)
        
        if category:
            queryset = queryset.filter(category__name=category)
            
        # The questionnaire_type filter is now removed from here.
        # Questions are filtered based on responses, not the question itself.
        
        return queryset.order_by('category', 'order', 'index_code')


class ESGQuestionResponseViewSet(viewsets.ModelViewSet):
    serializer_class = ESGQuestionResponseSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = ESGQuestionResponse.objects.all()
        
        user_role = self.request.user.role
        
        if user_role == 'stakeholder':
            # Stakeholders can only see their own responses
            queryset = queryset.filter(user=self.request.user, questionnaire_type='stakeholder')
        elif user_role == 'client_admin':
            # Client admins can see responses from their client
            queryset = queryset.filter(user__client=self.request.user.client, questionnaire_type='client_admin')
        # terramo_admin can see all responses
        
        return queryset.order_by('-updated_at')
    
    def perform_create(self, serializer):
        user_role = self.request.user.role
        questionnaire_type = None
        if user_role == 'stakeholder':
            questionnaire_type = 'stakeholder'
        elif user_role == 'client_admin':
            questionnaire_type = 'client_admin'
        
        serializer.save(user=self.request.user, questionnaire_type=questionnaire_type)


class ESGDashboardViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=False, methods=['get'])
    def overview(self, request):
        """Get ESG overview data"""
        year = request.query_params.get('year')
        current_year = ESGYear.objects.filter(is_current=True).first()
        if not year and current_year:
            year = current_year.year
        
        user_role = request.user.role
        questionnaire_type = None
        if user_role == 'stakeholder':
            questionnaire_type = 'stakeholder'
        elif user_role == 'client_admin':
            questionnaire_type = 'client_admin'

        questions_query = ESGQuestion.objects.filter(year__year=year, is_active=True)
        
        if questionnaire_type:
            # We assume a question's type is determined by the response, so we filter responses
            # based on the user's role, and then use those responses to get the relevant questions.
            relevant_question_ids = ESGQuestionResponse.objects.filter(
                user=request.user if user_role == 'stakeholder' else None,
                user__client=request.user.client if user_role == 'client_admin' else None,
                questionnaire_type=questionnaire_type
            ).values_list('question_id', flat=True)
            
            questions_query = questions_query.filter(id__in=relevant_question_ids).distinct()

        data = []
        categories = ESGCategory.objects.filter(is_active=True)
        
        for category in categories:
            cat_questions = questions_query.filter(category=category)
            
            responses = ESGQuestionResponse.objects.filter(question__in=cat_questions)
            if user_role == 'stakeholder':
                responses = responses.filter(user=request.user)
            elif user_role == 'client_admin':
                responses = responses.filter(user__client=request.user.client)
            
            data.append({
                'category': ESGCategorySerializer(category).data,
                'questions': ESGQuestionSerializer(cat_questions, many=True).data,
                'responses': ESGQuestionResponseSerializer(responses, many=True).data
            })
        
        return Response(data)
    
    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get ESG summary statistics"""
        year = request.query_params.get('year')
        current_year = ESGYear.objects.filter(is_current=True).first()
        if not year and current_year:
            year = current_year.year
        
        user_role = request.user.role
        
        questions_query = ESGQuestion.objects.filter(year__year=year, is_active=True)
        responses_query = ESGQuestionResponse.objects.all()

        # Filter responses based on user role and the questionnaire_type
        if user_role == 'stakeholder':
            responses_query = responses_query.filter(user=request.user, questionnaire_type='stakeholder')
        elif user_role == 'client_admin':
            responses_query = responses_query.filter(user__client=request.user.client, questionnaire_type='client_admin')

        # Filter questions to only include those that have a response from the current user/client.
        questions_query = questions_query.filter(id__in=responses_query.values('question_id')).distinct()

        total_questions = questions_query.count()
        answered_questions = responses_query.exclude(priority=0, status_quo=0).count()
        completion_percentage = (answered_questions / total_questions * 100) if total_questions > 0 else 0
        
        # Category breakdown
        category_breakdown = {}
        for category in ESGCategory.objects.filter(is_active=True):
            cat_questions = questions_query.filter(category=category).count()
            cat_responses = responses_query.filter(question__category=category).exclude(priority=0, status_quo=0).count()
            category_breakdown[category.name] = {
                'total': cat_questions,
                'answered': cat_responses,
                'percentage': (cat_responses / cat_questions * 100) if cat_questions > 0 else 0
            }
        
        # Priority distribution
        priority_distribution = {}
        for choice in ESGQuestionResponse.PRIORITY_CHOICES:
            count = responses_query.filter(priority=choice[0]).count()
            priority_distribution[choice[1]] = count
        
        # Status quo distribution
        status_quo_distribution = {}
        for choice in ESGQuestionResponse.STATUS_QUO_CHOICES:
            count = responses_query.filter(status_quo=choice[0]).count()
            status_quo_distribution[choice[1]] = count
        
        summary_data = {
            'total_questions': total_questions,
            'answered_questions': answered_questions,
            'completion_percentage': round(completion_percentage, 2),
            'category_breakdown': category_breakdown,
            'priority_distribution': priority_distribution,
            'status_quo_distribution': status_quo_distribution
        }
        
        serializer = ESGSummarySerializer(summary_data)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def chart_data(self, request):
        """Get data formatted for charts"""
        year = request.query_params.get('year')
        current_year = ESGYear.objects.filter(is_current=True).first()
        if not year and current_year:
            year = current_year.year
        
        user_role = request.user.role
        
        questions_query = ESGQuestion.objects.filter(year__year=year, is_active=True)
        responses_query = ESGQuestionResponse.objects.all()

        if user_role == 'stakeholder':
            responses_query = responses_query.filter(user=request.user, questionnaire_type='stakeholder')
        elif user_role == 'client_admin':
            responses_query = responses_query.filter(user__client=request.user.client, questionnaire_type='client_admin')
        
        questions_query = questions_query.filter(id__in=responses_query.values('question_id')).distinct()

        chart_data = []
        for question in questions_query:
            response = responses_query.filter(question=question).first()
            chart_data.append({
                'index_code': question.index_code,
                'measure': question.measure[:50] + '...' if len(question.measure) > 50 else question.measure,
                'priority': response.priority if response else 0,
                'status_quo': response.status_quo if response else 0,
                'category': question.category.name
            })
        
        return Response(chart_data)