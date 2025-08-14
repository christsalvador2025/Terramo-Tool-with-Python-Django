# # esg/views.py
# from rest_framework import viewsets, status, permissions
# from rest_framework.decorators import action
# from rest_framework.response import Response
# from django.shortcuts import get_object_or_404
# from django.db.models import Count, Q
# from .models import ESGYear, ESGCategory, ESGQuestion, ESGQuestionResponse
# from .serializers import (
#     ESGYearSerializer, ESGCategorySerializer, ESGQuestionSerializer,
#     ESGQuestionResponseSerializer, ESGDashboardSerializer, ESGSummarySerializer
# )


# class ESGYearViewSet(viewsets.ModelViewSet):
#     queryset = ESGYear.objects.all()
#     serializer_class = ESGYearSerializer
#     permission_classes = [permissions.IsAuthenticated]
    
#     def get_queryset(self):
#         if self.request.user.role == 'terramo_admin':
#             return ESGYear.objects.all()
#         return ESGYear.objects.filter(is_active=True)


# class ESGCategoryViewSet(viewsets.ReadOnlyModelViewSet):
#     queryset = ESGCategory.objects.filter(is_active=True)
#     serializer_class = ESGCategorySerializer
#     permission_classes = [permissions.IsAuthenticated]


# class ESGQuestionViewSet(viewsets.ReadOnlyModelViewSet):
#     serializer_class = ESGQuestionSerializer
#     permission_classes = [permissions.IsAuthenticated]
#     pagination_class = None
#     def get_queryset(self):
#         queryset = ESGQuestion.objects.filter(is_active=True)
        
#         year = self.request.query_params.get('year')
#         category = self.request.query_params.get('category')
        
#         if year:
#             queryset = queryset.filter(year__year=year)
        
#         if category:
#             queryset = queryset.filter(category__name=category)
            
#         # The questionnaire_type filter is now removed from here.
#         # Questions are filtered based on responses, not the question itself.
        
#         return queryset.order_by('category', 'order', 'index_code')


# class ESGQuestionResponseViewSet(viewsets.ModelViewSet):
#     serializer_class = ESGQuestionResponseSerializer
#     permission_classes = [permissions.IsAuthenticated]
    
#     def get_queryset(self):
#         queryset = ESGQuestionResponse.objects.all()
        
#         user_role = self.request.user.role
        
#         if user_role == 'stakeholder':
#             # Stakeholders can only see their own responses
#             queryset = queryset.filter(user=self.request.user, questionnaire_type='stakeholder')
#         elif user_role == 'client_admin':
#             # Client admins can see responses from their client
#             queryset = queryset.filter(user__client=self.request.user.client, questionnaire_type='client_admin')
#         # terramo_admin can see all responses
        
#         return queryset.order_by('-updated_at')
    
#     def perform_create(self, serializer):
#         user_role = self.request.user.role
#         questionnaire_type = None
#         if user_role == 'stakeholder':
#             questionnaire_type = 'stakeholder'
#         elif user_role == 'client_admin':
#             questionnaire_type = 'client_admin'
        
#         serializer.save(user=self.request.user, questionnaire_type=questionnaire_type)


# class ESGDashboardViewSet(viewsets.ViewSet):
#     permission_classes = [permissions.IsAuthenticated]
    
#     @action(detail=False, methods=['get'])
#     def overview(self, request):
#         """Get ESG overview data"""
#         year = request.query_params.get('year')
#         current_year = ESGYear.objects.filter(is_current=True).first()
#         if not year and current_year:
#             year = current_year.year
        
#         user_role = request.user.role
#         questionnaire_type = None
#         if user_role == 'stakeholder':
#             questionnaire_type = 'stakeholder'
#         elif user_role == 'client_admin':
#             questionnaire_type = 'client_admin'

#         questions_query = ESGQuestion.objects.filter(year__year=year, is_active=True)
        
#         if questionnaire_type:
#             # We assume a question's type is determined by the response, so we filter responses
#             # based on the user's role, and then use those responses to get the relevant questions.
#             relevant_question_ids = ESGQuestionResponse.objects.filter(
#                 user=request.user if user_role == 'stakeholder' else None,
#                 user__client=request.user.client if user_role == 'client_admin' else None,
#                 questionnaire_type=questionnaire_type
#             ).values_list('question_id', flat=True)
            
#             questions_query = questions_query.filter(id__in=relevant_question_ids).distinct()

#         data = []
#         categories = ESGCategory.objects.filter(is_active=True)
        
#         for category in categories:
#             cat_questions = questions_query.filter(category=category)
            
#             responses = ESGQuestionResponse.objects.filter(question__in=cat_questions)
#             if user_role == 'stakeholder':
#                 responses = responses.filter(user=request.user)
#             elif user_role == 'client_admin':
#                 responses = responses.filter(user__client=request.user.client)
            
#             data.append({
#                 'category': ESGCategorySerializer(category).data,
#                 'questions': ESGQuestionSerializer(cat_questions, many=True).data,
#                 'responses': ESGQuestionResponseSerializer(responses, many=True).data
#             })
        
#         return Response(data)
    
#     @action(detail=False, methods=['get'])
#     def summary(self, request):
#         """Get ESG summary statistics"""
#         year = request.query_params.get('year')
#         current_year = ESGYear.objects.filter(is_current=True).first()
#         if not year and current_year:
#             year = current_year.year
        
#         user_role = request.user.role
        
#         questions_query = ESGQuestion.objects.filter(year__year=year, is_active=True)
#         responses_query = ESGQuestionResponse.objects.all()

#         # Filter responses based on user role and the questionnaire_type
#         if user_role == 'stakeholder':
#             responses_query = responses_query.filter(user=request.user, questionnaire_type='stakeholder')
#         elif user_role == 'client_admin':
#             responses_query = responses_query.filter(user__client=request.user.client, questionnaire_type='client_admin')

#         # Filter questions to only include those that have a response from the current user/client.
#         questions_query = questions_query.filter(id__in=responses_query.values('question_id')).distinct()

#         total_questions = questions_query.count()
#         answered_questions = responses_query.exclude(priority=0, status_quo=0).count()
#         completion_percentage = (answered_questions / total_questions * 100) if total_questions > 0 else 0
        
#         # Category breakdown
#         category_breakdown = {}
#         for category in ESGCategory.objects.filter(is_active=True):
#             cat_questions = questions_query.filter(category=category).count()
#             cat_responses = responses_query.filter(question__category=category).exclude(priority=0, status_quo=0).count()
#             category_breakdown[category.name] = {
#                 'total': cat_questions,
#                 'answered': cat_responses,
#                 'percentage': (cat_responses / cat_questions * 100) if cat_questions > 0 else 0
#             }
        
#         # Priority distribution
#         priority_distribution = {}
#         for choice in ESGQuestionResponse.PRIORITY_CHOICES:
#             count = responses_query.filter(priority=choice[0]).count()
#             priority_distribution[choice[1]] = count
        
#         # Status quo distribution
#         status_quo_distribution = {}
#         for choice in ESGQuestionResponse.STATUS_QUO_CHOICES:
#             count = responses_query.filter(status_quo=choice[0]).count()
#             status_quo_distribution[choice[1]] = count
        
#         summary_data = {
#             'total_questions': total_questions,
#             'answered_questions': answered_questions,
#             'completion_percentage': round(completion_percentage, 2),
#             'category_breakdown': category_breakdown,
#             'priority_distribution': priority_distribution,
#             'status_quo_distribution': status_quo_distribution
#         }
        
#         serializer = ESGSummarySerializer(summary_data)
#         return Response(serializer.data)
    
#     @action(detail=False, methods=['get'])
#     def chart_data(self, request):
#         """Get data formatted for charts"""
#         year = request.query_params.get('year')
#         current_year = ESGYear.objects.filter(is_current=True).first()
#         if not year and current_year:
#             year = current_year.year
        
#         user_role = request.user.role
        
#         questions_query = ESGQuestion.objects.filter(year__year=year, is_active=True)
#         responses_query = ESGQuestionResponse.objects.all()

#         if user_role == 'stakeholder':
#             responses_query = responses_query.filter(user=request.user, questionnaire_type='stakeholder')
#         elif user_role == 'client_admin':
#             responses_query = responses_query.filter(user__client=request.user.client, questionnaire_type='client_admin')
        
#         questions_query = questions_query.filter(id__in=responses_query.values('question_id')).distinct()

#         chart_data = []
#         for question in questions_query:
#             response = responses_query.filter(question=question).first()
#             chart_data.append({
#                 'index_code': question.index_code,
#                 'measure': question.measure[:50] + '...' if len(question.measure) > 50 else question.measure,
#                 'priority': response.priority if response else 0,
#                 'status_quo': response.status_quo if response else 0,
#                 'category': question.category.name
#             })
        
#         return Response(chart_data)



from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.db.models import Q, Avg, Count
from django.db import transaction
from django.contrib.auth import get_user_model
from django.conf import settings
from django.utils import timezone

from .models import (
    ESGYear, ESGCategory, ESGQuestion, ESGQuestionResponse,
    ESGSurvey, ESGSurveyQuestion, StakeholderResponse,
    ClientResponse, ESGAnalytics
)
from .serializers import (
    ESGYearSerializer, ESGCategorySerializer, ESGQuestionSerializer,
    ESGQuestionResponseSerializer, ESGSurveySerializer,
    ESGSurveyQuestionSerializer, StakeholderResponseSerializer,
    ClientResponseSerializer, ESGAnalyticsSerializer,
    ESGDashboardSerializer, ESGChartDataSerializer,
    StakeholderListSerializer, ClientListSerializer,
    BulkESGResponseUpdateSerializer
)
from core_apps.authentication.models import Stakeholder
from core_apps.clients.models import Client

# User = get_user_model()
User = settings.AUTH_USER_MODEL


class ESGYearViewSet(viewsets.ModelViewSet):
    queryset = ESGYear.objects.all()
    serializer_class = ESGYearSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=['get'])
    def current(self, request):
        """Get current active ESG year"""
        current_year = ESGYear.get_current_year()
        if current_year:
            serializer = self.get_serializer(current_year)
            return Response(serializer.data)
        return Response({'detail': 'No current year set'}, status=status.HTTP_404_NOT_FOUND)


class ESGCategoryViewSet(viewsets.ModelViewSet):
    queryset = ESGCategory.objects.filter(is_active=True)
    serializer_class = ESGCategorySerializer
    permission_classes = [permissions.IsAuthenticated]


class ESGQuestionViewSet(viewsets.ModelViewSet):
    serializer_class = ESGQuestionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = ESGQuestion.objects.filter(is_active=True)
        year = self.request.query_params.get('year')
        category = self.request.query_params.get('category')
        
        if year:
            queryset = queryset.filter(year__year=year)
        if category:
            queryset = queryset.filter(category__name=category)
            
        return queryset.select_related('category', 'year').order_by('category', 'order', 'index_code')


class ESGDashboardViewSet(viewsets.ViewSet):
    """Main dashboard viewset handling different user roles"""
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=['get'])
    def client_admin_dashboard(self, request):
        """Dashboard for client admin users"""
        user = request.user
        
        # Get user's client
        try:
            client = user.client
        except AttributeError:
            return Response({'error': 'User is not associated with a client'}, 
                          status=status.HTTP_403_FORBIDDEN)

        # Get current year
        current_year = ESGYear.get_current_year()
        if not current_year:
            return Response({'error': 'No current ESG year set'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        # Get or create survey for client
        survey, created = ESGSurvey.objects.get_or_create(
            client=client,
            year=current_year.year,
            defaults={
                'title': f'ESG-Check - {current_year.year}',
                'created_by': user,
                'status': 'active'
            }
        )

        # Get questions and responses
        categories = ESGCategory.objects.filter(is_active=True).order_by('name')
        questions = ESGQuestion.objects.filter(
            year=current_year,
            is_active=True
        ).select_related('category').order_by('category', 'order', 'index_code')

        # Get user's responses
        user_responses = {}
        responses = ESGQuestionResponse.objects.filter(
            user=user,
            question__year=current_year,
            questionnaire_type='client_admin'
        ).select_related('question')

        for response in responses:
            user_responses[response.question.id] = {
                'id': response.id,
                'priority': response.priority,
                'status_quo': response.status_quo,
                'comment': response.comment,
                'priority_display': response.get_priority_display(),
                'status_quo_display': response.get_status_quo_display(),
                'is_answered': response.is_answered,
                'completion_score': response.completion_score
            }

        # Create responses for questions without responses
        questions_without_responses = questions.exclude(
            id__in=user_responses.keys()
        )
        
        new_responses = []
        for question in questions_without_responses:
            new_responses.append(
                ESGQuestionResponse(
                    question=question,
                    user=user,
                    questionnaire_type='client_admin'
                )
            )
        
        if new_responses:
            ESGQuestionResponse.objects.bulk_create(new_responses)
            # Refresh user_responses
            for question in questions_without_responses:
                user_responses[question.id] = {
                    'id': None,
                    'priority': 0,
                    'status_quo': 0,
                    'comment': '',
                    'priority_display': 'Not Started',
                    'status_quo_display': 'Not Started',
                    'is_answered': False,
                    'completion_score': 0.0
                }

        # Group questions by category
        questions_by_category = {}
        for category in categories:
            category_questions = questions.filter(category=category)
            questions_by_category[category.name] = {
                'category_info': ESGCategorySerializer(category).data,
                'questions': []
            }
            
            for question in category_questions:
                question_data = ESGQuestionSerializer(question).data
                question_data['user_response'] = user_responses.get(question.id, {})
                questions_by_category[category.name]['questions'].append(question_data)

        # Calculate completion stats
        total_questions = questions.count()
        answered_questions = sum(1 for resp in user_responses.values() if resp['is_answered'])
        completion_rate = (answered_questions / total_questions * 100) if total_questions > 0 else 0

        return Response({
            'survey': ESGSurveySerializer(survey).data,
            'categories': ESGCategorySerializer(categories, many=True).data,
            'questions_by_category': questions_by_category,
            'completion_stats': {
                'total_questions': total_questions,
                'answered_questions': answered_questions,
                'completion_rate': round(completion_rate, 2)
            },
            'current_year': current_year.year
        })

    @action(detail=False, methods=['get'])
    def stakeholder_dashboard(self, request):
        """Dashboard for stakeholder users"""
        user = request.user
        
        # Get stakeholder
        try:
            stakeholder = Stakeholder.objects.get(user=user)
        except Stakeholder.DoesNotExist:
            return Response({'error': 'User is not a stakeholder'}, 
                          status=status.HTTP_403_FORBIDDEN)

        # Get client
        client = stakeholder.client
        current_year = ESGYear.get_current_year()
        if not current_year:
            return Response({'error': 'No current ESG year set'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        # Get survey
        try:
            survey = ESGSurvey.objects.get(client=client, year=current_year.year)
        except ESGSurvey.DoesNotExist:
            return Response({'error': 'No survey found for this client'}, 
                          status=status.HTTP_404_NOT_FOUND)

        # Get questions and responses
        questions = ESGQuestion.objects.filter(
            year=current_year,
            is_active=True
        ).select_related('category').order_by('category', 'order', 'index_code')

        # Get stakeholder's responses
        user_responses = {}
        responses = ESGQuestionResponse.objects.filter(
            user=user,
            question__year=current_year,
            questionnaire_type='stakeholder'
        ).select_related('question')

        for response in responses:
            user_responses[response.question.id] = {
                'id': response.id,
                'priority': response.priority,
                'status_quo': response.status_quo,
                'comment': response.comment,
                'priority_display': response.get_priority_display(),
                'status_quo_display': response.get_status_quo_display(),
                'is_answered': response.is_answered,
                'completion_score': response.completion_score
            }

        # Create responses for questions without responses
        questions_without_responses = questions.exclude(
            id__in=user_responses.keys()
        )
        
        new_responses = []
        for question in questions_without_responses:
            new_responses.append(
                ESGQuestionResponse(
                    question=question,
                    user=user,
                    questionnaire_type='stakeholder'
                )
            )
        
        if new_responses:
            ESGQuestionResponse.objects.bulk_create(new_responses)

        # Group questions by category
        categories = ESGCategory.objects.filter(is_active=True).order_by('name')
        questions_by_category = {}
        for category in categories:
            category_questions = questions.filter(category=category)
            questions_by_category[category.name] = {
                'category_info': ESGCategorySerializer(category).data,
                'questions': []
            }
            
            for question in category_questions:
                question_data = ESGQuestionSerializer(question).data
                question_data['user_response'] = user_responses.get(question.id, {
                    'priority': 0,
                    'status_quo': 0,
                    'comment': '',
                    'priority_display': 'Not Started',
                    'status_quo_display': 'Not Started',
                    'is_answered': False
                })
                questions_by_category[category.name]['questions'].append(question_data)

        return Response({
            'survey': ESGSurveySerializer(survey).data,
            'categories': ESGCategorySerializer(categories, many=True).data,
            'questions_by_category': questions_by_category,
            'stakeholder': StakeholderListSerializer(stakeholder).data,
            'current_year': current_year.year
        })

    @action(detail=False, methods=['get'])
    def admin_dashboard(self, request):
        """Dashboard for Terrano admin users"""
        if not request.user.is_staff:
            return Response({'error': 'Admin access required'}, 
                          status=status.HTTP_403_FORBIDDEN)

        current_year = ESGYear.get_current_year()
        if not current_year:
            return Response({'error': 'No current ESG year set'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        # Get all clients and their surveys
        clients = Client.objects.filter(is_active=True)
        client_data = []

        for client in clients:
            try:
                survey = ESGSurvey.objects.get(client=client, year=current_year.year)
                # Calculate completion stats for this client
                total_questions = ESGQuestion.objects.filter(
                    year=current_year, is_active=True
                ).count()
                
                completed_responses = ESGQuestionResponse.objects.filter(
                    question__year=current_year,
                    user__client=client,
                    status='submitted'
                ).count()
                
                completion_rate = (completed_responses / total_questions * 100) if total_questions > 0 else 0
                
                client_data.append({
                    'client': ClientListSerializer(client).data,
                    'survey': ESGSurveySerializer(survey).data,
                    'completion_rate': round(completion_rate, 2),
                    'total_questions': total_questions,
                    'completed_responses': completed_responses
                })
            except ESGSurvey.DoesNotExist:
                client_data.append({
                    'client': ClientListSerializer(client).data,
                    'survey': None,
                    'completion_rate': 0,
                    'total_questions': 0,
                    'completed_responses': 0
                })

        return Response({
            'clients': client_data,
            'current_year': current_year.year,
            'total_clients': clients.count()
        })

    @action(detail=False, methods=['get'], url_path='client/(?P<client_id>[^/.]+)')
    def client_detail(self, request, client_id=None):
        """Detailed view for a specific client (admin only)"""
        if not request.user.is_staff:
            return Response({'error': 'Admin access required'}, 
                          status=status.HTTP_403_FORBIDDEN)

        client = get_object_or_404(Client, id=client_id, is_active=True)
        current_year = ESGYear.get_current_year()

        try:
            survey = ESGSurvey.objects.get(client=client, year=current_year.year)
        except ESGSurvey.DoesNotExist:
            return Response({'error': 'No survey found for this client'}, 
                          status=status.HTTP_404_NOT_FOUND)

        # Get questions grouped by category
        categories = ESGCategory.objects.filter(is_active=True).order_by('name')
        questions = ESGQuestion.objects.filter(
            year=current_year,
            is_active=True
        ).select_related('category').order_by('category', 'order', 'index_code')

        # Get all responses for this client
        client_responses = ESGQuestionResponse.objects.filter(
            question__year=current_year,
            user__client=client
        ).select_related('question', 'user')

        # Group responses by question
        responses_by_question = {}
        for response in client_responses:
            if response.question.id not in responses_by_question:
                responses_by_question[response.question.id] = []
            responses_by_question[response.question.id].append({
                'user_email': response.user.email,
                'questionnaire_type': response.questionnaire_type,
                'priority': response.priority,
                'status_quo': response.status_quo,
                'comment': response.comment,
                'priority_display': response.get_priority_display(),
                'status_quo_display': response.get_status_quo_display(),
                'is_answered': response.is_answered
            })

        # Build category structure
        questions_by_category = {}
        for category in categories:
            category_questions = questions.filter(category=category)
            questions_by_category[category.name] = {
                'category_info': ESGCategorySerializer(category).data,
                'questions': []
            }
            
            for question in category_questions:
                question_data = ESGQuestionSerializer(question).data
                question_data['responses'] = responses_by_question.get(question.id, [])
                questions_by_category[category.name]['questions'].append(question_data)

        return Response({
            'client': ClientListSerializer(client).data,
            'survey': ESGSurveySerializer(survey).data,
            'categories': ESGCategorySerializer(categories, many=True).data,
            'questions_by_category': questions_by_category,
            'current_year': current_year.year
        })

    @action(detail=False, methods=['post'])
    def bulk_update_responses(self, request):
        """Bulk update ESG responses"""
        serializer = BulkESGResponseUpdateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        responses_data = serializer.validated_data['responses']
        
        with transaction.atomic():
            for response_data in responses_data:
                question_id = response_data['question_id']
                priority = response_data.get('priority', 0)
                status_quo = response_data.get('status_quo', 0)
                comment = response_data.get('comment', '')
                
                # Determine questionnaire type based on user role
                questionnaire_type = 'client_admin'
                try:
                    stakeholder = Stakeholder.objects.get(user=request.user)
                    questionnaire_type = 'stakeholder'
                except Stakeholder.DoesNotExist:
                    pass

                # Update or create response
                response, created = ESGQuestionResponse.objects.update_or_create(
                    question_id=question_id,
                    user=request.user,
                    questionnaire_type=questionnaire_type,
                    defaults={
                        'priority': priority,
                        'status_quo': status_quo,
                        'comment': comment,
                        'status': 'draft' if priority == 0 and status_quo == 0 else 'submitted'
                    }
                )

        return Response({'message': 'Responses updated successfully'})

    @action(detail=False, methods=['get'])
    def chart_data(self, request):
        """Get chart data for visualization"""
        user = request.user
        current_year = ESGYear.get_current_year()
        
        # Determine user type and get appropriate responses
        try:
            stakeholder = Stakeholder.objects.get(user=user)
            questionnaire_type = 'stakeholder'
        except Stakeholder.DoesNotExist:
            questionnaire_type = 'client_admin'

        # Get responses
        responses = ESGQuestionResponse.objects.filter(
            user=user,
            question__year=current_year,
            questionnaire_type=questionnaire_type
        ).select_related('question', 'question__category')

        # Group by category
        categories = ESGCategory.objects.filter(is_active=True).order_by('name')
        chart_data = []
        
        for category in categories:
            category_responses = responses.filter(question__category=category)
            questions_data = []
            
            for response in category_responses:
                questions_data.append({
                    'index_code': response.question.index_code,
                    'measure': response.question.measure[:50] + '...' if len(response.question.measure) > 50 else response.question.measure,
                    'priority': response.priority,
                    'status_quo': response.status_quo,
                    'priority_display': response.get_priority_display(),
                    'status_quo_display': response.get_status_quo_display(),
                    'comment': response.comment
                })
            
            chart_data.append({
                'category': category.display_name,
                'questions': questions_data
            })

        return Response(chart_data)


class ESGQuestionResponseViewSet(viewsets.ModelViewSet):
    serializer_class = ESGQuestionResponseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        queryset = ESGQuestionResponse.objects.filter(user=user)
        
        questionnaire_type = self.request.query_params.get('type')
        if questionnaire_type:
            queryset = queryset.filter(questionnaire_type=questionnaire_type)
            
        return queryset.select_related('question', 'question__category', 'user')

    def perform_create(self, serializer):
        # Determine questionnaire type
        questionnaire_type = 'client_admin'
        try:
            Stakeholder.objects.get(user=self.request.user)
            questionnaire_type = 'stakeholder'
        except Stakeholder.DoesNotExist:
            pass
            
        serializer.save(
            user=self.request.user,
            questionnaire_type=questionnaire_type
        )