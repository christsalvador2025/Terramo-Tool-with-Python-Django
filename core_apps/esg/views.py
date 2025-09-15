

"""
-------------------------------------
"""
"""
###########################################################################################
TRACKING:
TO SEARCH THE CODE JUST COPY THE SPECIFIC LIST HERE AND CTRL + F 
1. class ESGYearViewSet
2. class ESGCategoryViewSet 
3. START: STAKEHOLDER ANAYLSIS 
###########################################################################################
"""
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.db.models import Q, Avg, Count, F, Exists, OuterRef
from django.db import transaction
from django.contrib.auth import get_user_model
from django.conf import settings
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.db import transaction, IntegrityError
import logging

from django.core.exceptions import ValidationError
from django.utils.crypto import get_random_string

logger = logging.getLogger(__name__)
from django.utils.crypto import get_random_string

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
    BulkESGResponseUpdateSerializer, ClientFullDetailsSerializer
)
from core_apps.authentication.models import Stakeholder, StakeholderGroup
from core_apps.clients.models import Client, ClientProduct
from core_apps.user_auth.models import User
# User = settings.AUTH_USER_MODEL
from core_apps.services.email_service import EmailService
from uuid import UUID
# ------ 1. class ESGYearViewSet ----------
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

# ------ 2. class ESGCategoryViewSet ----------
class ESGCategoryViewSet(viewsets.ModelViewSet):
    queryset = ESGCategory.objects.filter(is_active=True)
    serializer_class = ESGCategorySerializer
    permission_classes = [permissions.IsAuthenticated]


class ESGQuestionViewSet(viewsets.ModelViewSet):
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
            
        return queryset.select_related('category', 'year').order_by('category', 'order', 'index_code')

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

class ESGDashboardViewSet(viewsets.ViewSet):
    """Main dashboard viewset handling different user roles"""
    permission_classes = [permissions.IsAuthenticated]

    def _calculate_client_averages(self, client, current_year):
        """Calculate priority and status quo averages for a client"""
        # Get all stakeholders for this client
        stakeholder_groups = StakeholderGroup.objects.filter(client=client, is_active=True)
        stakeholder_users = []
        
        # Collect all stakeholder users
        for group in stakeholder_groups:
            stakeholders = Stakeholder.objects.filter(
                group=group, 
                is_registered=True, 
                status='approved',
                user__isnull=False
            )
            stakeholder_users.extend([s.user for s in stakeholders])
        
        # Get client admin user (assuming the client has one admin)
        try:
            client_admin = User.objects.get(client=client, role='client_admin')
        except User.DoesNotExist:
            client_admin = None
        
        # Get all submitted responses for this client
        all_responses = ESGQuestionResponse.objects.filter(
            question__year=current_year,
            status='submitted'
        ).exclude(
            Q(priority__isnull=True) | Q(status_quo__isnull=True)
        )
        
        # Filter by client users (stakeholders + client admin)
        client_user_ids = [user.id for user in stakeholder_users if user]
        if client_admin:
            client_user_ids.append(client_admin.id)
        
        client_responses = all_responses.filter(user_id__in=client_user_ids)
        
        # Calculate averages by category
        categories = ESGCategory.objects.filter(is_active=True)
        category_averages = {}
        
        for category in categories:
            category_responses = client_responses.filter(question__category=category)
            
            if category_responses.exists():
                avg_data = category_responses.aggregate(
                    avg_priority=Avg('priority'),
                    avg_status_quo=Avg('status_quo'),
                    total_responses=Count('id')
                )
                category_averages[category.name] = {
                    'avg_priority': round(avg_data['avg_priority'] or 0, 2),
                    'avg_status_quo': round(avg_data['avg_status_quo'] or 0, 2),
                    'total_responses': avg_data['total_responses']
                }
            else:
                category_averages[category.name] = {
                    'avg_priority': 0,
                    'avg_status_quo': 0,
                    'total_responses': 0
                }
        
        # Calculate overall averages
        overall_avg = client_responses.aggregate(
            avg_priority=Avg('priority'),
            avg_status_quo=Avg('status_quo'),
            total_responses=Count('id')
        )
        
        return {
            'overall': {
                'avg_priority': round(overall_avg['avg_priority'] or 0, 2),
                'avg_status_quo': round(overall_avg['avg_status_quo'] or 0, 2),
                'total_responses': overall_avg['total_responses']
            },
            'by_category': category_averages,
            'stakeholder_count': len(stakeholder_users),
            'client_admin_included': client_admin is not None
        }

    @action(detail=False, methods=['get'])
    def admin_dashboard(self, request):
        """Dashboard for Terramo admin users with client analytics"""
        if not request.user.role == "terramo_admin":
            return Response({'error': 'Admin access required'}, 
                          status=status.HTTP_403_FORBIDDEN)

        current_year = ESGYear.get_current_year()
        if not current_year:
            return Response({'error': 'No current ESG year set'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        # Get all clients and their surveys
        clients = Client.objects.filter(is_active=True)
        client_data = []

        total_questions = ESGQuestion.objects.filter(
            year=current_year, is_active=True
        ).count()

        for client in clients:
            try:
                survey = ESGSurvey.objects.get(client=client, year=current_year.year)
            except ESGSurvey.DoesNotExist:
                survey = None
            
            # Calculate averages for this client
            averages = self._calculate_client_averages(client, current_year)
            # averages = self._calculate_category_averages_with_year(client, current_year)
            
            
            # Calculate completion rate based on submitted responses
            stakeholder_groups = StakeholderGroup.objects.filter(client=client, is_active=True)
            stakeholder_users = []
            
            for group in stakeholder_groups:
                stakeholders = Stakeholder.objects.filter(
                    group=group, 
                    is_registered=True, 
                    status='approved',
                    user__isnull=False
                )
                stakeholder_users.extend([s.user for s in stakeholders])
            
            # Include client admin
            try:
                client_admin = User.objects.get(client=client, role='client_admin')
                stakeholder_users.append(client_admin)
            except User.DoesNotExist:
                pass
            
            completed_responses = ESGQuestionResponse.objects.filter(
                question__year=current_year,
                user__in=stakeholder_users,
                status='submitted'
            ).exclude(
                Q(priority__isnull=True) | Q(status_quo__isnull=True) |
                Q(priority=0) | Q(status_quo=0)
            ).count()
            
            expected_responses = total_questions * len(stakeholder_users)
            completion_rate = (completed_responses / expected_responses * 100) if expected_responses > 0 else 0
            
            client_data.append({
                'client': ClientListSerializer(client).data,
                'survey': ESGSurveySerializer(survey).data if survey else None,
                'completion_rate': round(completion_rate, 2),
                'total_questions': total_questions,
                'completed_responses': completed_responses,
                'expected_responses': expected_responses,
                'averages': averages
            })

        return Response({
            'clients': client_data,
            'current_year': current_year.year,
            'total_clients': clients.count()
        })

    @action(detail=False, methods=['get'], url_path='client/(?P<client_id>[^/.]+)')
    def client_detail(self, request, client_id=None):
        """Detailed view for a specific client with averages"""
        if not request.user.role == "terramo_admin":
            return Response({'error': 'Admin access required'}, 
                          status=status.HTTP_403_FORBIDDEN)

        client = get_object_or_404(Client, id=client_id, is_active=True)
        current_year = ESGYear.get_current_year()

        try:
            survey = ESGSurvey.objects.get(client=client, year=current_year.year)
        except ESGSurvey.DoesNotExist:
            return Response({'error': 'No survey found for this client'}, 
                          status=status.HTTP_404_NOT_FOUND)

        # Get client averages
        averages = self._calculate_client_averages(client, current_year)
        
        # Get stakeholder details
        stakeholder_groups = StakeholderGroup.objects.filter(client=client, is_active=True)
        stakeholder_details = []
        
        for group in stakeholder_groups:
            stakeholders = Stakeholder.objects.filter(
                group=group, 
                is_registered=True, 
                status='approved'
            ).select_related('user')
            
            for stakeholder in stakeholders:
                if stakeholder.user:
                    # Get stakeholder's response stats
                    stakeholder_responses = ESGQuestionResponse.objects.filter(
                        user=stakeholder.user,
                        question__year=current_year,
                        status='submitted'
                    ).exclude(
                        Q(priority__isnull=True) | Q(status_quo__isnull=True) |
                        Q(priority=0) | Q(status_quo=0)
                    )
                    
                    stakeholder_avg = stakeholder_responses.aggregate(
                        avg_priority=Avg('priority'),
                        avg_status_quo=Avg('status_quo'),
                        total_responses=Count('id')
                    )
                    
                    stakeholder_details.append({
                        'stakeholder': StakeholderListSerializer(stakeholder).data,
                        'group': group.name,
                        'avg_priority': round(stakeholder_avg['avg_priority'] or 0, 2),
                        'avg_status_quo': round(stakeholder_avg['avg_status_quo'] or 0, 2),
                        'total_responses': stakeholder_avg['total_responses']
                    })

        # Get questions grouped by category with averages
        categories = ESGCategory.objects.filter(is_active=True).order_by('name')
        questions = ESGQuestion.objects.filter(
            year=current_year,
            is_active=True
        ).select_related('category').order_by('category', 'order', 'index_code')

        # Build category structure with averages
        questions_by_category = {}
        for category in categories:
            category_questions = questions.filter(category=category)
            category_avg = averages['by_category'].get(category.name, {})
            
            questions_by_category[category.name] = {
                'category_info': ESGCategorySerializer(category).data,
                'averages': category_avg,
                'questions': ESGQuestionSerializer(category_questions, many=True).data
            }

        return Response({
            'client': ClientListSerializer(client).data,
            'survey': ESGSurveySerializer(survey).data,
            'averages': averages,
            'categories': ESGCategorySerializer(categories, many=True).data,
            'questions_by_category': questions_by_category,
            'stakeholders': stakeholder_details,
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

        # Get client through stakeholder group
        client = stakeholder.group.client
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

        # Get client averages
        averages = self._calculate_client_averages(client, current_year)

        return Response({
            'survey': ESGSurveySerializer(survey).data,
            'categories': ESGCategorySerializer(categories, many=True).data,
            'questions_by_category': questions_by_category,
            'stakeholder': StakeholderListSerializer(stakeholder).data,
            'client_averages': averages,
            'current_year': current_year.year
        })

    # @action(detail=False, methods=['post'])
    # def bulk_update_responses(self, request):
    #     """Bulk update ESG responses"""
    #     serializer = BulkESGResponseUpdateSerializer(data=request.data)
    #     if not serializer.is_valid():
    #         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    #     responses_data = serializer.validated_data['responses']
        
    #     with transaction.atomic():
    #         for response_data in responses_data:
    #             question_id = response_data['question_id']
    #             priority = response_data.get('priority', 0)
    #             status_quo = response_data.get('status_quo', 0)
    #             comment = response_data.get('comment', '')
                
    #             # Determine questionnaire type based on user role
    #             questionnaire_type = 'client_admin'
    #             try:
    #                 stakeholder = Stakeholder.objects.get(user=request.user)
    #                 questionnaire_type = 'stakeholder'
    #             except Stakeholder.DoesNotExist:
    #                 pass

    #             # Update or create response
    #             response, created = ESGQuestionResponse.objects.update_or_create(
    #                 question_id=question_id,
    #                 user=request.user,
    #                 questionnaire_type=questionnaire_type,
    #                 defaults={
    #                     'priority': priority,
    #                     'status_quo': status_quo,
    #                     'comment': comment,
    #                     'status': 'draft' if priority == 0 and status_quo == 0 else 'submitted'
    #                 }
    #             )

    #     return Response({'message': 'Responses updated successfully'})
    @action(detail=False, methods=['post'])
    def bulk_update_responses(self, request):
        """Bulk update ESG responses (client_admin or stakeholder)"""
        serializer = BulkESGResponseUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        status_in = serializer.validated_data["status"]          # 'draft' | 'submitted'
        responses_data = serializer.validated_data["responses"]

        # Determine questionnaire type by user
        questionnaire_type = 'client_admin'
        try:
            Stakeholder.objects.get(user=request.user)
            questionnaire_type = 'stakeholder'
        except Stakeholder.DoesNotExist:
            pass

        updated = 0
        created = 0

        with transaction.atomic():
            for item in responses_data:
                qid = item["question_id"]
                priority = item.get("priority", None)
                status_quo = item.get("status_quo", None)
                comment = (item.get("comment") or "").strip()

                obj, was_created = ESGQuestionResponse.objects.update_or_create(
                    question_id=qid,
                    user=request.user,            # 
                    defaults={
                        "priority": priority,
                        "status_quo": status_quo,
                        "comment": comment,
                        "questionnaire_type": questionnaire_type,
                        "status": status_in,
                        # responded_at handled by model.save() when status == 'submitted'
                    },
                )
                created += 1 if was_created else 0
                updated += 0 if was_created else 1

        return Response(
            {
                "message": "Responses updated successfully",
                "updated": updated,
                "created": created,
                "status": status_in,
            },
            status=status.HTTP_200_OK,
        )
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


    def _calculate_question_level_averages(self, client, current_year, category_filter=None):
        """
        Calculate priority and status quo averages per question for a client
        Including both stakeholders and client admin responses
        """
        from django.db.models import Avg, Count, Q
        from django.utils import timezone
        from core_apps.authentication.models import Stakeholder, StakeholderGroup
        from core_apps.user_auth.models import User
        
        # Get all stakeholders for this client
        stakeholder_groups = StakeholderGroup.objects.filter(client=client, is_active=True)
        stakeholder_users = []
        
        # Collect all stakeholder users
        for group in stakeholder_groups:
            stakeholders = Stakeholder.objects.filter(
                group=group, 
                is_registered=True, 
                status='approved',
                user__isnull=False
            )
            stakeholder_users.extend([s.user for s in stakeholders])
        
        # Get client admin user
        try:
            client_admin = User.objects.get(client=client, role='client_admin')
            stakeholder_users.append(client_admin)
        except User.DoesNotExist:
            pass
        
        if not stakeholder_users:
            return {}
        
        # Get all questions for the current year
        questions_query = ESGQuestion.objects.filter(
            year=current_year,
            is_active=True
        ).select_related('category')
        
        # Filter by category if specified
        if category_filter:
            questions_query = questions_query.filter(category__name=category_filter)
        
        # Get all submitted responses for this client's users
        client_user_ids = [user.id for user in stakeholder_users if user]
        all_responses = ESGQuestionResponse.objects.filter(
            question__year=current_year,
            user_id__in=client_user_ids,
            status='submitted'
        ).exclude(
            Q(priority__isnull=True) | Q(status_quo__isnull=True)
        ).select_related('question', 'question__category')
        
        # Calculate averages per question
        question_averages = {}
        categories_data = {}
        
        for question in questions_query:
            question_responses = all_responses.filter(question=question)
            
            if question_responses.exists():
                avg_data = question_responses.aggregate(
                    avg_priority=Avg('priority'),
                    avg_status_quo=Avg('status_quo'),
                    response_count=Count('id')
                )
                
                question_avg = {
                    'question_id': str(question.id),
                    'index_code': question.index_code,
                    'measure': question.measure,
                    'avg_priority': round(avg_data['avg_priority'] or 0, 2),
                    'avg_status_quo': round(avg_data['avg_status_quo'] or 0, 2),
                    'response_count': avg_data['response_count'],
                    'total_possible_responses': len(stakeholder_users),
                    'response_rate': round((avg_data['response_count'] / len(stakeholder_users)) * 100, 2) if len(stakeholder_users) > 0 else 0
                }
            else:
                question_avg = {
                    'question_id': str(question.id),
                    'index_code': question.index_code,
                    'measure': question.measure,
                    'avg_priority': 0.0,
                    'avg_status_quo': 0.0,
                    'response_count': 0,
                    'total_possible_responses': len(stakeholder_users),
                    'response_rate': 0.0
                }
            
            question_averages[str(question.id)] = question_avg
            
            # Group by category
            category_name = question.category.name
            if category_name not in categories_data:
                categories_data[category_name] = {
                    'category_info': {
                        'id': str(question.category.id),
                        'name': question.category.name,
                        'display_name': question.category.display_name
                    },
                    'questions': []
                }
            
            categories_data[category_name]['questions'].append(question_avg)
        
        return {
            'question_averages': question_averages,
            'by_category': categories_data,
            'total_users': len(stakeholder_users),
            'calculation_timestamp': timezone.now().isoformat()
        }

    # Add this new action to your ESGDashboardViewSet class:

    @action(detail=False, methods=['get'])
    def question_averages(self, request):
        """Get question-level averages for current user's client"""
        user = request.user
        category = request.query_params.get('category')  # Optional category filter
        year = request.query_params.get('year')
        # Determine user's client
        client = None
        if user.role == 'client_admin':
            client = user.client
        elif user.role == 'stakeholder':
            try:
                stakeholder = Stakeholder.objects.get(user=user)
                client = stakeholder.group.client
            except Stakeholder.DoesNotExist:
                return Response({'error': 'User is not a stakeholder'}, 
                            status=status.HTTP_403_FORBIDDEN)
        elif user.role == 'terramo_admin':
            # Admin can specify client_id in query params
            client_id = request.query_params.get('client_id')
            if client_id:
                client = get_object_or_404(Client, id=client_id, is_active=True)
            else:
                return Response({'error': 'client_id parameter required for admin users'}, 
                            status=status.HTTP_400_BAD_REQUEST)
        
        if not client:
            return Response({'error': 'No client associated with user'}, 
                        status=status.HTTP_403_FORBIDDEN)
        
        current_year = ESGYear.get_current_year()
        if not current_year:
            return Response({'error': 'No current ESG year set'}, 
                        status=status.HTTP_400_BAD_REQUEST)
        
        # Calculate question averages
        averages_data = self._calculate_question_level_averages(
            client, current_year, category
        )
        
        return Response({
            'client': {
                'id': str(client.id),
                'name': client.company_name
            },
            'year': current_year.year,
            'category_filter': category,
            'averages': averages_data
        })

    @action(detail=False, methods=['get'])
    def enhanced_chart_data(self, request):
        """Get enhanced chart data with averages for visualization"""
        user = request.user
        
        # Determine user's client
        client = None
        if user.role == 'client_admin':
            client = user.client
        elif user.role == 'stakeholder':
            try:
                stakeholder = Stakeholder.objects.get(user=user)
                client = stakeholder.group.client
            except Stakeholder.DoesNotExist:
                return Response({'error': 'User is not a stakeholder'}, 
                            status=status.HTTP_403_FORBIDDEN)
        
        if not client:
            return Response({'error': 'No client associated with user'}, 
                        status=status.HTTP_403_FORBIDDEN)
        
        current_year = ESGYear.get_current_year()
        if not current_year:
            return Response({'error': 'No current ESG year set'}, 
                        status=status.HTTP_400_BAD_REQUEST)
        
        # Get question averages
        averages_data = self._calculate_question_level_averages(client, current_year)
        
        # Format for chart visualization (similar to your image)
        chart_data = []
        for category_name, category_data in averages_data['by_category'].items():
            category_chart = {
                'category': category_name,
                'questions': []
            }
            
            for question_avg in category_data['questions']:
                category_chart['questions'].append({
                    'index_code': question_avg['index_code'],
                    'measure': question_avg['measure'][:50] + '...' if len(question_avg['measure']) > 50 else question_avg['measure'],
                    'avg_priority': question_avg['avg_priority'],
                    'avg_status_quo': question_avg['avg_status_quo'],
                    'response_count': question_avg['response_count'],
                    'response_rate': question_avg['response_rate'],
                    # For chart visualization - you can use these for bar lengths
                    'priority_bar_width': (question_avg['avg_priority'] / 3) * 100 if question_avg['avg_priority'] > 0 else 0,  # Assuming 3 is max priority
                    'status_quo_bar_width': (question_avg['avg_status_quo'] / 3) * 100 if question_avg['avg_status_quo'] > 0 else 0  # Assuming 3 is max status quo
                })
            
            chart_data.append(category_chart)
        
        return Response({
            'client': {
                'id': str(client.id),
                'name': client.name
            },
            'year': current_year.year,
            'chart_data': chart_data,
            'total_users': averages_data['total_users']
        })


    # --------- Enhance client admin Start ----------------
    def _calculate_category_averages(self, client, current_year):
        """Calculate average priority and status quo for each question under each category."""
        from django.db.models import Avg, Count, Q
        
        # Get client users (stakeholder and client admin)
        stakeholder_groups = StakeholderGroup.objects.filter(client=client, is_active=True, disable_the_invitation=False)

        stakeholder_users = []
        
        for group in stakeholder_groups:
            stakeholders = Stakeholder.objects.filter(
                group=group, 
                is_registered=True, 
                status='approved',
                user__isnull=False
            )
            stakeholder_users.extend([s.user for s in stakeholders])

        try:
            client_admin = User.objects.get(client=client, role='client_admin')
            stakeholder_users.append(client_admin)
        except User.DoesNotExist:
            pass
        
        if not stakeholder_users:
            return {}

        # Get the questions for the current year
        questions = ESGQuestion.objects.filter(
            year=current_year,
            is_active=True
        ).select_related('category')
        
        # Filter responses that are submitted and belong to the client users
        client_user_ids = [user.id for user in stakeholder_users]
        responses = ESGQuestionResponse.objects.filter(
            question__year=current_year,
            user_id__in=client_user_ids,
            status='submitted'
        ).exclude(
            Q(priority__isnull=True) | Q(status_quo__isnull=True)
        )

        # Prepare dictionary to store average data
        category_averages = {}

        for question in questions:
            # Get all responses for this question
            question_responses = responses.filter(question=question)

            if question_responses.exists():
                avg_data = question_responses.aggregate(
                    avg_priority=Avg('priority'),
                    avg_status_quo=Avg('status_quo'),
                    response_count=Count('id')
                )

                question_avg = {
                    'question_id': str(question.id),
                    'index_code': question.index_code,
                    'measure': question.measure,
                    'avg_priority': round(avg_data['avg_priority'] or 0, 2),
                    'avg_status_quo': round(avg_data['avg_status_quo'] or 0, 2),
                    'response_count': avg_data['response_count'],
                }
            else:
                question_avg = {
                    'question_id': str(question.id),
                    'index_code': question.index_code,
                    'measure': question.measure,
                    'avg_priority': 0.0,
                    'avg_status_quo': 0.0,
                    'response_count': 0
                }

            # Group by category
            category_name = question.category.name
            if category_name not in category_averages:
                category_averages[category_name] = {
                    'category_info': {
                        'id': str(question.category.id),
                        'name': question.category.name,
                        'display_name': question.category.display_name
                    },
                    'questions': []
                }
            
            category_averages[category_name]['questions'].append(question_avg)

        return category_averages

    
    # def _get_all_client_responses(self, client,current_year):
    #     pass
    # @action(detail=False, methods=['get'])
    # def client_admin_dashboard(self, request):
    #     """Dashboard for client admin users"""
    @action(detail=False, methods=['get'])
    def client_admin_dashboard(self, request):
        # client_admin_dashboard_esg
        """Dashboard for client admin users"""
        # get year in the request if attached
        year_param = request.query_params.get("year")
         
        user = request.user
        
        
        # Get user's client
        try:
            client = user.client
        except AttributeError:
            return Response({'error': 'User is not associated with a client'}, 
                            status=status.HTTP_403_FORBIDDEN)
        
        # Get current year
        # current_year = ESGYear.get_current_year()

        # if not current_year:
        #     return Response({'error': 'No current ESG year set'}, 
        #                     status=status.HTTP_400_BAD_REQUEST)
        # Determine which year to use
        if year_param:
            try:
                # Convert to integer and validate
                year_value = int(year_param)
                
                # Try to get the specific ESG year
                try:
                    current_year = ESGYear.objects.get(year=year_value, is_active=True)
                except ESGYear.DoesNotExist:
                    return Response({
                        'error': f'ESG year {year_value} not found or not active'
                    }, status=status.HTTP_404_NOT_FOUND)
                    
            except (ValueError, TypeError):
                return Response({
                    'error': 'Invalid year parameter. Year must be a valid integer.'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Get current year if no year parameter provided
            # Use the manager's get_current method or the class method
            current_year = ESGYear.objects.get_current()  # or ESGYear.get_current_year()
            if not current_year:
                return Response({'error': 'No current ESG year set'}, 
                                status=status.HTTP_400_BAD_REQUEST)
        # Get categories and calculate averages
        category_averages = self._calculate_category_averages(client, current_year)

        # Get user's ESG question responses
        user_responses = {}
        responses = ESGQuestionResponse.objects.filter(
            user=user,
            question__year=current_year,
            questionnaire_type='client_admin'
        ).select_related('question', 'question__category')

        # Create a dictionary for quick lookup
        for response in responses:
            user_responses[response.question.id] = {
                'id': response.id,
                'priority': response.priority,
                'status_quo': response.status_quo,
                'comment': response.comment,
                'priority_display': response.get_priority_display(),
                'status_quo_display': response.get_status_quo_display(),
                'is_answered': response.is_answered,
                'completion_score': response.completion_score,
                'status': response.status
            }

        # Get all questions for the current year to ensure we have responses for all
        questions = ESGQuestion.objects.filter(
            year=current_year,
            is_active=True
        ).select_related('category').order_by('category', 'order', 'index_code')

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
        
        # Use bulk_create with ignore_conflicts to avoid IntegrityError
        if new_responses:
            ESGQuestionResponse.objects.bulk_create(new_responses, ignore_conflicts=True)
        
        # Re-fetch all responses after bulk_create to ensure completeness
        all_user_responses = ESGQuestionResponse.objects.filter(
            user=user,
            question__year=current_year,
            questionnaire_type='client_admin'
        ).select_related('question', 'question__category')

        # Update user_responses dictionary with all responses
        user_responses = {}
        for response in all_user_responses:
            user_responses[response.question.id] = {
                'id': response.id,
                'priority': response.priority,
                'status_quo': response.status_quo,
                'comment': response.comment,
                'priority_display': response.get_priority_display(),
                'status_quo_display': response.get_status_quo_display(),
                'is_answered': response.is_answered,
                'completion_score': response.completion_score,
                'status': response.status
            }

        # Build question_response structure grouped by category
        question_response = {}
        categories = ESGCategory.objects.filter(is_active=True).order_by('name')
        
        for category in categories:
            category_questions = questions.filter(category=category)
            question_response[category.name] = {
                'category_info': {
                    'id': str(category.id),
                    'name': category.name,
                    'display_name': category.display_name
                },
                'questions': []
            }
            
            for question in category_questions:
                user_resp = user_responses.get(question.id, {})
                
                question_data = {
                    'question_id': str(question.id),
                    'index_code': question.index_code,
                    'measure': question.measure,
                    'question_description': question.desription or '',  # Note: there's a typo in the model field name
                    'priority': user_resp.get('priority', 0),
                    'status_quo': user_resp.get('status_quo', 0),
                    'comment': user_resp.get('comment', ''),
                    'priority_display': user_resp.get('priority_display', 'Not Started'),
                    'status_quo_display': user_resp.get('status_quo_display', 'Not Started'),
                    'is_answered': user_resp.get('is_answered', False),
                    'completion_score': user_resp.get('completion_score', 0.0),
                    'status': user_resp.get('status', 'draft'),
                    'response_id': user_resp.get('id', None)
                }
                
                question_response[category.name]['questions'].append(question_data)
        client_data_serialized = ClientFullDetailsSerializer(client).data
        return Response({
            # 'client': {
            #     'id': str(client.id),
            #     'name': client.company_name
            # },
            'client': client_data_serialized,
            'year': current_year.year,
            'categories': category_averages,
            'question_response': question_response
        })

    @action(detail=False, methods=['get'])
    def client_admin_dashboard_with_year(self, request):
        """Dashboard for client admin users"""
        
        client_id = request.query_params.get("client_id")
        
        
        # Get year from query parameters, default to current year if not provided
        year_param = request.query_params.get("year")
        
        # print(f"client id is pass ={client_id}")
        user = request.user
        
        # Get user's client
        try:
            client = None
            if user.role == "terramo_admin":
                if not client_id:
                    return Response(
                        {"error": "Client id is required."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                # validate UUID format
                try:
                    UUID(str(client_id))  # will raise ValueError if not a valid UUID
                except ValueError:
                    return Response(
                        {"error": "Invalid client id format."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                client = Client.objects.filter(id=client_id).first()
                if not client:
                    return Response(
                        {"error": "Client not found."},
                        status=status.HTTP_404_NOT_FOUND
                    )
                
            else:
                
                client = user.client
        except AttributeError:
            return Response({'error': 'User is not associated with a client'}, 
                            status=status.HTTP_403_FORBIDDEN)
        client_data_serialized = ClientFullDetailsSerializer(client).data
        # Determine which year to use
        if year_param:
            try:
                # Convert to integer and validate
                year_value = int(year_param)
                
                # Try to get the specific ESG year
                try:
                    target_year = ESGYear.objects.get(year=year_value, is_active=True)
                except ESGYear.DoesNotExist:
                    return Response({
                        'error': f'ESG year {year_value} not found or not active'
                    }, status=status.HTTP_404_NOT_FOUND)
                    
            except (ValueError, TypeError):
                return Response({
                    'error': 'Invalid year parameter. Year must be a valid integer.'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Get current year if no year parameter provided
            # Use the manager's get_current method or the class method
            target_year = ESGYear.objects.get_current()  # or ESGYear.get_current_year()
            if not target_year:
                return Response({'error': 'No current ESG year set'}, 
                                status=status.HTTP_400_BAD_REQUEST)

        # Get categories and calculate averages for the target year
        category_averages = self.calculate_category_averages_with_year(client, target_year)
        category_averages_with_comments = self._calculate_category_averages_with_year_and_comments(client, target_year)

        # Get user's ESG question responses for the target year
        user_responses = {}
        responses = ESGQuestionResponse.objects.filter(
            user=user,
            question__year=target_year,  # Use target_year instead of current_year
            questionnaire_type='client_admin'
        ).select_related('question', 'question__category')

        # Create a dictionary for quick lookup
        for response in responses:
            user_responses[response.question.id] = {
                'id': response.id,
                'priority': response.priority,
                'status_quo': response.status_quo,
                'comment': response.comment,
                'priority_display': response.get_priority_display(),
                'status_quo_display': response.get_status_quo_display(),
                'is_answered': response.is_answered,
                'completion_score': response.completion_score,
                'status': response.status
            }

        # Get all questions for the target year to ensure we have responses for all
        questions = ESGQuestion.objects.filter(
            year=target_year,  # Use target_year instead of current_year
            is_active=True
        ).select_related('category').order_by('category', 'order', 'index_code')

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
        
        # Use bulk_create with ignore_conflicts to avoid IntegrityError
        if new_responses:
            ESGQuestionResponse.objects.bulk_create(new_responses, ignore_conflicts=True)
        
        # Re-fetch all responses after bulk_create to ensure completeness
        all_user_responses = ESGQuestionResponse.objects.filter(
            user=user,
            question__year=target_year,  # Use target_year instead of current_year
            questionnaire_type='client_admin'
        ).select_related('question', 'question__category')

        # Update user_responses dictionary with all responses
        user_responses = {}
        for response in all_user_responses:
            user_responses[response.question.id] = {
                'id': response.id,
                'priority': response.priority,
                'status_quo': response.status_quo,
                'comment': response.comment,
                'priority_display': response.get_priority_display(),
                'status_quo_display': response.get_status_quo_display(),
                'is_answered': response.is_answered,
                'completion_score': response.completion_score,
                'status': response.status
            }

        # Build question_response structure grouped by category
        question_response = {}
        categories = ESGCategory.objects.filter(is_active=True).order_by('name')
        
        for category in categories:
            category_questions = questions.filter(category=category)
            question_response[category.name] = {
                'category_info': {
                    'id': str(category.id),
                    'name': category.name,
                    'display_name': category.display_name
                },
                'questions': []
            }
            
            for question in category_questions:
                user_resp = user_responses.get(question.id, {})
                
                question_data = {
                    'question_id': str(question.id),
                    'index_code': question.index_code,
                    'measure': question.measure,
                    'question_description': question.desription or '',  # Note: there's a typo in the model field name
                    'priority': user_resp.get('priority', 0),
                    'status_quo': user_resp.get('status_quo', 0),
                    'comment': user_resp.get('comment', ''),
                    'priority_display': user_resp.get('priority_display', 'Not Started'),
                    'status_quo_display': user_resp.get('status_quo_display', 'Not Started'),
                    'is_answered': user_resp.get('is_answered', False),
                    'completion_score': user_resp.get('completion_score', 0.0),
                    'status': user_resp.get('status', 'draft'),
                    'response_id': user_resp.get('id', None)
                }
                
                question_response[category.name]['questions'].append(question_data)

        return Response({
            'client': client_data_serialized,
            'year': target_year.year,  # Return the actual year being used
            'categories': category_averages,
            'question_response': question_response,
            # 'all_questions_with_comments': category_averages_with_comments,
        })
    
    
    # ------------------------------------- viewing comments and averages ---------------------------------
    @action(detail=False, methods=['get'])
    def client_admin_dashboard_with_year_responses(self, request):
        """Dashboard for client admin users"""
        
        client_id = request.query_params.get("client_id")
        
        
        # Get year from query parameters, default to current year if not provided
        year_param = request.query_params.get("year")
        
        # print(f"client id is pass ={client_id}")
        user = request.user
        
        # Get user's client
        try:
            client = None
            if user.role == "terramo_admin":
                if not client_id:
                    return Response(
                        {"error": "Client id is required."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                # validate UUID format
                try:
                    UUID(str(client_id))  # will raise ValueError if not a valid UUID
                except ValueError:
                    return Response(
                        {"error": "Invalid client id format."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                client = Client.objects.filter(id=client_id).first()
                if not client:
                    return Response(
                        {"error": "Client not found."},
                        status=status.HTTP_404_NOT_FOUND
                    )
                
            else:
                
                client = user.client
        except AttributeError:
            return Response({'error': 'User is not associated with a client'}, 
                            status=status.HTTP_403_FORBIDDEN)

        # Determine which year to use
        if year_param:
            try:
                # Convert to integer and validate
                year_value = int(year_param)
                
                # Try to get the specific ESG year
                try:
                    target_year = ESGYear.objects.get(year=year_value, is_active=True)
                except ESGYear.DoesNotExist:
                    return Response({
                        'error': f'ESG year {year_value} not found or not active'
                    }, status=status.HTTP_404_NOT_FOUND)
                    
            except (ValueError, TypeError):
                return Response({
                    'error': 'Invalid year parameter. Year must be a valid integer.'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Get current year if no year parameter provided
            # Use the manager's get_current method or the class method
            target_year = ESGYear.objects.get_current()  # or ESGYear.get_current_year()
            if not target_year:
                return Response({'error': 'No current ESG year set'}, 
                                status=status.HTTP_400_BAD_REQUEST)

        # Get categories and calculate averages for the target year
        category_averages = self._calculate_category_averages_with_year(client, target_year)
        category_averages_with_comments = self._calculate_category_averages_with_year_and_comments(client, target_year)

        # Get user's ESG question responses for the target year
        user_responses = {}
        responses = ESGQuestionResponse.objects.filter(
            user=user,
            question__year=target_year,  # Use target_year instead of current_year
            questionnaire_type='client_admin'
        ).select_related('question', 'question__category')

        # Create a dictionary for quick lookup
        for response in responses:
            user_responses[response.question.id] = {
                'id': response.id,
                'priority': response.priority,
                'status_quo': response.status_quo,
                'comment': response.comment,
                'priority_display': response.get_priority_display(),
                'status_quo_display': response.get_status_quo_display(),
                'is_answered': response.is_answered,
                'completion_score': response.completion_score,
                'status': response.status
            }

        # Get all questions for the target year to ensure we have responses for all
        questions = ESGQuestion.objects.filter(
            year=target_year,  # Use target_year instead of current_year
            is_active=True
        ).select_related('category').order_by('category', 'order', 'index_code')

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
        
        # Use bulk_create with ignore_conflicts to avoid IntegrityError
        if new_responses:
            ESGQuestionResponse.objects.bulk_create(new_responses, ignore_conflicts=True)
        
        # Re-fetch all responses after bulk_create to ensure completeness
        all_user_responses = ESGQuestionResponse.objects.filter(
            user=user,
            question__year=target_year,  # Use target_year instead of current_year
            questionnaire_type='client_admin'
        ).select_related('question', 'question__category')

        # Update user_responses dictionary with all responses
        user_responses = {}
        for response in all_user_responses:
            user_responses[response.question.id] = {
                'id': response.id,
                'priority': response.priority,
                'status_quo': response.status_quo,
                'comment': response.comment,
                'priority_display': response.get_priority_display(),
                'status_quo_display': response.get_status_quo_display(),
                'is_answered': response.is_answered,
                'completion_score': response.completion_score,
                'status': response.status
            }

        # Build question_response structure grouped by category
        question_response = {}
        categories = ESGCategory.objects.filter(is_active=True).order_by('name')
        
        for category in categories:
            category_questions = questions.filter(category=category)
            question_response[category.name] = {
                'category_info': {
                    'id': str(category.id),
                    'name': category.name,
                    'display_name': category.display_name
                },
                'questions': []
            }
            
            for question in category_questions:
                user_resp = user_responses.get(question.id, {})
                
                question_data = {
                    'question_id': str(question.id),
                    'index_code': question.index_code,
                    'measure': question.measure,
                    'question_description': question.desription or '',  # Note: there's a typo in the model field name
                    'priority': user_resp.get('priority', 0),
                    'status_quo': user_resp.get('status_quo', 0),
                    'comment': user_resp.get('comment', ''),
                    'priority_display': user_resp.get('priority_display', 'Not Started'),
                    'status_quo_display': user_resp.get('status_quo_display', 'Not Started'),
                    'is_answered': user_resp.get('is_answered', False),
                    'completion_score': user_resp.get('completion_score', 0.0),
                    'status': user_resp.get('status', 'draft'),
                    'response_id': user_resp.get('id', None)
                }
                
                question_response[category.name]['questions'].append(question_data)

        return Response({
            'client': {
                'id': str(client.id),
                'name': client.company_name
            },
            'year': target_year.year,  # Return the actual year being used
            'categories': category_averages,
            'question_response': question_response,
            'all_questions_with_comments': category_averages_with_comments,
        })
    
    def calculate_category_averages_with_year(self, client, current_year):
        """Calculate average priority and status quo for each question under each category."""
        from django.db.models import Avg, Count, Q
        
        # Get client users (stakeholder and client admin)
        stakeholder_groups = StakeholderGroup.objects.filter(client=client, is_active=True)
        stakeholder_users = []
        
        for group in stakeholder_groups:
            stakeholders = Stakeholder.objects.filter(
                group=group, 
                is_registered=True, 
                status='approved',
                user__isnull=False
            )
            stakeholder_users.extend([s.user for s in stakeholders])
        try:
            client_admin = User.objects.get(client=client, role='client_admin')
            stakeholder_users.append(client_admin)
        except User.DoesNotExist:
            pass
        
        if not stakeholder_users:
            return {}
        # Get the questions for the current year
        questions = ESGQuestion.objects.filter(
            year=current_year,
            is_active=True
        ).select_related('category')
        
        # Filter responses that are submitted and belong to the client users
        client_user_ids = [user.id for user in stakeholder_users]
        responses = ESGQuestionResponse.objects.filter(
            question__year=current_year,
            user_id__in=client_user_ids,
            status='submitted'
        ).exclude(
            Q(priority__isnull=True) | Q(status_quo__isnull=True)
        )
        
        # Prepare dictionary to store average data
        category_averages = {}
        for question in questions:
            # Get all responses for this question
            question_responses = responses.filter(question=question)
        
            if question_responses.exists():
                avg_data = question_responses.aggregate(
                    avg_priority=Avg('priority'),
                    avg_status_quo=Avg('status_quo'),
                    response_count=Count('id')
                )
                
                # Collect comments for this question
                question_comments = []
                for response in question_responses:
                    if response.comment:  # Only include non-empty comments
                        question_comments.append({
                            'user_id': str(response.user.id),
                            'user_email': response.user.email,
                            'questionnaire_type': response.questionnaire_type,
                            'comment': response.comment,
                            'responded_at': response.responded_at,
                            'updated_at': response.updated_at,
                            'is_client_admin': response.user.email == client.email,
                        })
            
                question_avg = {
                    'question_id': str(question.id),
                    'index_code': question.index_code,
                    'measure': question.measure,
                    'avg_priority': round(avg_data['avg_priority'] or 0, 2),
                    'avg_status_quo': round(avg_data['avg_status_quo'] or 0, 2),
                    'response_count': avg_data['response_count'],
                    'comments': question_comments,  # Add comments here
                }
                
            else:
                question_avg = {
                    'question_id': str(question.id),
                    'index_code': question.index_code,
                    'measure': question.measure,
                    'avg_priority': 0.0,
                    'avg_status_quo': 0.0,
                    'response_count': 0,
                    'comments': [],  # Empty comments array when no responses
                }
            
            # Group by category
            category_name = question.category.name
            if category_name not in category_averages:
                category_averages[category_name] = {
                    'category_info': {
                        'id': str(question.category.id),
                        'name': question.category.name,
                        'display_name': question.category.display_name
                    },
                    'questions': []
                }
            
            category_averages[category_name]['questions'].append(question_avg)
        return category_averages
    
    def _calculate_category_averages_with_year_and_comments(self, client, esg_year):
        """Calculate category averages for a specific ESG year"""
        from django.db.models import Avg, Count, Q
        category_averages = {}
        
        # Get all categories
        categories = ESGCategory.objects.filter(is_active=True)
        
        for category in categories:
            # Get all questions for this category and year
            questions = ESGQuestion.objects.filter(
                category=category,
                year=esg_year,  # Filter by the specific year
                is_active=True
            )
            
            # Get all responses for these questions from users of this client
            responses = ESGQuestionResponse.objects.filter(
                question__in=questions,
                user__client=client,
                questionnaire_type__in=['client_admin', 'stakeholder'],
                status='submitted'
            )
            
            # Calculate averages
            if responses.exists():
                avg_priority = responses.aggregate(
                    avg_priority=Avg('priority')
                )['avg_priority'] or 0
                
                avg_status_quo = responses.aggregate(
                    avg_status_quo=Avg('status_quo')
                )['avg_status_quo'] or 0
            else:
                avg_priority = 0
                avg_status_quo = 0
            
            # Get question details for this category
            question_details = []
             
            # comments container 
            category_comments = []
            for question in questions:
                # Get user responses for this question
                question_responses = responses.filter(question=question)
                
                if question_responses.exists():
                    q_avg_priority = question_responses.aggregate(
                        avg_priority=Avg('priority')
                    )['avg_priority'] or 0
                    
                    q_avg_status_quo = question_responses.aggregate(
                        avg_status_quo=Avg('status_quo')
                    )['avg_status_quo'] or 0

                    # Collect comments for this specific question
                question_comments = []
                for response in question_responses:
                    if response.comment:  # Only include non-empty comments
                        question_comments.append({
                            'user_id': str(response.user.id),
                            'user_email': response.user.email,
                            'comment': response.comment,
                            'responded_at': response.responded_at,
                            'updated_at': response.updated_at,
                            'is_client_admin': response.user.email == client.email,
                        })

                    
                else:
                    q_avg_priority = 0
                    q_avg_status_quo = 0
                
                question_details.append({
                    'question_id': str(question.id),
                    'index_code': question.index_code,
                    'measure': question.measure,
                    'avg_priority': q_avg_priority,
                    'avg_status_quo': q_avg_status_quo,
                    'comments': question_comments,
                    
                })
                
            
            category_averages[category.name] = {
                'category_info': {
                    'id': str(category.id),
                    'name': category.name,
                    'display_name': category.display_name,
                },
                'avg_priority': avg_priority,
                'avg_status_quo': avg_status_quo,
                'total_questions': questions.count(),
                'answered_questions': responses.values('question').distinct().count(),
                'questions': question_details,
               
                'total_comments': len(category_comments),
            }
        
        return category_averages
    @action(detail=False, methods=['get'])
    def available_years(self, request):
        """Get available ESG years for dropdown"""
        years = ESGYear.objects.filter(is_active=True).values_list('year', flat=True).order_by('-year')
        current_year = ESGYear.objects.get_current()
        
        return Response({
            'available_years': list(years),
            'current_year': current_year.year if current_year else None
        })
    
    
    @action(detail=False, methods=['get'])
    def admin_dashboard_with_year(self, request):
        """Dashboard for Terramo admin users with client analytics"""
        if not request.user.role == "terramo_admin":
            return Response({'error': 'Admin access required'}, 
                        status=status.HTTP_403_FORBIDDEN)

        # Get year from query parameters, default to current year if not provided
        year_param = request.query_params.get("year")
        
        # Determine which year to use
        if year_param:
            try:
                # Convert to integer and validate
                year_value = int(year_param)
                
                # Try to get the specific ESG year
                try:
                    target_year = ESGYear.objects.get(year=year_value, is_active=True)
                except ESGYear.DoesNotExist:
                    return Response({
                        'error': f'ESG year {year_value} not found or not active'
                    }, status=status.HTTP_404_NOT_FOUND)
                    
            except (ValueError, TypeError):
                return Response({
                    'error': 'Invalid year parameter. Year must be a valid integer.'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Get current year if no year parameter provided
            target_year = ESGYear.objects.get_current()  # or ESGYear.get_current_year()
            if not target_year:
                return Response({'error': 'No current ESG year set'}, 
                                status=status.HTTP_400_BAD_REQUEST)

        # Get all clients and their surveys
        clients = Client.objects.filter(is_active=True)
        client_data = []

        total_questions = ESGQuestion.objects.filter(
            year=target_year, is_active=True  # Use target_year instead of current_year
        ).count()

        for client in clients:
            try:
                survey = ESGSurvey.objects.get(client=client, year=target_year.year)  # Use target_year
            except ESGSurvey.DoesNotExist:
                survey = None
            
            # Calculate averages for this client using the target year
            averages = self._calculate_client_averages_with_year(client, target_year)
            
            # Calculate completion rate based on submitted responses
            stakeholder_groups = StakeholderGroup.objects.filter(client=client, is_active=True)
            stakeholder_users = []
            
            for group in stakeholder_groups:
                stakeholders = Stakeholder.objects.filter(
                    group=group, 
                    is_registered=True, 
                    status='approved',
                    user__isnull=False
                )
                stakeholder_users.extend([s.user for s in stakeholders])
            
            # Include client admin
            try:
                client_admin = User.objects.get(client=client, role='client_admin')
                stakeholder_users.append(client_admin)
            except User.DoesNotExist:
                pass
            
            completed_responses = ESGQuestionResponse.objects.filter(
                question__year=target_year,  # Use target_year instead of current_year
                user__in=stakeholder_users,
                status='submitted'
            ).exclude(
                Q(priority__isnull=True) | Q(status_quo__isnull=True) |
                Q(priority=0) | Q(status_quo=0)
            ).count()
            
            expected_responses = total_questions * len(stakeholder_users)
            completion_rate = (completed_responses / expected_responses * 100) if expected_responses > 0 else 0
            
            client_data.append({
                'client': ClientListSerializer(client).data,
                'survey': ESGSurveySerializer(survey).data if survey else None,
                'completion_rate': round(completion_rate, 2),
                'total_questions': total_questions,
                'completed_responses': completed_responses,
                'expected_responses': expected_responses,
                'averages': averages
            })

        return Response({
            'clients': client_data,
            'year': target_year.year,  # Return the actual year being used
            'total_clients': clients.count()
        })


    def _calculate_client_averages_with_year(self, client, esg_year):
        """Calculate client averages for a specific ESG year"""
        from django.db.models import Avg, Count, Q
        
        # Get all questions for the specific year
        questions = ESGQuestion.objects.filter(
            year=esg_year,  # Filter by the specific year
            is_active=True
        )
        
        # Get all stakeholder users for this client
        stakeholder_groups = StakeholderGroup.objects.filter(client=client, is_active=True)
        stakeholder_users = []
        
        for group in stakeholder_groups:
            stakeholders = Stakeholder.objects.filter(
                group=group, 
                is_registered=True, 
                status='approved',
                user__isnull=False
            )
            stakeholder_users.extend([s.user for s in stakeholders])
        
        # Include client admin
        try:
            client_admin = User.objects.get(client=client, role='client_admin')
            stakeholder_users.append(client_admin)
        except User.DoesNotExist:
            pass
        
        # Get all responses for these questions from users of this client
        responses = ESGQuestionResponse.objects.filter(
            question__in=questions,
            user__in=stakeholder_users,
            status='submitted'
        )
        
        # Calculate overall averages
        if responses.exists():
            avg_priority = responses.aggregate(
                avg_priority=Avg('priority')
            )['avg_priority'] or 0
            
            avg_status_quo = responses.aggregate(
                avg_status_quo=Avg('status_quo')
            )['avg_status_quo'] or 0
        else:
            avg_priority = 0
            avg_status_quo = 0
        
        # Calculate category-wise averages
        categories = ESGCategory.objects.filter(is_active=True)
        category_averages = {}
        
        for category in categories:
            category_questions = questions.filter(category=category)
            category_responses = responses.filter(question__in=category_questions)
            
            if category_responses.exists():
                cat_avg_priority = category_responses.aggregate(
                    avg_priority=Avg('priority')
                )['avg_priority'] or 0
                
                cat_avg_status_quo = category_responses.aggregate(
                    avg_status_quo=Avg('status_quo')
                )['avg_status_quo'] or 0
            else:
                cat_avg_priority = 0
                cat_avg_status_quo = 0
            
            category_averages[category.name] = {
                'category_info': {
                    'id': str(category.id),
                    'name': category.name,
                    'display_name': category.display_name,
                },
                'avg_priority': cat_avg_priority,
                'avg_status_quo': cat_avg_status_quo,
                'total_questions': category_questions.count(),
                'answered_questions': category_responses.values('question').distinct().count(),
            }
        
        return {
            'overall': {
                'avg_priority': avg_priority,
                'avg_status_quo': avg_status_quo,
                'total_questions': questions.count(),
                'answered_questions': responses.values('question').distinct().count(),
            },
            'categories': category_averages
        }
    # --------- Enhance client admin End ----------------

    # Enhance stakeholder 
    @action(detail=False, methods=['get'])
    def stakeholderuser_dashboard(self, request):
        """Dashboard for Stakeholder users"""
        user = request.user
        
        # try:
        #     stakeholder = Stakeholder.objects.get(user=user)
        # except Stakeholder.DoesNotExist:
        #     return Response({'error': 'User is not a stakeholder'}, 
        #                   status=status.HTTP_403_FORBIDDEN)

        # # Get client through stakeholder group
        # client = stakeholder.group.client
        # current_year = ESGYear.get_current_year()
        # if not current_year:
        #     return Response({'error': 'No current ESG year set'}, 
        #                   status=status.HTTP_400_BAD_REQUEST)
        
        # Get user's client
        try:
            stakeholder = Stakeholder.objects.get(user=user)
        except AttributeError:
            return Response({'error': 'User is not associated with a client'}, 
                            status=status.HTTP_403_FORBIDDEN)

        client = stakeholder.client
        # Get current year
        current_year = ESGYear.get_current_year()
        if not current_year:
            return Response({'error': 'No current ESG year set'}, 
                            status=status.HTTP_400_BAD_REQUEST)

        # Get categories and calculate averages
        # category_averages = self._calculate_category_averages(client, current_year)

        # Get user's ESG question responses
        user_responses = {}
        responses = ESGQuestionResponse.objects.filter(
            user=user,
            question__year=current_year,
            questionnaire_type='stakeholder'
        ).select_related('question', 'question__category')

        # Create a dictionary for quick lookup
        for response in responses:
            user_responses[response.question.id] = {
                'id': response.id,
                'priority': response.priority,
                'status_quo': response.status_quo,
                'comment': response.comment,
                'priority_display': response.get_priority_display(),
                'status_quo_display': response.get_status_quo_display(),
                'is_answered': response.is_answered,
                'completion_score': response.completion_score,
                'status': response.status
            }

        # Get all questions for the current year to ensure we have responses for all
        questions = ESGQuestion.objects.filter(
            year=current_year,
            is_active=True
        ).select_related('category').order_by('category', 'order', 'index_code')

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
        
        # Use bulk_create with ignore_conflicts to avoid IntegrityError
        if new_responses:
            ESGQuestionResponse.objects.bulk_create(new_responses, ignore_conflicts=True)
        
        # Re-fetch all responses after bulk_create to ensure completeness
        all_user_responses = ESGQuestionResponse.objects.filter(
            user=user,
            question__year=current_year,
            questionnaire_type='stakeholder'
        ).select_related('question', 'question__category')

        # Update user_responses dictionary with all responses
        user_responses = {}
        for response in all_user_responses:
            user_responses[response.question.id] = {
                'id': response.id,
                'priority': response.priority,
                'status_quo': response.status_quo,
                'comment': response.comment,
                'priority_display': response.get_priority_display(),
                'status_quo_display': response.get_status_quo_display(),
                'is_answered': response.is_answered,
                'completion_score': response.completion_score,
                'status': response.status
            }

        # Build question_response structure grouped by category
        question_response = {}
        categories = ESGCategory.objects.filter(is_active=True).order_by('name')
        
        for category in categories:
            category_questions = questions.filter(category=category)
            question_response[category.name] = {
                'category_info': {
                    'id': str(category.id),
                    'name': category.name,
                    'display_name': category.display_name
                },
                'questions': []
            }
            
            for question in category_questions:
                user_resp = user_responses.get(question.id, {})
                
                question_data = {
                    'question_id': str(question.id),
                    'index_code': question.index_code,
                    'measure': question.measure,
                    'question_description': question.desription or '',  # Note: there's a typo in the model field name
                    'priority': user_resp.get('priority', 0),
                    'status_quo': user_resp.get('status_quo', 0),
                    'comment': user_resp.get('comment', ''),
                    'priority_display': user_resp.get('priority_display', 'Not Started'),
                    'status_quo_display': user_resp.get('status_quo_display', 'Not Started'),
                    'is_answered': user_resp.get('is_answered', False),
                    'completion_score': user_resp.get('completion_score', 0.0),
                    'status': user_resp.get('status', 'draft'),
                    'response_id': user_resp.get('id', None)
                }
                
                question_response[category.name]['questions'].append(question_data)

        return Response({
            'client': {
                'id': str(client.id),
                'name': client.company_name
            },
            'stakeholder': {
                'id': str(stakeholder.id),
                'name': stakeholder.first_name,
                'email': stakeholder.email,
                'group': stakeholder.group.name
            },
            'year': current_year.year,
            # 'categories': category_averages,
            'question_response': question_response
        })
    
    def _get_user_responses(self, user, current_year):
        """Get user's ESG question responses"""
        user_responses = {}
        print(f"_get_user_responses- {current_year}")
        responses = ESGQuestionResponse.objects.filter(
            user=user,
            question__year=current_year,
            questionnaire_type='client_admin'
        ).select_related('question', 'question__category')

        for response in responses:
            user_responses[response.question.id] = {
                'id': response.id,
                'priority': response.priority,
                'status_quo': response.status_quo,
                'comment': response.comment,
                'priority_display': response.get_priority_display(),
                'status_quo_display': response.get_status_quo_display(),
                'completion_score': response.completion_score,
                'status': response.status
            }
        return user_responses

    def _ensure_question_responses(self, user, current_year):
        """Ensure all questions have responses, create missing ones"""
        questions = ESGQuestion.objects.filter(
            year=current_year,
            is_active=True
        ).select_related('category').order_by('category', 'order', 'index_code')

        # Get existing response question IDs
        existing_response_ids = set(
            ESGQuestionResponse.objects.filter(
                user=user,
                question__year=current_year,
                questionnaire_type='client_admin'
            ).values_list('question_id', flat=True)
        )

        # Create responses for questions without responses
        questions_without_responses = questions.exclude(id__in=existing_response_ids)
        
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
            ESGQuestionResponse.objects.bulk_create(new_responses, ignore_conflicts=True)
        
        return questions

    def _build_question_response_structure(self, questions, user_responses):
        """Build question response structure grouped by category"""
        question_response = {}
        categories = ESGCategory.objects.filter(is_active=True).order_by('name')
        
        for category in categories:
            category_questions = questions.filter(category=category)
            question_response[category.name] = {
                'category_info': {
                    'id': str(category.id),
                    'name': category.name,
                    'display_name': category.display_name
                },
                'questions': []
            }
            
            for question in category_questions:
                user_resp = user_responses.get(question.id, {})
                
                question_data = {
                    'question_id': str(question.id),
                    'index_code': question.index_code,
                    'measure': question.measure,
                    'question_description': question.desription or '',
                    'priority': user_resp.get('priority', 0),
                    'status_quo': user_resp.get('status_quo', 0),
                    'comment': user_resp.get('comment', ''),
                    'priority_display': user_resp.get('priority_display', 'Not Started'),
                    'status_quo_display': user_resp.get('status_quo_display', 'Not Started'),
                    'completion_score': user_resp.get('completion_score', 0.0),
                    'status': user_resp.get('status', 'draft'),
                    'response_id': user_resp.get('id', None)
                }
                
                question_response[category.name]['questions'].append(question_data)

        return question_response

    

    def _build_question_response_structure_year(self, questions, user_responses, year):
        """Build question response structure grouped by category"""
        question_response = {}
        categories = ESGCategory.objects.filter(is_active=True).order_by('name')
        
        for category in categories:
            category_questions = questions.filter(category=category)
            question_response[category.name] = {
                'category_info': {
                    'id': str(category.id),
                    'name': category.name,
                    'display_name': category.display_name
                },
                'questions': []
            }
            
            for question in category_questions:
                user_resp = user_responses.get(question.id, {})
                
                question_data = {
                    'question_id': str(question.id),
                    'index_code': question.index_code,
                    'measure': question.measure,
                    'question_description': question.desription or '',
                    'priority': user_resp.get('priority', 0),
                    'status_quo': user_resp.get('status_quo', 0),
                    'comment': user_resp.get('comment', ''),
                    'priority_display': user_resp.get('priority_display', 'Not Started'),
                    'status_quo_display': user_resp.get('status_quo_display', 'Not Started'),
                    'completion_score': user_resp.get('completion_score', 0.0),
                    'status': user_resp.get('status', 'draft'),
                    'response_id': user_resp.get('id', None)
                }
                
                question_response[category.name]['questions'].append(question_data)

        return question_response
    def _check_group_has_responses(self, stakeholder_group, current_year):
        """Check if stakeholder group has any completed responses"""
        # Get all stakeholders in this group who are registered users
        stakeholder_users = User.objects.filter(
            usr_stakeholder__group=stakeholder_group,
            usr_stakeholder__status='approved'
        )

        if not stakeholder_users.exists():
            return False

        # Check if any of these users have responses
        # Removed is_answered=True since it's not a database field
        return ESGQuestionResponse.objects.filter(
            user__in=stakeholder_users,
            question__year=current_year,
            questionnaire_type='stakeholder',
            status='submitted'  # Only check submitted responses
        ).exists()

    def _calculate_stakeholder_group_category_averages(self, stakeholder_group, current_year):
        """Calculate category averages for a specific stakeholder group"""
        # Get all stakeholder users in this group
        stakeholder_users = User.objects.filter(
            usr_stakeholder__group=stakeholder_group,
            usr_stakeholder__status='approved'
        )

        if not stakeholder_users.exists():
            return {}

        # Get all categories
        categories = ESGCategory.objects.filter(is_active=True)
        category_averages = {}

        for category in categories:
            # Calculate averages for priority and status_quo for this category and group
            priority_avg = ESGQuestionResponse.objects.filter(
                user__in=stakeholder_users,
                question__year=current_year,
                question__category=category,
                questionnaire_type='stakeholder',
                status='submitted',
                priority__gt=0  # Exclude not answered (0 values)
            ).aggregate(avg_priority=Avg('priority'))['avg_priority'] or 0

            # Removed is_answered=True filter since it's not a database field
            status_quo_avg = ESGQuestionResponse.objects.filter(
                user__in=stakeholder_users,
                question__year=current_year,
                question__category=category,
                questionnaire_type='stakeholder',
                status='submitted',  # Use status='submitted' instead
                status_quo__gt=0  # Exclude not answered (0 values)
            ).aggregate(avg_status_quo=Avg('status_quo'))['avg_status_quo'] or 0

            category_averages[category.name] = {
                'category_info': {
                    'id': str(category.id),
                    'name': category.name,
                    'display_name': category.display_name
                },
                'priority_average': round(priority_avg, 2),
                'status_quo_average': round(status_quo_avg, 2)
            }

        return category_averages

    def _calculate_category_averages_stakeholder_analysis(self, client, current_year, group_type='client_admin'):
        """Calculate category averages for client admin (default behavior) - stakeholder analysis specific"""
        categories = ESGCategory.objects.filter(is_active=True)
        category_averages = {}

        for category in categories:
            if group_type == 'client_admin':
                # For client admin, get their responses
                priority_avg = ESGQuestionResponse.objects.filter(
                    user__client=client,
                    question__year=current_year,
                    question__category=category,
                    questionnaire_type='client_admin',
                    status='submitted',  # Use status instead of is_answered
                    priority__gt=0
                ).aggregate(avg_priority=Avg('priority'))['avg_priority'] or 0

                status_quo_avg = ESGQuestionResponse.objects.filter(
                    user__client=client,
                    question__year=current_year,
                    question__category=category,
                    questionnaire_type='client_admin',
                    status='submitted',  
                    status_quo__gt=0
                ).aggregate(avg_status_quo=Avg('status_quo'))['avg_status_quo'] or 0
            
            category_averages[category.name] = {
                'category_info': {
                    'id': str(category.id),
                    'name': category.name,
                    'display_name': category.display_name
                },
                'priority_average': round(priority_avg, 2),
                'status_quo_average': round(status_quo_avg, 2)
            }

    #     return category_averages

    @action(detail=False, methods=['post'])
    def client_admin_stakeholder_analysis_show_in_table(self, request):
        """Dashboard for client admin stakeholder analysis setting up the show in or not in the data table"""
        user = request.user
        stakeholdergroup_ids = request.data.get('stakeholdergroup_ids')
        current_client_id = request.data.get('client_id')
        # print(f"current_client_id-{current_client_id}")
        
        # for val in stakeholdergroup_ids:
        #     for val, data in val.items():
        #         print(val,data)
        # return Response({
        #     "stakeholdergroup_ids": stakeholdergroup_ids,
        #     "client_id": current_client_id
        # })

        # Validate required fields
        if not stakeholdergroup_ids:
            return Response({
                'error': 'stakeholdergroup_ids is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not current_client_id:
            return Response({
                'error': 'client_id is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Permission checks
        if str(user.client.id) != current_client_id:
            return Response({
                'error': 'You don\'t have permission to perform this action.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        if user.role != "client_admin":
            return Response({
                'error': 'You don\'t have permission to perform this action.'
            }, status=status.HTTP_403_FORBIDDEN)

        # Get user's client
        try:
            client = user.client
        except AttributeError:
            return Response({
                'error': 'User is not associated with a client'
            }, status=status.HTTP_403_FORBIDDEN)

        updated_count = 0
        not_found_ids = []
        permission_denied_ids = []

        with transaction.atomic():
            for group_lists in stakeholdergroup_ids:
                for group, boolean_value in group_lists.items():
                    try:
                        # Check if stakeholder group exists and belongs to the client
                        stakeholder_group = StakeholderGroup.objects.get(
                            id=group,
                            client=client,
                            is_active=True
                        )
                        
                        # Update the show_in_table field
                        stakeholder_group.show_in_table = boolean_value
                        stakeholder_group.save()
                        updated_count += 1
                        
                    except StakeholderGroup.DoesNotExist:
                        # Check if group exists but doesn't belong to client
                        if StakeholderGroup.objects.filter(id=group).exists():
                            permission_denied_ids.append(group)
                        else:
                            not_found_ids.append(group)
        
        # Prepare response
        response_data = {
            'message': f'Successfully updated {updated_count} stakeholder group(s)',
            'updated_count': updated_count,
            'client_id': current_client_id,
            'updated_stakeholder_groups': stakeholdergroup_ids[:updated_count]  # Only successful ones
        }
        
        # Add warnings if any groups weren't updated
        if not_found_ids or permission_denied_ids:
            warnings = []
            if not_found_ids:
                warnings.append(f"Groups not found: {not_found_ids}")
            if permission_denied_ids:
                warnings.append(f"Groups don't belong to your client: {permission_denied_ids}")
            response_data['warnings'] = warnings
        
        if updated_count == 0:
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(response_data, status=status.HTTP_200_OK)

        


    @action(detail=False, methods=['get'])
    def client_admin_stakeholder_analysis(self, request):
        """Dashboard for client admin stakeholder analysis"""
        user = request.user
        year_param = request.query_params.get("year")
        @method_decorator(cache_page(60 * 15, key_prefix=('clientadmin_stakeholder_analysis')))
        def list(self,request, *args, **kwargs):
            return super().list(request, *args, **kwargs)
        
        def get_queryset(self):
            import time
            time.sleep(5)
            return super().get_queryset()
        
        # Get user's client
        try:
            client = user.client
        except AttributeError:
            return Response({'error': 'User is not associated with a client'}, 
                            status=status.HTTP_403_FORBIDDEN)
        if year_param:
            try:
                # Convert to integer and validate
                year_value = int(year_param)
                
                # Try to get the specific ESG year
                try:
                    current_year = ESGYear.objects.get(year=year_value, is_active=True)
                except ESGYear.DoesNotExist:
                    return Response({
                        'error': f'ESG year {year_value} not found or not active'
                    }, status=status.HTTP_404_NOT_FOUND)
                    
            except (ValueError, TypeError):
                return Response({
                    'error': 'Invalid year parameter. Year must be a valid integer.'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Get current year if no year parameter provided
            # Use the manager's get_current method or the class method
            current_year = ESGYear.objects.get_current()  # or ESGYear.get_current_year()
            if not current_year:
                return Response({'error': 'No current ESG year set'}, 
                                status=status.HTTP_400_BAD_REQUEST)
        # Get categories and calculate averages for client admin (default)
        category_averages = self._calculate_category_averages_stakeholder_analysis(client, current_year)

        # Get user's ESG question responses (client admin responses)
        user_responses = self._get_user_responses(user, current_year)

        # Get all questions and ensure responses exist
        questions = self._ensure_question_responses(user, current_year)
        
        # Build question_response structure grouped by category
        question_response = self._build_question_response_structure(questions, user_responses)

        # Get stakeholder groups with their data (now includes per-question responses)
        stakeholder_groups_data = self._get_stakeholder_groups_data(client, current_year, questions)

        stakeholder_groups_data_plot = self._get_stakeholder_groups_data_plot_with_show_in_table_filter(client, current_year, questions)
        return Response({
            'client': {
                'id': str(client.id),
                'name': client.company_name
            },
            'year': current_year.year,
            'categories': category_averages,
            'question_response': question_response,
            'stakeholder_groups': stakeholder_groups_data,
            'stakeholder_groups_data_plot': stakeholder_groups_data_plot
        })

    # Terramo admin viewing the client stakeholder anaylsis
    @action(detail=False, methods=['get'])
    def client_admin_stakeholder_analysis_with_year(self, request):
        """Dashboard for client admin stakeholder analysis"""
        client_id = request.query_params.get("client_id")

        # Get year from query parameters, default to current year if not provided
        year_param = request.query_params.get("year")
        user = request.user
        
        # Get user's client
        # try:
        #     client = user.client
        # except AttributeError:
        #     return Response({'error': 'User is not associated with a client'}, 
        #                     status=status.HTTP_403_FORBIDDEN)
        # Get user's client
        try:
            # client = None
            if user.role == "terramo_admin":
                if not client_id:
                    return Response(
                        {"error": "Client id is required."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                # validate UUID format
                try:
                    UUID(str(client_id))  # will raise ValueError if not a valid UUID
                except ValueError:
                    return Response(
                        {"error": "Invalid client id format."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                client = Client.objects.filter(id=client_id).first()
                if not client:
                    return Response(
                        {"error": "Client not found."},
                        status=status.HTTP_404_NOT_FOUND
                    )
                
            else:
                try:
                    if client_id:
                        UUID(str(client_id))  # will raise ValueError if not a valid UUID
                except ValueError:
                    return Response(
                        {"error": "Invalid client id format."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                if client_id:
                    client = Client.objects.filter(id=client_id).first()
                    if user.client != client:
                        return Response(
                            {"error": f"You dont have permission to view this information."},
                            status=status.HTTP_403_FORBIDDEN
                        )
                client = user.client

        except AttributeError:
            return Response({'error': 'User is not associated with a client'}, 
                            status=status.HTTP_403_FORBIDDEN)

        if year_param:
            try:
                # Convert to integer and validate
                year_value = int(year_param)
                
                # Try to get the specific ESG year
                try:
                    current_year = ESGYear.objects.get(year=year_value, is_active=True)
                    print(f"---------current_year----------{current_year}")
                except ESGYear.DoesNotExist:
                    return Response({
                        'error': f'ESG year {year_value} not found or not active'
                    }, status=status.HTTP_404_NOT_FOUND)
                    
            except (ValueError, TypeError):
                return Response({
                    'error': 'Invalid year parameter. Year must be a valid integer.'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Get current year if no year parameter provided
            # Use the manager's get_current method or the class method
            current_year = ESGYear.objects.get_current()  # or ESGYear.get_current_year()
            if not current_year:
                return Response({'error': 'No current ESG year set'}, 
                                status=status.HTTP_400_BAD_REQUEST)
        # Get current year
        # current_year = ESGYear.get_current_year()
        # if not current_year:
        #     return Response({'error': 'No current ESG year set'}, 
        #                     status=status.HTTP_400_BAD_REQUEST)
   
        # Get categories and calculate averages for client admin (default)
        category_averages = self._calculate_category_averages_stakeholder_analysis(client, current_year)

        # Get user's ESG question responses (client admin responses)
        user_responses = self._get_user_responses(user, current_year)

        # Get all questions and ensure responses exist
        questions = self._ensure_question_responses(user, current_year)
        
        # Build question_response structure grouped by category
        question_response = self._build_question_response_structure(questions, user_responses)

        # Get stakeholder groups with their data (now includes per-question responses)
        # stakeholder_groups_data = self._get_stakeholder_groups_data(client, current_year, questions)
        print(f"---curent year - {current_year}")
        stakeholder_groups_data = self._get_stakeholder_groups_data(client, current_year, questions)
        
        return Response({
            'client': {
                'id': str(client.id),
                'name': client.company_name
            },
            'year': str(current_year),
            'categories': category_averages,
            'question_response': question_response,
            'stakeholder_groups': stakeholder_groups_data,
        })

    def _get_stakeholder_groups_data(self, client, current_year, questions):
        """Get stakeholder groups with their response data and per-question responses"""
        # Get all stakeholder groups for this client
        stakeholder_groups = StakeholderGroup.objects.filter(
            client=client,
            is_active=True,
            disable_the_invitation=False,
        ).annotate(
            stakeholder_count=Count('stakeholders', filter=Q(stakeholders__status='approved', stakeholders__client=client))
        ).order_by('name')

        # get global stakeholder groups and append later to the client data
        global_stakeholder_groups = StakeholderGroup.objects.filter(
            client=None,
            is_active=True,
            is_global=True,
            disable_the_invitation=False,
        ).annotate(
            stakeholder_count=Count('stakeholders', filter=Q(stakeholders__status='approved', stakeholders__client=client))
        ).order_by('name')

        # combine the global stakeholders
        combine_stakeholder_groups = stakeholder_groups.union(global_stakeholder_groups)


        stakeholder_groups_data = []

        # default_group = 'Management'
        # Add stakeholder groups
        for group in combine_stakeholder_groups:
            # Check if this group has any responses
            has_responses = self._check_group_has_responses(group, current_year)
            
            # Calculate category averages for this group if they have responses
            category_averages = {}
            question_response = {}
            
            if has_responses:
                category_averages = self._calculate_stakeholder_group_category_averages(group, current_year)
                question_response = self._build_stakeholder_group_question_response(group, current_year, questions)

            # modify the invite_url per groups 
            
            if group.is_global:
                # f"{settings.FRONTEND_DOMAIN_URL}/stakeholder/accept-invitation/{self.invitation_token}/"
                final_invite_url = f"{settings.FRONTEND_DOMAIN_URL}/stakeholder/accept-invitation/{group.invitation_token}/client/{client.id}/"
            else: 
                final_invite_url = group.get_invite_full_url()
            # modifying data, append the stakeholder groups global
            group_data = {
                'id': str(group.id),
                'name': group.name,
                'display_name': group.name,
                'stakeholder_count': group.stakeholder_count,
                'is_default': group.is_global,
                'is_global': group.is_global,
                'show_in_table': group.show_in_table,
                'has_responses': has_responses,
                'category_averages': category_averages,
                'question_response': question_response,  # New: per-question responses
                'invitation_link': final_invite_url
            }
            stakeholder_groups_data.append(group_data)

        return stakeholder_groups_data
    
    # Filtering StakeholderGroups for show in table filter
    def _get_stakeholder_groups_data_plot_with_show_in_table_filter(self, client, current_year, questions):
        """Get stakeholder groups with their response data and per-question responses"""
        # Get all stakeholder groups for this client
        stakeholder_groups = StakeholderGroup.objects.filter(
            client=client,
            is_active=True,
            disable_the_invitation=False,
            show_in_table=True, # newly added fields for filtering data.
        ).annotate(
            stakeholder_count=Count('stakeholders', filter=Q(stakeholders__status='approved'))
        ).order_by('name')

        # get global stakeholder groups and append later to the client data
        global_stakeholder_groups = StakeholderGroup.objects.filter(
            client=None,
            is_active=True,
            is_global=True,
            disable_the_invitation=False
        ).annotate(
            stakeholder_count=Count('stakeholders', filter=Q(stakeholders__status='approved'))
        ).order_by('name')

        # combine the global stakeholders
        combine_stakeholder_groups = stakeholder_groups.union(global_stakeholder_groups)


        stakeholder_groups_data = []

        # default_group = 'Management'
        # Add stakeholder groups
        for group in combine_stakeholder_groups:
            # Check if this group has any responses
            has_responses = self._check_group_has_responses(group, current_year)
            
            # Calculate category averages for this group if they have responses
            category_averages = {}
            question_response = {}
            
            if has_responses:
                category_averages = self._calculate_stakeholder_group_category_averages(group, current_year)
                question_response = self._build_stakeholder_group_question_response(group, current_year, questions)

            if group.is_global:
                # f"{settings.FRONTEND_DOMAIN_URL}/stakeholder/accept-invitation/{self.invitation_token}/"
                final_invite_url = f"{settings.FRONTEND_DOMAIN_URL}/stakeholder/accept-invitation/{group.invitation_token}/client/{client.id}/"
            else: 
                final_invite_url = group.get_invite_full_url()
            # modifying data, append the stakeholder groups global
            group_data = {
                'id': str(group.id),
                'name': group.name,
                'display_name': group.name,
                'stakeholder_count': group.stakeholder_count,
                'is_default': group.is_global,
                'is_global': group.is_global,
                'show_in_table': group.show_in_table,
                'has_responses': has_responses,
                'category_averages': category_averages,
                'question_response': question_response,  # New: per-question responses
                'invitation_link': final_invite_url,
            }
            stakeholder_groups_data.append(group_data)

        return stakeholder_groups_data
    # End filtering show_in_table
    def _get_stakeholder_groups_data_for_year(self, client, year, questions):
        """
        Modified version of your existing method to filter by year
        """
        print(f"print----- logging the year -- {year}")
        logger.info(f"----- logging the year -- {year}")
        # Get the ESG year object
        # try:
        #     esg_year = ESGYear.objects.get(year=year, is_active=True)
        # except ESGYear.DoesNotExist:
        #     return []
        # esg_year = ESGYear.objects.filter(year=year).first()
        # print(f"esg_year----- logging the year -- {esg_year}")
        # Get all stakeholder groups for this client
        stakeholder_groups = StakeholderGroup.objects.filter(
            client=client,
            is_active=True
        ).annotate(
            stakeholder_count=Count('stakeholders', filter=Q(stakeholders__status='approved')),
            # Check if group has responses for this specific year
            has_year_responses=Exists(
                ESGQuestionResponse.objects.filter(
                    question__year=year,  # Use year_id
                    user__usr_stakeholder__group=OuterRef('id'),
                    questionnaire_type='stakeholder'
                )
            )
        ).order_by('name')

        stakeholder_groups_data = []
        default_group = 'Management'
        
        for group in stakeholder_groups:
            # Only process groups that have responses for this year
            if group.has_year_responses:
                # category_averages = self._calculate_stakeholder_group_category_averages_for_year(
                #     group, esg_year
                # )
                category_averages = self._calculate_stakeholder_group_category_averages_for_year(
                    group, year
                )
                question_response = self._build_stakeholder_group_question_response_for_year(
                    group, year, questions
                )

                group_data = {
                    'id': str(group.id),
                    'name': group.name,
                    'display_name': group.name,
                    'stakeholder_count': group.stakeholder_count,
                    'is_default': group.name == default_group,
                    'has_responses': True,  # We know they have responses for this year
                    'year': year,
                    'category_averages': category_averages,
                    'question_response': question_response,
                    'invitation_link': group.get_invite_full_url()
                }
                stakeholder_groups_data.append(group_data)

        return stakeholder_groups_data
    
    def _build_stakeholder_group_question_response_for_year(self, group, esg_year, questions):
        """
        Build question responses for a stakeholder group for a specific ESG year
        """
        # Get all responses from this group for the specific year
        responses = ESGQuestionResponse.objects.filter(
            question__year=esg_year,
            user__usr_stakeholder__group=group,
            questionnaire_type='stakeholder'
        ).select_related('question', 'user')
        
        # Create a mapping of question_id to responses
        question_responses = {}
        
        for response in responses:
            question_id = response.question.id
            if question_id not in question_responses:
                question_responses[question_id] = []
            
            question_responses[question_id].append({
                'user_email': response.user.email,
                'user_name': f"{response.user.first_name} {response.user.last_name}".strip(),
                'priority': response.priority,
                'status_quo': response.status_quo,
                'comment': response.comment,
                'status': response.status,
                'responded_at': response.responded_at,
                'is_answered': response.is_answered,
                'completion_score': response.completion_score
            })
        
        # Build the final structure matching your questions
        question_response_data = {}
        
        for question in questions:
            question_id = question.id
            responses_for_question = question_responses.get(question_id, [])
            
            # Calculate aggregates for this question
            valid_priorities = [r['priority'] for r in responses_for_question if r['priority'] is not None and r['priority'] > 0]
            valid_status_quos = [r['status_quo'] for r in responses_for_question if r['status_quo'] is not None and r['status_quo'] > 0]
            
            question_response_data[str(question_id)] = {
                'question_code': question.index_code,
                'question_text': question.measure,
                'category': question.category.name,
                'responses': responses_for_question,
                'response_count': len(responses_for_question),
                'priority_average': round(sum(valid_priorities) / len(valid_priorities), 2) if valid_priorities else 0,
                'status_quo_average': round(sum(valid_status_quos) / len(valid_status_quos), 2) if valid_status_quos else 0,
                'answered_count': len([r for r in responses_for_question if r['is_answered']])
            }
        
        return question_response_data
    def _calculate_stakeholder_group_category_averages_for_year(self, group, esg_year):
        """
        Calculate category averages for a stakeholder group for a specific ESG year
        """
        from django.db.models import Avg, Q
        
        # Get all responses from this group for the specific year
        responses = ESGQuestionResponse.objects.filter(
            question__year=esg_year,
            user__usr_stakeholder__group=group,
            questionnaire_type='stakeholder'
        ).select_related('question__category')
        
        if not responses.exists():
            return {}
        
        # Group responses by category and calculate averages
        category_averages = {}
        
        # Get all categories that have responses
        categories = responses.values_list('question__category__name', flat=True).distinct()
        
        for category_name in categories:
            category_responses = responses.filter(question__category__name=category_name)
            
            # Calculate averages for priority and status_quo
            priority_avg = category_responses.filter(
                priority__isnull=False, 
                priority__gt=0
            ).aggregate(avg=Avg('priority'))['avg']
            
            status_quo_avg = category_responses.filter(
                status_quo__isnull=False, 
                status_quo__gt=0
            ).aggregate(avg=Avg('status_quo'))['avg']
            
            category_averages[category_name] = {
                'priority_average': round(priority_avg, 2) if priority_avg else 0,
                'status_quo_average': round(status_quo_avg, 2) if status_quo_avg else 0,
                'response_count': category_responses.count()
            }
        
        return category_averages
    
    def _build_stakeholder_group_question_response(self, stakeholder_group, current_year, questions):
        """Build question response structure for a stakeholder group"""
        # Get all stakeholder users in this group
        stakeholder_users = User.objects.filter(
            usr_stakeholder__group=stakeholder_group,
            usr_stakeholder__status='approved'
        )

        if not stakeholder_users.exists():
            return {}

        # Get all responses from stakeholders in this group
        group_responses = ESGQuestionResponse.objects.filter(
            user__in=stakeholder_users,
            question__year=current_year,
            questionnaire_type='stakeholder',
            status='submitted'
        ).select_related('question', 'question__category')

        # Aggregate responses by question
        question_aggregates = {}
        for response in group_responses:
            question_id = response.question.id
            if question_id not in question_aggregates:
                question_aggregates[question_id] = {
                    'priorities': [],
                    'status_quos': [],
                    'comments': [],
                    'response_count': 0
                }
            
            if response.priority is not None and response.priority > 0:
                question_aggregates[question_id]['priorities'].append(response.priority)
            if response.status_quo is not None and response.status_quo > 0:
                question_aggregates[question_id]['status_quos'].append(response.status_quo)
            if response.comment:
                question_aggregates[question_id]['comments'].append(response.comment)
            
            question_aggregates[question_id]['response_count'] += 1

        # Build the structure similar to client admin question_response
        question_response = {}
        categories = ESGCategory.objects.filter(is_active=True).order_by('name')
        
        for category in categories:
            category_questions = questions.filter(category=category)
            question_response[category.name] = {
                'category_info': {
                    'id': str(category.id),
                    'name': category.name,
                    'display_name': category.display_name
                },
                'questions': []
            }
            
            for question in category_questions:
                aggregates = question_aggregates.get(question.id, {
                    'priorities': [],
                    'status_quos': [],
                    'comments': [],
                    'response_count': 0
                })
                
                # Calculate averages
                priority_avg = sum(aggregates['priorities']) / len(aggregates['priorities']) if aggregates['priorities'] else 0
                status_quo_avg = sum(aggregates['status_quos']) / len(aggregates['status_quos']) if aggregates['status_quos'] else 0
                
                # Get priority and status quo display values
                priority_display = None
                status_quo_display = None
                
                if priority_avg > 0:
                    priority_choices = dict(ESGQuestionResponse.PRIORITY_CHOICES)
                    priority_display = priority_choices.get(round(priority_avg), 'Not Started')
                
                if status_quo_avg > 0:
                    status_quo_choices = dict(ESGQuestionResponse.STATUS_QUO_CHOICES)
                    status_quo_display = status_quo_choices.get(round(status_quo_avg), 'Not Started')
                
                # Combine all comments
                combined_comments = ' | '.join(aggregates['comments']) if aggregates['comments'] else ''
                
                # Calculate completion score (simplified version)
                completion_score = 0.0
                if priority_avg > 0:
                    completion_score += 0.4
                if status_quo_avg > 0:
                    completion_score += 0.4
                if combined_comments:
                    completion_score += 0.2
                
                question_data = {
                    'question_id': str(question.id),
                    'index_code': question.index_code,
                    'measure': question.measure,
                    'question_description': question.desription or '',
                    'priority': round(priority_avg, 2) if priority_avg > 0 else None,
                    'status_quo': round(status_quo_avg, 2) if status_quo_avg > 0 else None,
                    'comment': combined_comments,
                    'priority_display': priority_display,
                    'status_quo_display': status_quo_display,
                    'completion_score': completion_score,
                    'response_count': aggregates['response_count'],  # Additional info: how many stakeholders responded
                    'status': 'aggregated'  # Indicate this is aggregated data
                }
                
                question_response[category.name]['questions'].append(question_data)

        return question_response
    
    #  ================================================================================
    #        2. START: STAKEHOLDER ANAYLSIS 
    #  ================================================================================
    # Add these methods to your ESGDashboardViewSet class

    # @action(detail=False, methods=['post'])
    # def create_stakeholder_group(self, request):
    #     """Create a new stakeholder group"""
    #     user = request.user
        
    #     # Get user's client
    #     try:
    #         client = user.client
    #     except AttributeError:
    #         return Response({'error': 'User is not associated with a client'}, 
    #                         status=status.HTTP_403_FORBIDDEN)

    #     name = request.data.get('name', '').strip()
    #     if not name:
    #         return Response({'error': 'Name is required'}, 
    #                         status=status.HTTP_400_BAD_REQUEST)

    #     # Check if group already exists
    #     if StakeholderGroup.objects.filter(client=client, name__iexact=name, is_active=True).exists():
    #         return Response({'error': 'Stakeholder group with this name already exists'}, 
    #                         status=status.HTTP_400_BAD_REQUEST)

    #     # Create the group
    #     group = StakeholderGroup.objects.create(
    #         client=client,
    #         name=name,
    #         is_active=True
    #     )

    #     return Response({
    #         'message': 'Stakeholder group created successfully',
    #         'group': {
    #             'id': str(group.id),
    #             'name': group.name,
    #             'display_name': group.name,
    #             'stakeholder_count': 0,
    #             'is_default': False,
    #             'has_responses': False,
    #             'invitation_link': group.get_invite_full_url()
    #         }
    #     }, status=status.HTTP_201_CREATED)
    def create_esg_responses_for_user(self, user):
        """
        Create ESGQuestionResponse records for a client admin user
        """
        # Get current ESG year
        current_year = ESGYear.get_current_year()
        
        if not current_year:
            logger.warning("No current ESG year found, skipping ESG response creation")
            return
        
        # Get all active ESG questions for the current year
        active_questions = ESGQuestion.objects.filter(
            year=current_year,
            is_active=True
        ).select_related('category')
        
        if not active_questions.exists():
            # logger.warning(f"No active ESG questions found for year {current_year.year}")
            return
        
        # Create ESGQuestionResponse records
        responses_to_create = []
        for question in active_questions:
            response = ESGQuestionResponse(
                question=question,
                user=user,
                questionnaire_type='stakeholder',
                status='draft'
            )
            responses_to_create.append(response)
        
        # Bulk create for better performance
        created_responses = ESGQuestionResponse.objects.bulk_create(
            responses_to_create, 
            ignore_conflicts=True
        )
        print(f"Created {len(responses_to_create)} ESG question responses for {user.email}")
        logger.info(f"Created {len(responses_to_create)} ESG question responses for {user.email}")
        return created_responses
    
    @action(detail=False, methods=['post'])
    def create_global_stakeholders_group(self, request):
        """Create a global stakeholder group to all clients"""
        login_user = request.user

        # Get user's client
        try:
            
            if login_user:
                if not login_user.role == "terramo_admin":
                    return Response(
                        {'error': 'Unauthorized access!'},
                        status=status.HTTP_403_FORBIDDEN
                    )
                else:
                    pass
        except AttributeError:
            return Response(
                {'error': 'User is not associated with a client'},
                status=status.HTTP_403_FORBIDDEN
            )

        name = (request.data.get('name') or '').strip()
        if not name:
            return Response(
                {'error': 'Name is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if group already exists (active)
        if StakeholderGroup.objects.filter(
            name__iexact=name, is_active=True, is_global=True
        ).exists():
            return Response(
                {'error': 'Stakeholder group with this name already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )

        
        try:
            # Create the group and record the creator
            group = StakeholderGroup.objects.create(
                name=name,
                created_by=login_user,          
                is_active=True,
                is_global=True,
            )
        except IntegrityError:
            # Handles rare race with unique_together
            return Response(
                {'error': 'A group with this name already exists.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response(
            {
                'message': 'Global Stakeholder group created successfully',
                'group': {
                    'id': str(group.id),
                    'name': group.name,
                    'display_name': group.name,
                    'is_default': False,
                    'invitation_link': group.get_invite_full_url(),
                }
            },
            status=status.HTTP_201_CREATED
        )

    @action(detail=False, methods=['post'])
    def create_stakeholder_group(self, request):
        """Create a new stakeholder group"""
        login_user = request.user

        # check if terramo admin
        
        
        # Get user's client
        try:
            client = login_user.client
        except AttributeError:
            return Response(
                {'error': 'User is not associated with a client'},
                status=status.HTTP_403_FORBIDDEN
            )

        name = (request.data.get('name') or '').strip()
        if not name:
            return Response(
                {'error': 'Name is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if group already exists (active)
        if StakeholderGroup.objects.filter(
            client=client, name__iexact=name, is_active=True
        ).exists():
            return Response(
                {'error': 'Stakeholder group with this name already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )

        
        try:
            # Create the group and record the creator
            group = StakeholderGroup.objects.create(
                client=client,
                name=name,
                created_by=login_user,          
                is_active=True
            )
        except IntegrityError:
            # Handles rare race with unique_together
            return Response(
                {'error': 'A group with this name already exists for this client'},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response(
            {
                'message': 'Stakeholder group created successfully',
                'group': {
                    'id': str(group.id),
                    'name': group.name,
                    'display_name': group.name,
                    'stakeholder_count': 0,
                    'is_default': False,
                    'has_responses': False,
                    'created_by': {          # 👇 handy creator info for the frontend (optional)
                        'id': login_user.id,
                        'email': getattr(login_user, 'email', ''),
                        'full_name': getattr(login_user, 'get_full_name', lambda: None)() or getattr(login_user, 'username', ''),
                    },
                    'invitation_link': group.get_invite_full_url(),
                }
            },
            status=status.HTTP_201_CREATED
        )
    @action(detail=False, methods=['post'])
    def create_stakeholder(self, request):
        """Create a new stakeholder in a group"""
        user = request.user
        
        # Get user's client
        try:
            client = user.client
        except AttributeError:
            return Response({'error': 'User is not associated with a client'}, 
                            status=status.HTTP_403_FORBIDDEN)

        group_id = request.data.get('group_id')
        email = request.data.get('email', '').strip()
        first_name = request.data.get('first_name', '').strip()
        last_name = request.data.get('last_name', '').strip()
        send_invitation = request.data.get('send_invitation', True)
        send_login_link = request.data.get('send_login_link', False)

        if not email:
            return Response({'error': 'Email is required'}, 
                            status=status.HTTP_400_BAD_REQUEST)

        if not group_id:
            return Response({'error': 'Group ID is required'}, 
                            status=status.HTTP_400_BAD_REQUEST)

        # Get the stakeholder group
        try:
            group = StakeholderGroup.objects.get(id=group_id, client=client, is_active=True)
        except StakeholderGroup.DoesNotExist:
            return Response({'error': 'Stakeholder group not found'}, 
                            status=status.HTTP_404_NOT_FOUND)

        # Check if stakeholder already exists in the company
        if Stakeholder.objects.filter(
            group__client=client, 
            email__iexact=email
        ).exists():
            return Response({'error': 'Stakeholder with this email already exists in this company'}, 
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                # Create the stakeholder
                stakeholder = Stakeholder.objects.create(
                    group=group,
                    email=email,
                    client=client,
                    first_name=first_name,
                    last_name=last_name,
                    status='approved',  # Default status
                    is_registered=True
                )

                # create user
                auto_pwd = get_random_string(32)  # Generate a random password
                user_obj = User.objects.create_user(
                    email=stakeholder.email,
                    first_name=stakeholder.first_name,
                    last_name=stakeholder.last_name,
                    password=auto_pwd,
                    role="stakeholder",   
                    client=stakeholder.group.client,
                    is_active=True,
                )

                print(f"--------- Stakeholder -{user_obj.first_name}")
                # create ESG responses for the user 
                self.create_esg_responses_for_user(user_obj)
                # send invitation emails
                # if send_invitation:
                #     send_invitation_email(stakeholder)
                # if send_login_link:
                #     send_login_link_email(stakeholder)
                print(f"--------- Stakeholder created successfully-{group.name}")
                return Response({
                    'message': 'Stakeholder created successfully',
                    'stakeholder': {
                        'id': stakeholder.id,
                        'email': stakeholder.email,
                        'first_name': stakeholder.first_name,
                        'last_name': stakeholder.last_name,
                        'status': stakeholder.status,
                        'group': group.name
                    }
                }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': f'Failed to create stakeholder: {str(e)}'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['get'], url_path='stakeholder-group/(?P<group_id>[^/.]+)/stakeholders')
    def get_group_stakeholders(self, request, group_id=None):
        """Get stakeholders for a specific group"""
        user = request.user
        client_id = request.query_params.get("client_id")

        # Get user's client
        # try:
        #     client = user.client
        # except AttributeError:
        #     return Response({'error': 'User is not associated with a client'}, 
        #                     status=status.HTTP_403_FORBIDDEN)
        try:
            # client = None
            if user.role == "terramo_admin":
                if not client_id:
                    return Response(
                        {"error": "Client id is required."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                # validate UUID format
                try:
                    UUID(str(client_id))  # will raise ValueError if not a valid UUID
                except ValueError:
                    return Response(
                        {"error": "Invalid client id format."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                client = Client.objects.filter(id=client_id).first()
                if not client:
                    return Response(
                        {"error": "Client not found."},
                        status=status.HTTP_404_NOT_FOUND
                    )
                
            else:
                try:
                    if client_id:
                        UUID(str(client_id))  # will raise ValueError if not a valid UUID
                except ValueError:
                    return Response(
                        {"error": "Invalid client id format."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                if client_id:
                    client = Client.objects.filter(id=client_id).first()
                    if user.client != client:
                        return Response(
                            {"error": f"You dont have permission to view this information."},
                            status=status.HTTP_403_FORBIDDEN
                        )
                client = user.client

        except AttributeError:
            return Response({'error': 'User is not associated with a client'}, 
                            status=status.HTTP_403_FORBIDDEN)
        # Get the stakeholder group
        try:
            group = StakeholderGroup.objects.get(id=group_id, is_active=True,disable_the_invitation=False)
            print(f"---------group-----",group)
        except StakeholderGroup.DoesNotExist:
            return Response({'error': 'Stakeholder group not found'}, 
                            status=status.HTTP_404_NOT_FOUND)

        # Get stakeholders in this group
        # if group.is_global:
        #     stakeholders = Stakeholder.objects.filter(
        #         group=group,
        #         status='approved',
        #         client=client,
        #     ).select_related('user').order_by('first_name', 'last_name', 'email')
        # else:
        print(f"---------id-----",group_id)
        stakeholders = Stakeholder.objects.filter(
            group__id=group_id,
            status='approved',
            client=client,
            group__disable_the_invitation=False
        ).select_related('user').order_by('first_name', 'last_name', 'email')

        print(f"stakeholders groups: {stakeholders.count()}")
        stakeholders_data = []
        for stakeholder in stakeholders:
            stakeholders_data.append({
                'id': stakeholder.id,
                'first_name': stakeholder.first_name,
                'last_name': stakeholder.last_name,
                'email': stakeholder.email,
                'status': stakeholder.status,
                'last_login': stakeholder.user.last_login if stakeholder.user else None,
                'is_registered': stakeholder.is_registered
            })

        return Response({
            'group': {
                'id': str(group.id),
                'name': group.name,
                'display_name': group.name
            },
            'stakeholders': stakeholders_data
        })

    @action(detail=False, methods=['delete'], url_path='stakeholder/(?P<stakeholder_id>[^/.]+)')
    def remove_stakeholder(self, request, stakeholder_id=None):
        """Remove a stakeholder from a group"""
        user = request.user
        
        # Get user's client
        try:
            client = user.client
        except AttributeError:
            return Response({'error': 'User is not associated with a client'}, 
                            status=status.HTTP_403_FORBIDDEN)

        try:
            stakeholder = Stakeholder.objects.get(
                id=stakeholder_id, 
                client=client
            )
            
            # Instead of deleting, mark as inactive or actually delete based on your business logic
            stakeholder.delete()  # or stakeholder.is_active = False; stakeholder.save()
            
            return Response({'message': 'Stakeholder removed successfully'})
            
        except Stakeholder.DoesNotExist:
            return Response({'error': 'Stakeholder not found'}, 
                            status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['post'])
    def copy_invitation_link(self, request):
        """Get invitation link for a stakeholder group"""
        user = request.user
        
        # Get user's client
        try:
            client = user.client
        except AttributeError:
            return Response({'error': 'User is not associated with a client'}, 
                            status=status.HTTP_403_FORBIDDEN)

        group_id = request.data.get('group_id')
        if not group_id:
            return Response({'error': 'Group ID is required'}, 
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            group = StakeholderGroup.objects.get(id=group_id, client=client, is_active=True)
            
            return Response({
                'invitation_link': group.get_invite_full_url(),
                'group_name': group.name
            })
            
        except StakeholderGroup.objects.DoesNotExist:
            return Response({'error': 'Stakeholder group not found'}, 
                            status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['patch'])
    def update_group_visibility(self, request):
        """Update stakeholder group visibility in analysis"""
        user = request.user
        
        # Get user's client
        try:
            client = user.client
        except AttributeError:
            return Response({'error': 'User is not associated with a client'}, 
                            status=status.HTTP_403_FORBIDDEN)

        group_visibilities = request.data.get('group_visibilities', {})
        
        if not isinstance(group_visibilities, dict):
            return Response({'error': 'Invalid group_visibilities format'}, 
                            status=status.HTTP_400_BAD_REQUEST)

        updated_groups = []
        
        try:
            with transaction.atomic():
                for group_id, is_visible in group_visibilities.items():
                    try:
                        group = StakeholderGroup.objects.get(
                            id=group_id, 
                            client=client, 
                            is_active=True
                        )
                        
                        # Don't allow disabling default groups
                        if not group.name == 'Management':  # Assuming 'Management' is default
                            # You might want to add a field like 'show_in_analysis' to your model
                            # For now, we'll just return the current state
                            updated_groups.append({
                                'id': str(group.id),
                                'name': group.name,
                                'is_visible': is_visible
                            })
                            
                    except StakeholderGroup.DoesNotExist:
                        continue

                return Response({
                    'message': 'Group visibilities updated successfully',
                    'updated_groups': updated_groups
                })
                
        except Exception as e:
            return Response({'error': f'Failed to update group visibilities: {str(e)}'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    #  ================================================================================
    #        2. END: STAKEHOLDER ANAYLSIS 
    #  ================================================================================
    
    @action(detail=False, methods=['post'])
    def test_send_mail(self, request):
        user_info = {
            'first_name': request.user.first_name,
            'company_name': request.user.client.company_name,
            'email': request.user.email,
            'role_display': 'Client Admin',
            'role': request.user.role,
            'invitee_email': request.user.client
        }

        role = 'client_admin'
        invite_url= 'http://localhost:5143/sample/dasd.com'
        inviter = {
            'email': 'terramo_admin@gmail.com',
            'name': 'Terramo Admin',
        }
        EmailService.send_invitation_email(user_info, inviter, role, invite_url)
        return Response({
            "success": "Email Sent!",
        }, status=status.HTTP_200_OK)