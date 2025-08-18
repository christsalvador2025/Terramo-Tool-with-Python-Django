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


"""
-----------------------------------------------------------------------------------
"""
# from rest_framework import viewsets, status, permissions
# from rest_framework.decorators import action
# from rest_framework.response import Response
# from django.shortcuts import get_object_or_404
# from django.db.models import Q, Avg, Count
# from django.db import transaction
# from django.contrib.auth import get_user_model
# from django.conf import settings
# from django.utils import timezone

# from .models import (
#     ESGYear, ESGCategory, ESGQuestion, ESGQuestionResponse,
#     ESGSurvey, ESGSurveyQuestion, StakeholderResponse,
#     ClientResponse, ESGAnalytics
# )
# from .serializers import (
#     ESGYearSerializer, ESGCategorySerializer, ESGQuestionSerializer,
#     ESGQuestionResponseSerializer, ESGSurveySerializer,
#     ESGSurveyQuestionSerializer, StakeholderResponseSerializer,
#     ClientResponseSerializer, ESGAnalyticsSerializer,
#     ESGDashboardSerializer, ESGChartDataSerializer,
#     StakeholderListSerializer, ClientListSerializer,
#     BulkESGResponseUpdateSerializer
# )
# from core_apps.authentication.models import Stakeholder
# from core_apps.clients.models import Client

# # User = get_user_model()
# User = settings.AUTH_USER_MODEL


# class ESGYearViewSet(viewsets.ModelViewSet):
#     queryset = ESGYear.objects.all()
#     serializer_class = ESGYearSerializer
#     permission_classes = [permissions.IsAuthenticated]

#     @action(detail=False, methods=['get'])
#     def current(self, request):
#         """Get current active ESG year"""
#         current_year = ESGYear.get_current_year()
#         if current_year:
#             serializer = self.get_serializer(current_year)
#             return Response(serializer.data)
#         return Response({'detail': 'No current year set'}, status=status.HTTP_404_NOT_FOUND)


# class ESGCategoryViewSet(viewsets.ModelViewSet):
#     queryset = ESGCategory.objects.filter(is_active=True)
#     serializer_class = ESGCategorySerializer
#     permission_classes = [permissions.IsAuthenticated]


# class ESGQuestionViewSet(viewsets.ModelViewSet):
#     serializer_class = ESGQuestionSerializer
#     permission_classes = [permissions.IsAuthenticated]

#     def get_queryset(self):
#         queryset = ESGQuestion.objects.filter(is_active=True)
#         year = self.request.query_params.get('year')
#         category = self.request.query_params.get('category')
        
#         if year:
#             queryset = queryset.filter(year__year=year)
#         if category:
#             queryset = queryset.filter(category__name=category)
            
#         return queryset.select_related('category', 'year').order_by('category', 'order', 'index_code')


# class ESGDashboardViewSet(viewsets.ViewSet):
#     """Main dashboard viewset handling different user roles"""
#     permission_classes = [permissions.IsAuthenticated]
#     pagination_class = None
#     @action(detail=False, methods=['get'])
#     def client_admin_dashboard(self, request):
#         """Dashboard for client admin users"""
#         user = request.user
        
#         # Get user's client
#         try:
#             client = user.client
#         except AttributeError:
#             return Response({'error': 'User is not associated with a client'}, 
#                           status=status.HTTP_403_FORBIDDEN)

#         # Get current year
#         current_year = ESGYear.get_current_year()
#         if not current_year:
#             return Response({'error': 'No current ESG year set'}, 
#                           status=status.HTTP_400_BAD_REQUEST)

#         # Get or create survey for client
#         survey, created = ESGSurvey.objects.get_or_create(
#             client=client,
#             year=current_year.year,
#             defaults={
#                 'title': f'ESG-Check - {current_year.year}',
#                 'created_by': user,
#                 'status': 'active'
#             }
#         )

#         # Get questions and responses
#         categories = ESGCategory.objects.filter(is_active=True).order_by('name')
#         questions = ESGQuestion.objects.filter(
#             year=current_year,
#             is_active=True
#         ).select_related('category').order_by('category', 'order', 'index_code')

#         # Get user's responses
#         user_responses = {}
#         responses = ESGQuestionResponse.objects.filter(
#             user=user,
#             question__year=current_year,
#             questionnaire_type='client_admin'
#         ).select_related('question')

#         for response in responses:
#             user_responses[response.question.id] = {
#                 'id': response.id,
#                 'priority': response.priority,
#                 'status_quo': response.status_quo,
#                 'comment': response.comment,
#                 'priority_display': response.get_priority_display(),
#                 'status_quo_display': response.get_status_quo_display(),
#                 'is_answered': response.is_answered,
#                 'completion_score': response.completion_score
#             }

#         # Create responses for questions without responses
#         questions_without_responses = questions.exclude(
#             id__in=user_responses.keys()
#         )
        
#         new_responses = []
#         for question in questions_without_responses:
#             new_responses.append(
#                 ESGQuestionResponse(
#                     question=question,
#                     user=user,
#                     questionnaire_type='client_admin'
#                 )
#             )
        
#         if new_responses:
#             ESGQuestionResponse.objects.bulk_create(new_responses)
#             # Refresh user_responses
#             for question in questions_without_responses:
#                 user_responses[question.id] = {
#                     'id': None,
#                     'priority': 0,
#                     'status_quo': 0,
#                     'comment': '',
#                     'priority_display': 'Not Started',
#                     'status_quo_display': 'Not Started',
#                     'is_answered': False,
#                     'completion_score': 0.0
#                 }

#         # Group questions by category
#         questions_by_category = {}
#         for category in categories:
#             category_questions = questions.filter(category=category)
#             questions_by_category[category.name] = {
#                 'category_info': ESGCategorySerializer(category).data,
#                 'questions': []
#             }
            
#             for question in category_questions:
#                 question_data = ESGQuestionSerializer(question).data
#                 question_data['user_response'] = user_responses.get(question.id, {})
#                 questions_by_category[category.name]['questions'].append(question_data)

#         # Calculate completion stats
#         total_questions = questions.count()
#         answered_questions = sum(1 for resp in user_responses.values() if resp['is_answered'])
#         completion_rate = (answered_questions / total_questions * 100) if total_questions > 0 else 0

#         return Response({
#             'survey': ESGSurveySerializer(survey).data,
#             'categories': ESGCategorySerializer(categories, many=True).data,
#             'questions_by_category': questions_by_category,
#             'completion_stats': {
#                 'total_questions': total_questions,
#                 'answered_questions': answered_questions,
#                 'completion_rate': round(completion_rate, 2)
#             },
#             'current_year': current_year.year
#         })

#     @action(detail=False, methods=['get'])
#     def stakeholder_dashboard(self, request):
#         """Dashboard for stakeholder users"""
#         user = request.user
        
#         # Get stakeholder
#         try:
#             stakeholder = Stakeholder.objects.get(user=user)
#         except Stakeholder.DoesNotExist:
#             return Response({'error': 'User is not a stakeholder'}, 
#                           status=status.HTTP_403_FORBIDDEN)

#         # Get client
#         # client = stakeholder.client
#         Userinfo = settings.AUTH_USER_MODEL
#         client = Userinfo.objects.get(stakeholder.email)
#         current_year = ESGYear.get_current_year()
#         if not current_year:
#             return Response({'error': 'No current ESG year set'}, 
#                           status=status.HTTP_400_BAD_REQUEST)

#         # Get survey
#         try:
#             survey = ESGSurvey.objects.get(client=client, year=current_year.year)
#         except ESGSurvey.DoesNotExist:
#             return Response({'error': 'No survey found for this client'}, 
#                           status=status.HTTP_404_NOT_FOUND)

#         # Get questions and responses
#         questions = ESGQuestion.objects.filter(
#             year=current_year,
#             is_active=True
#         ).select_related('category').order_by('category', 'order', 'index_code')

#         # Get stakeholder's responses
#         user_responses = {}
#         responses = ESGQuestionResponse.objects.filter(
#             user=user,
#             question__year=current_year,
#             questionnaire_type='stakeholder'
#         ).select_related('question')

#         for response in responses:
#             user_responses[response.question.id] = {
#                 'id': response.id,
#                 'priority': response.priority,
#                 'status_quo': response.status_quo,
#                 'comment': response.comment,
#                 'priority_display': response.get_priority_display(),
#                 'status_quo_display': response.get_status_quo_display(),
#                 'is_answered': response.is_answered,
#                 'completion_score': response.completion_score
#             }

#         # Create responses for questions without responses
#         questions_without_responses = questions.exclude(
#             id__in=user_responses.keys()
#         )
        
#         new_responses = []
#         for question in questions_without_responses:
#             new_responses.append(
#                 ESGQuestionResponse(
#                     question=question,
#                     user=user,
#                     questionnaire_type='stakeholder'
#                 )
#             )
        
#         if new_responses:
#             ESGQuestionResponse.objects.bulk_create(new_responses)

#         # Group questions by category
#         categories = ESGCategory.objects.filter(is_active=True).order_by('name')
#         questions_by_category = {}
#         for category in categories:
#             category_questions = questions.filter(category=category)
#             questions_by_category[category.name] = {
#                 'category_info': ESGCategorySerializer(category).data,
#                 'questions': []
#             }
            
#             for question in category_questions:
#                 question_data = ESGQuestionSerializer(question).data
#                 question_data['user_response'] = user_responses.get(question.id, {
#                     'priority': 0,
#                     'status_quo': 0,
#                     'comment': '',
#                     'priority_display': 'Not Started',
#                     'status_quo_display': 'Not Started',
#                     'is_answered': False
#                 })
#                 questions_by_category[category.name]['questions'].append(question_data)

#         return Response({
#             'survey': ESGSurveySerializer(survey).data,
#             'categories': ESGCategorySerializer(categories, many=True).data,
#             'questions_by_category': questions_by_category,
#             'stakeholder': StakeholderListSerializer(stakeholder).data,
#             'current_year': current_year.year
#         })

#     @action(detail=False, methods=['get'])
#     def admin_dashboard(self, request):
#         """Dashboard for Terrano admin users"""
#         if not request.user.role == "terramo_admin":
#             return Response({'error': 'Admin access required'}, 
#                           status=status.HTTP_403_FORBIDDEN)

#         current_year = ESGYear.get_current_year()
#         if not current_year:
#             return Response({'error': 'No current ESG year set'}, 
#                           status=status.HTTP_400_BAD_REQUEST)

#         # Get all clients and their surveys
#         clients = Client.objects.filter(is_active=True)
#         client_data = []

#         for client in clients:
#             try:
#                 survey = ESGSurvey.objects.get(client=client, year=current_year.year)
#                 # Calculate completion stats for this client
#                 total_questions = ESGQuestion.objects.filter(
#                     year=current_year, is_active=True
#                 ).count()
                
#                 completed_responses = ESGQuestionResponse.objects.filter(
#                     question__year=current_year,
#                     user__client=client,
#                     status='submitted'
#                 ).count()
                
#                 completion_rate = (completed_responses / total_questions * 100) if total_questions > 0 else 0
                
#                 client_data.append({
#                     'client': ClientListSerializer(client).data,
#                     'survey': ESGSurveySerializer(survey).data,
#                     'completion_rate': round(completion_rate, 2),
#                     'total_questions': total_questions,
#                     'completed_responses': completed_responses
#                 })
#             except ESGSurvey.DoesNotExist:
#                 client_data.append({
#                     'client': ClientListSerializer(client).data,
#                     'survey': None,
#                     'completion_rate': 0,
#                     'total_questions': 0,
#                     'completed_responses': 0
#                 })

#         return Response({
#             'clients': client_data,
#             'current_year': current_year.year,
#             'total_clients': clients.count()
#         })

#     @action(detail=False, methods=['get'], url_path='client/(?P<client_id>[^/.]+)')
#     def client_detail(self, request, client_id=None):
#         """Detailed view for a specific client (admin only)"""
#         if not request.user.is_staff:
#             return Response({'error': 'Admin access required'}, 
#                           status=status.HTTP_403_FORBIDDEN)

#         client = get_object_or_404(Client, id=client_id, is_active=True)
#         current_year = ESGYear.get_current_year()

#         try:
#             survey = ESGSurvey.objects.get(client=client, year=current_year.year)
#         except ESGSurvey.DoesNotExist:
#             return Response({'error': 'No survey found for this client'}, 
#                           status=status.HTTP_404_NOT_FOUND)

#         # Get questions grouped by category
#         categories = ESGCategory.objects.filter(is_active=True).order_by('name')
#         questions = ESGQuestion.objects.filter(
#             year=current_year,
#             is_active=True
#         ).select_related('category').order_by('category', 'order', 'index_code')

#         # Get all responses for this client
#         client_responses = ESGQuestionResponse.objects.filter(
#             question__year=current_year,
#             user__client=client
#         ).select_related('question', 'user')

#         # Group responses by question
#         responses_by_question = {}
#         for response in client_responses:
#             if response.question.id not in responses_by_question:
#                 responses_by_question[response.question.id] = []
#             responses_by_question[response.question.id].append({
#                 'user_email': response.user.email,
#                 'questionnaire_type': response.questionnaire_type,
#                 'priority': response.priority,
#                 'status_quo': response.status_quo,
#                 'comment': response.comment,
#                 'priority_display': response.get_priority_display(),
#                 'status_quo_display': response.get_status_quo_display(),
#                 'is_answered': response.is_answered
#             })

#         # Build category structure
#         questions_by_category = {}
#         for category in categories:
#             category_questions = questions.filter(category=category)
#             questions_by_category[category.name] = {
#                 'category_info': ESGCategorySerializer(category).data,
#                 'questions': []
#             }
            
#             for question in category_questions:
#                 question_data = ESGQuestionSerializer(question).data
#                 question_data['responses'] = responses_by_question.get(question.id, [])
#                 questions_by_category[category.name]['questions'].append(question_data)

#         return Response({
#             'client': ClientListSerializer(client).data,
#             'survey': ESGSurveySerializer(survey).data,
#             'categories': ESGCategorySerializer(categories, many=True).data,
#             'questions_by_category': questions_by_category,
#             'current_year': current_year.year
#         })

#     @action(detail=False, methods=['post'])
#     def bulk_update_responses(self, request):
#         """Bulk update ESG responses"""
#         serializer = BulkESGResponseUpdateSerializer(data=request.data)
#         if not serializer.is_valid():
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#         responses_data = serializer.validated_data['responses']
        
#         with transaction.atomic():
#             for response_data in responses_data:
#                 question_id = response_data['question_id']
#                 priority = response_data.get('priority', 0)
#                 status_quo = response_data.get('status_quo', 0)
#                 comment = response_data.get('comment', '')
                
#                 # Determine questionnaire type based on user role
#                 questionnaire_type = 'client_admin'
#                 try:
#                     stakeholder = Stakeholder.objects.get(user=request.user)
#                     questionnaire_type = 'stakeholder'
#                 except Stakeholder.DoesNotExist:
#                     pass

#                 # Update or create response
#                 response, created = ESGQuestionResponse.objects.update_or_create(
#                     question_id=question_id,
#                     user=request.user,
#                     questionnaire_type=questionnaire_type,
#                     defaults={
#                         'priority': priority,
#                         'status_quo': status_quo,
#                         'comment': comment,
#                         'status': 'draft' if priority == 0 and status_quo == 0 else 'submitted'
#                     }
#                 )

#         return Response({'message': 'Responses updated successfully'})

#     @action(detail=False, methods=['get'])
#     def chart_data(self, request):
#         """Get chart data for visualization"""
#         user = request.user
#         current_year = ESGYear.get_current_year()
        
#         # Determine user type and get appropriate responses
#         try:
#             stakeholder = Stakeholder.objects.get(user=user)
#             questionnaire_type = 'stakeholder'
#         except Stakeholder.DoesNotExist:
#             questionnaire_type = 'client_admin'

#         # Get responses
#         responses = ESGQuestionResponse.objects.filter(
#             user=user,
#             question__year=current_year,
#             questionnaire_type=questionnaire_type
#         ).select_related('question', 'question__category')

#         # Group by category
#         categories = ESGCategory.objects.filter(is_active=True).order_by('name')
#         chart_data = []
        
#         for category in categories:
#             category_responses = responses.filter(question__category=category)
#             questions_data = []
            
#             for response in category_responses:
#                 questions_data.append({
#                     'index_code': response.question.index_code,
#                     'measure': response.question.measure[:50] + '...' if len(response.question.measure) > 50 else response.question.measure,
#                     'priority': response.priority,
#                     'status_quo': response.status_quo,
#                     'priority_display': response.get_priority_display(),
#                     'status_quo_display': response.get_status_quo_display(),
#                     'comment': response.comment
#                 })
            
#             chart_data.append({
#                 'category': category.display_name,
#                 'questions': questions_data
#             })

#         return Response(chart_data)


# class ESGQuestionResponseViewSet(viewsets.ModelViewSet):
#     serializer_class = ESGQuestionResponseSerializer
#     permission_classes = [permissions.IsAuthenticated]

#     def get_queryset(self):
#         user = self.request.user
#         queryset = ESGQuestionResponse.objects.filter(user=user)
        
#         questionnaire_type = self.request.query_params.get('type')
#         if questionnaire_type:
#             queryset = queryset.filter(questionnaire_type=questionnaire_type)
            
#         return queryset.select_related('question', 'question__category', 'user')

#     def perform_create(self, serializer):
#         # Determine questionnaire type
#         questionnaire_type = 'client_admin'
#         try:
#             Stakeholder.objects.get(user=self.request.user)
#             questionnaire_type = 'stakeholder'
#         except Stakeholder.DoesNotExist:
#             pass
            
#         serializer.save(
#             user=self.request.user,
#             questionnaire_type=questionnaire_type
#         )

"""
-------------------------------------
"""

from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.db.models import Q, Avg, Count, F
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
from core_apps.authentication.models import Stakeholder, StakeholderGroup
from core_apps.clients.models import Client
from core_apps.user_auth.models import User
# User = settings.AUTH_USER_MODEL


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

    # @action(detail=False, methods=['get'])
    # def client_admin_dashboard(self, request):
    #     """Dashboard for client admin users"""
    #     user = request.user
        
    #     # Get user's client
    #     try:
    #         client = user.client
    #     except AttributeError:
    #         return Response({'error': 'User is not associated with a client'}, 
    #                       status=status.HTTP_403_FORBIDDEN)

    #     # Get current year
    #     current_year = ESGYear.get_current_year()
    #     if not current_year:
    #         return Response({'error': 'No current ESG year set'}, 
    #                       status=status.HTTP_400_BAD_REQUEST)

    #     # Get or create survey for client
    #     survey, created = ESGSurvey.objects.get_or_create(
    #         client=client,
    #         year=current_year.year,
    #         defaults={
    #             'title': f'ESG-Check - {current_year.year}',
    #             'created_by': user,
    #             'status': 'active'
    #         }
    #     )

    #     # Get questions and responses
    #     categories = ESGCategory.objects.filter(is_active=True).order_by('name')
    #     questions = ESGQuestion.objects.filter(
    #         year=current_year,
    #         is_active=True
    #     ).select_related('category').order_by('category', 'order', 'index_code')

    #     # Get user's responses
    #     user_responses = {}
    #     responses = ESGQuestionResponse.objects.filter(
    #         user=user,
    #         question__year=current_year,
    #         questionnaire_type='client_admin'
    #     ).select_related('question')

    #     for response in responses:
    #         user_responses[response.question.id] = {
    #             'id': response.id,
    #             'priority': response.priority,
    #             'status_quo': response.status_quo,
    #             'comment': response.comment,
    #             'priority_display': response.get_priority_display(),
    #             'status_quo_display': response.get_status_quo_display(),
    #             'is_answered': response.is_answered,
    #             'completion_score': response.completion_score
    #         }

    #     # Create responses for questions without responses
    #     questions_without_responses = questions.exclude(
    #         id__in=user_responses.keys()
    #     )
        
    #     new_responses = []
    #     for question in questions_without_responses:
    #         new_responses.append(
    #             ESGQuestionResponse(
    #                 question=question,
    #                 user=user,
    #                 questionnaire_type='client_admin'
    #             )
    #         )
        
    #     if new_responses:
    #         ESGQuestionResponse.objects.bulk_create(new_responses)
    #         # Refresh user_responses
    #         for question in questions_without_responses:
    #             user_responses[question.id] = {
    #                 'id': None,
    #                 'priority': 0,
    #                 'status_quo': 0,
    #                 'comment': '',
    #                 'priority_display': 'Not Started',
    #                 'status_quo_display': 'Not Started',
    #                 'is_answered': False,
    #                 'completion_score': 0.0
    #             }

    #     # Group questions by category
    #     questions_by_category = {}
    #     for category in categories:
    #         category_questions = questions.filter(category=category)
    #         questions_by_category[category.name] = {
    #             'category_info': ESGCategorySerializer(category).data,
    #             'questions': []
    #         }
            
    #         for question in category_questions:
    #             question_data = ESGQuestionSerializer(question).data
    #             question_data['user_response'] = user_responses.get(question.id, {})
    #             questions_by_category[category.name]['questions'].append(question_data)

    #     # Calculate completion stats
    #     total_questions = questions.count()
    #     answered_questions = sum(1 for resp in user_responses.values() if resp['is_answered'])
    #     completion_rate = (answered_questions / total_questions * 100) if total_questions > 0 else 0

    #     # Get client averages including this user's responses
    #     averages = self._calculate_client_averages(client, current_year)

    #     return Response({
    #         'survey': ESGSurveySerializer(survey).data,
    #         'categories': ESGCategorySerializer(categories, many=True).data,
    #         'questions_by_category': questions_by_category,
    #         'completion_stats': {
    #             'total_questions': total_questions,
    #             'answered_questions': answered_questions,
    #             'completion_rate': round(completion_rate, 2)
    #         },
    #         'client_averages': averages,
    #         'current_year': current_year.year
    #     })
    
    # @action(detail=False, methods=['get'])
    # def client_admin_dashboard(self, request):
    #     """Dashboard for client admin users"""
    #     user = request.user
        
    #     # Get user's client
    #     try:
    #         client = user.client
    #     except AttributeError:
    #         return Response({'error': 'User is not associated with a client'}, 
    #                         status=status.HTTP_403_FORBIDDEN)

    #     # Get current year
    #     current_year = ESGYear.get_current_year()
    #     if not current_year:
    #         return Response({'error': 'No current ESG year set'}, 
    #                         status=status.HTTP_400_BAD_REQUEST)

    #     # Get or create survey for client
    #     survey, created = ESGSurvey.objects.get_or_create(
    #         client=client,
    #         year=current_year.year,
    #         defaults={
    #             'title': f'ESG-Check - {current_year.year}',
    #             'created_by': user,
    #             'status': 'active'
    #         }
    #     )

    #     # Get questions and responses
    #     categories = ESGCategory.objects.filter(is_active=True).order_by('name')
    #     questions = ESGQuestion.objects.filter(
    #         year=current_year,
    #         is_active=True
    #     ).select_related('category').order_by('category', 'order', 'index_code')

    #     # Get user's responses
    #     user_responses = {}
    #     responses = ESGQuestionResponse.objects.filter(
    #         user=user,
    #         question__year=current_year,
    #         questionnaire_type='client_admin'
    #     ).select_related('question')

    #     for response in responses:
    #         user_responses[response.question.id] = {
    #             'id': response.id,
    #             'priority': response.priority,
    #             'status_quo': response.status_quo,
    #             'comment': response.comment,
    #             'priority_display': response.get_priority_display(),
    #             'status_quo_display': response.get_status_quo_display(),
    #             'is_answered': response.is_answered,
    #             'completion_score': response.completion_score
    #         }

    #     # Create responses for questions without responses
    #     questions_without_responses = questions.exclude(
    #         id__in=user_responses.keys()
    #     )
        
    #     new_responses = []
    #     for question in questions_without_responses:
    #         new_responses.append(
    #             ESGQuestionResponse(
    #                 question=question,
    #                 user=user,
    #                 questionnaire_type='client_admin'
    #             )
    #         )
        
    #     # FIX: Use `bulk_create` with `ignore_conflicts=True` to avoid the IntegrityError
    #     # This ensures that if a response was created between the .exclude() and .bulk_create() calls,
    #     # the database will simply ignore the new response instead of raising an error.
    #     if new_responses:
    #         ESGQuestionResponse.objects.bulk_create(new_responses, ignore_conflicts=True)
        
    #     # Re-fetch all responses after the bulk_create to get the complete and updated list
    #     # This is a safe way to ensure `user_responses` is fully up-to-date
    #     all_user_responses = ESGQuestionResponse.objects.filter(
    #         user=user,
    #         question__year=current_year,
    #         questionnaire_type='client_admin'
    #     ).select_related('question')

    #     user_responses = {
    #         response.question.id: {
    #             'id': response.id,
    #             'priority': response.priority,
    #             'status_quo': response.status_quo,
    #             'comment': response.comment,
    #             'priority_display': response.get_priority_display(),
    #             'status_quo_display': response.get_status_quo_display(),
    #             'is_answered': response.is_answered,
    #             'completion_score': response.completion_score
    #         } for response in all_user_responses
    #     }

    #     # Group questions by category
    #     questions_by_category = {}
    #     for category in categories:
    #         category_questions = questions.filter(category=category)
    #         questions_by_category[category.name] = {
    #             'category_info': ESGCategorySerializer(category).data,
    #             'questions': []
    #         }
            
    #         for question in category_questions:
    #             question_data = ESGQuestionSerializer(question).data
    #             question_data['user_response'] = user_responses.get(question.id, {})
    #             questions_by_category[category.name]['questions'].append(question_data)

    #     # Calculate completion stats
    #     total_questions = questions.count()
    #     answered_questions = sum(1 for resp in user_responses.values() if resp['is_answered'])
    #     completion_rate = (answered_questions / total_questions * 100) if total_questions > 0 else 0

    #     # Get client averages including this user's responses
    #     averages = self._calculate_client_averages(client, current_year)

    #     return Response({
    #         'survey': ESGSurveySerializer(survey).data,
    #         'categories': ESGCategorySerializer(categories, many=True).data,
    #         'questions_by_category': questions_by_category,
    #         'completion_stats': {
    #             'total_questions': total_questions,
    #             'answered_questions': answered_questions,
    #             'completion_rate': round(completion_rate, 2)
    #         },
    #         'client_averages': averages,
    #         'current_year': current_year.year
    #     })
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
                    user=request.user,            # ⚠️ lookup ONLY by (question, user)
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

        return Response({
            'client': {
                'id': str(client.id),
                'name': client.company_name
            },
            'year': current_year.year,
            'categories': category_averages,
            'question_response': question_response
        })

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

        client = stakeholder.group.client
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