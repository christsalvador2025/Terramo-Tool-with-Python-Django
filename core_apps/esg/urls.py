# # # esg/urls.py
# # from django.urls import path, include
# # from rest_framework.routers import DefaultRouter
# # from .views import (
# #     ESGYearViewSet, ESGCategoryViewSet, ESGQuestionViewSet,
# #     ESGQuestionResponseViewSet, ESGDashboardViewSet
# # )

# # router = DefaultRouter()
# # router.register(r'years', ESGYearViewSet)
# # router.register(r'categories', ESGCategoryViewSet)
# # router.register(r'questions', ESGQuestionViewSet, basename='esgquestion')
# # router.register(r'responses', ESGQuestionResponseViewSet, basename='esgquestionresponse')
# # router.register(r'dashboard', ESGDashboardViewSet, basename='esgdashboard')

# # urlpatterns = [
# #     path('', include(router.urls)),
# # ]

# from django.urls import path, include
# from rest_framework.routers import DefaultRouter
# from .views import (
#     ESGYearViewSet,
#     ESGCategoryViewSet, 
#     ESGQuestionViewSet,
#     ESGDashboardViewSet,
#     ESGQuestionResponseViewSet
# )

# router = DefaultRouter()
# router.register(r'years', ESGYearViewSet)
# router.register(r'categories', ESGCategoryViewSet)
# router.register(r'questions', ESGQuestionViewSet, basename='esgquestion')
# router.register(r'dashboard', ESGDashboardViewSet, basename='dashboard')
# router.register(r'responses', ESGQuestionResponseViewSet, basename='responses')

# app_name = 'esg'

# urlpatterns = [
#     path('api/', include(router.urls)),
# ]


# from django.urls import path, include
# from rest_framework.routers import DefaultRouter
# from .views import (
#     ESGYearViewSet,
#     ESGCategoryViewSet, 
#     ESGQuestionViewSet,
#     ESGDashboardViewSet,
#     ESGQuestionResponseViewSet
# )

# router = DefaultRouter()
# router.register(r'years', ESGYearViewSet)
# router.register(r'categories', ESGCategoryViewSet)
# router.register(r'questions', ESGQuestionViewSet, basename='esgquestion')
# router.register(r'dashboard', ESGDashboardViewSet, basename='dashboard')
# router.register(r'responses', ESGQuestionResponseViewSet, basename='responses')

# app_name = 'esg'

# urlpatterns = [
#     path('', include(router.urls)),
# ]

# # Additional URL patterns if needed
# extra_patterns = [
#     # Dashboard endpoints
#     path('dashboard/client-admin/', ESGDashboardViewSet.as_view({'get': 'client_admin_dashboard'}), name='client-admin-dashboard'),
#     path('dashboard/stakeholder/', ESGDashboardViewSet.as_view({'get': 'stakeholder_dashboard'}), name='stakeholder-dashboard'),
#     path('dashboard/admin/', ESGDashboardViewSet.as_view({'get': 'admin_dashboard'}), name='admin-dashboard'),
#     path('dashboard/client/<uuid:client_id>/', ESGDashboardViewSet.as_view({'get': 'client_detail'}), name='client-detail'),
#     path('dashboard/chart-data/', ESGDashboardViewSet.as_view({'get': 'chart_data'}), name='chart-data'),
#     path('responses/bulk-update/', ESGDashboardViewSet.as_view({'post': 'bulk_update_responses'}), name='bulk-update-responses'),
# ]

# urlpatterns += extra_patterns

"""
###########################################################################################
TRACKING:
TO SEARCH THE CODE JUST COPY THE SPECIFIC LIST HERE AND CTRL + F = 
1. 
2. START: STAKEHOLDER ANALYSIS 
###########################################################################################
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ESGYearViewSet,
    ESGCategoryViewSet, 
    ESGQuestionViewSet,
    ESGDashboardViewSet,
    ESGQuestionResponseViewSet
)

# Create router and register viewsets
router = DefaultRouter()
router.register(r'years', ESGYearViewSet, basename='esg-years')
router.register(r'categories', ESGCategoryViewSet, basename='esg-categories')
router.register(r'questions', ESGQuestionViewSet, basename='esg-questions')
router.register(r'responses', ESGQuestionResponseViewSet, basename='esg-responses')
router.register(r'dashboard', ESGDashboardViewSet, basename='esg-dashboard')

urlpatterns = [
    path('', include(router.urls)),
    
    # Alternative explicit URL patterns if you prefer not to use router
    path('dashboard/admin/', ESGDashboardViewSet.as_view({'get': 'admin_dashboard'}), name='esg-admin-dashboard'),
    # path('dashboard/client-admin/', ESGDashboardViewSet.as_view({'get': 'client_admin_dashboard'}), name='esg-client-admin-dashboard'),
    path('dashboard/client-admin/', ESGDashboardViewSet.as_view({'get': 'client_admin_dashboard'}), name='esg-client-admin-dashboard'),
    # path('dashboard/stakeholder/', ESGDashboardViewSet.as_view({'get': 'stakeholder_dashboard'}), name='esg-stakeholder-dashboard'), stakeholderuser_dashboard
    path('dashboard/stakeholder/', ESGDashboardViewSet.as_view({'get': 'stakeholderuser_dashboard'}), name='esg-stakeholder-dashboard'),
    path('dashboard/client/<uuid:client_id>/', ESGDashboardViewSet.as_view({'get': 'stakeholderuser_dashboard'}), name='esg-client-detail'),
    path('dashboard/chart-data/', ESGDashboardViewSet.as_view({'get': 'chart_data'}), name='esg-chart-data'),
    path('dashboard/bulk-update/', ESGDashboardViewSet.as_view({'post': 'bulk_update_responses'}), name='esg-bulk-update'),
    path('dashboard/question-averages/', ESGDashboardViewSet.as_view({'get': 'question_averages'}), name='esg-question-averages'),
    
    # stakeholders analysis
    # path('dashboard/client-admin/stakeholders-analysis', ESGDashboardViewSet.as_view({'get': 'client_admin_stakeholder_analysis'}), name='esg-client-admin-dashboard'),
    path(
        'dashboard/client-admin/stakeholders-analysis/', 
        ESGDashboardViewSet.as_view({'get': 'client_admin_stakeholder_analysis'}), 
        name='esg-client-admin-stakeholders-analysis'
    ),

    # ===============================================================================
    #    2. START: STAKEHOLDER ANALYSIS 
    # ===============================================================================

    # Stakeholder Analysis URLs
    path(
        'dashboard/client-admin/stakeholders-analysis/', 
        ESGDashboardViewSet.as_view({'get': 'client_admin_stakeholder_analysis'}), 
        name='esg-client-admin-stakeholders-analysis'
    ),

    # Stakeholder Group Management URLs
    path(
        'dashboard/stakeholder-groups/create/', 
        ESGDashboardViewSet.as_view({'post': 'create_stakeholder_group'}), 
        name='create-stakeholder-group'
    ),

    path(
        'dashboard/stakeholder-groups/<str:group_id>/stakeholders/', 
        ESGDashboardViewSet.as_view({'get': 'get_group_stakeholders'}), 
        name='get-group-stakeholders'
    ),

    path(
        'dashboard/stakeholders/create/', 
        ESGDashboardViewSet.as_view({'post': 'create_stakeholder'}), 
        name='create-stakeholder'
    ),

    path(
        'dashboard/stakeholders/<str:stakeholder_id>/', 
        ESGDashboardViewSet.as_view({'delete': 'remove_stakeholder'}), 
        name='remove-stakeholder'
    ),

    path(
        'dashboard/invitation-link/', 
        ESGDashboardViewSet.as_view({'post': 'copy_invitation_link'}), 
        name='copy-invitation-link'
    ),

    path(
        'dashboard/group-visibility/', 
        ESGDashboardViewSet.as_view({'patch': 'update_group_visibility'}), 
        name='update-group-visibility'
    ),

    # ===============================================================================
    #    2. END: STAKEHOLDER ANALYSIS 
    # ===============================================================================
]

# The router will automatically generate these URLs:
"""
Generated URLs by the router:

ESG Years:
- GET /api/v1/esg/years/ - List all ESG years
- POST /api/v1/esg/years/ - Create new ESG year
- GET /api/v1/esg/years/{id}/ - Get specific ESG year
- PUT /api/v1/esg/years/{id}/ - Update ESG year
- PATCH /api/v1/esg/years/{id}/ - Partial update ESG year
- DELETE /api/v1/esg/years/{id}/ - Delete ESG year
- GET /api/v1/esg/years/current/ - Get current active year

ESG Categories:
- GET /api/v1/esg/categories/ - List all categories
- POST /api/v1/esg/categories/ - Create new category
- GET /api/v1/esg/categories/{id}/ - Get specific category
- PUT /api/v1/esg/categories/{id}/ - Update category
- PATCH /api/v1/esg/categories/{id}/ - Partial update category
- DELETE /api/v1/esg/categories/{id}/ - Delete category

ESG Questions:
- GET /api/v1/esg/questions/ - List questions (with filters: ?year=2025&category=Environment)
- POST /api/v1/esg/questions/ - Create new question
- GET /api/v1/esg/questions/{id}/ - Get specific question
- PUT /api/v1/esg/questions/{id}/ - Update question
- PATCH /api/v1/esg/questions/{id}/ - Partial update question
- DELETE /api/v1/esg/questions/{id}/ - Delete question

ESG Responses:
- GET /api/v1/esg/responses/ - List user's responses (with filter: ?type=stakeholder)
- POST /api/v1/esg/responses/ - Create new response
- GET /api/v1/esg/responses/{id}/ - Get specific response
- PUT /api/v1/esg/responses/{id}/ - Update response
- PATCH /api/v1/esg/responses/{id}/ - Partial update response
- DELETE /api/v1/esg/responses/{id}/ - Delete response

ESG Dashboard:
- GET /api/v1/esg/dashboard/admin_dashboard/ - Admin dashboard with client averages
- GET /api/v1/esg/dashboard/client_admin_dashboard/ - Client admin dashboard
- GET /api/v1/esg/dashboard/stakeholder_dashboard/ - Stakeholder dashboard
- GET /api/v1/esg/dashboard/client/{client_id}/ - Detailed client view (admin only)
- GET /api/v1/esg/dashboard/chart_data/ - Chart data for visualization
- POST /api/v1/esg/dashboard/bulk_update_responses/ - Bulk update responses
"""