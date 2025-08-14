# # esg/urls.py
# from django.urls import path, include
# from rest_framework.routers import DefaultRouter
# from .views import (
#     ESGYearViewSet, ESGCategoryViewSet, ESGQuestionViewSet,
#     ESGQuestionResponseViewSet, ESGDashboardViewSet
# )

# router = DefaultRouter()
# router.register(r'years', ESGYearViewSet)
# router.register(r'categories', ESGCategoryViewSet)
# router.register(r'questions', ESGQuestionViewSet, basename='esgquestion')
# router.register(r'responses', ESGQuestionResponseViewSet, basename='esgquestionresponse')
# router.register(r'dashboard', ESGDashboardViewSet, basename='esgdashboard')

# urlpatterns = [
#     path('', include(router.urls)),
# ]

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ESGYearViewSet,
    ESGCategoryViewSet, 
    ESGQuestionViewSet,
    ESGDashboardViewSet,
    ESGQuestionResponseViewSet
)

router = DefaultRouter()
router.register(r'years', ESGYearViewSet)
router.register(r'categories', ESGCategoryViewSet)
router.register(r'questions', ESGQuestionViewSet, basename='esgquestion')
router.register(r'dashboard', ESGDashboardViewSet, basename='dashboard')
router.register(r'responses', ESGQuestionResponseViewSet, basename='responses')

app_name = 'esg'

urlpatterns = [
    path('api/', include(router.urls)),
]
