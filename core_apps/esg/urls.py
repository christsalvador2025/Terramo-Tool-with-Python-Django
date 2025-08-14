# esg/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ESGYearViewSet, ESGCategoryViewSet, ESGQuestionViewSet,
    ESGQuestionResponseViewSet, ESGDashboardViewSet
)

router = DefaultRouter()
router.register(r'years', ESGYearViewSet)
router.register(r'categories', ESGCategoryViewSet)
router.register(r'questions', ESGQuestionViewSet, basename='esgquestion')
router.register(r'responses', ESGQuestionResponseViewSet, basename='esgquestionresponse')
router.register(r'dashboard', ESGDashboardViewSet, basename='esgdashboard')

urlpatterns = [
    path('', include(router.urls)),
]

# Add to your main urls.py:
# path('api/esg/', include('esg.urls')),