from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import ProductListView

app_name = 'products'

urlpatterns = [
  
    path('', ProductListView.as_view(), name='product-list'),
 
    
]