
from rest_framework import generics, filters

from rest_framework.permissions import IsAuthenticated, AllowAny
# from rest_framework.permissions import AllowAny
from core_apps.user_auth.permissions import IsClientAdmin, IsTerramoAdmin, IsClientAdminOrTerramoAdmin
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from loguru import logger

from .models import Product
from .serializers import (

    ProductSerializer
)


class ProductListView(generics.ListAPIView):
    """List all available products for client creation"""
    queryset = Product.objects.filter(is_active=True)  # Assuming Product has is_active field
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticated, IsClientAdminOrTerramoAdmin]
    # permission_classes = [AllowAny]
    pagination_class = None
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering = ['name']

    @method_decorator(cache_page(60 * 15, key_prefix=('products')))
    def list(self,request, *args, **kwargs):
        print("accessing .. cache")
        return super().list(request, *args, **kwargs)
    
    
    def get_queryset(self):
        import time
        time.sleep(1)
        logger.info("accessing .. cache")
        print("get_queryset .. cache")
        return super().get_queryset()