from rest_framework import serializers
from core_apps.products.models import Product


class ProductSerializer(serializers.ModelSerializer):
    """Basic product serializer for client-product relationships"""
    class Meta:
        model = Product
        fields = ['id', 'name', 'description', 'price']