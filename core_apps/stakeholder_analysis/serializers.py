from rest_framework import serializers
from django.contrib.auth import get_user_model

from .models import Product
from datetime import datetime
import uuid

User = get_user_model()

class ProductSerializer(serializers.ModelSerializer):
    """Basic product serializer for client-product relationships"""
    class Meta:
        model = Product
        fields = ['id', 'name', 'description', 'price']  
