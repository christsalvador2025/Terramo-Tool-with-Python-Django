
from django.conf import settings
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from core_apps.clients import views
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

URL_PREFIX = f"api/{settings.API_VERSION}" # url prefix with api version

urlpatterns = [
    path(settings.ADMIN_URL, admin.site.urls),
    path(f"{URL_PREFIX}/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        f"{URL_PREFIX}/schema/swagger-ui/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    path(
        f"{URL_PREFIX}/schema/redoc/",
        SpectacularRedocView.as_view(url_name="schema"),
        name="redoc",
    ),
    path(f"{URL_PREFIX}/auth/", include("djoser.urls")),
    # path("api/v1/auth/", include("core_apps.user_auth.urls")),
    # path(f"{URL_PREFIX}/terramo/", include("core_apps.user_auth.urls")),
    path("api/v1/auth/", include("core_apps.user_auth.urls")),
    path(f"api/v1/clients/", include("core_apps.clients.urls")),
    path(f"api/v1/products/", include("core_apps.products.urls")),
    
    # path(f"api/v1/clients/", include("core_apps.clients.urls")),
    # path('clients/create/', views.ClientCreateView.as_view(), name='client_create'),
    # path("api/v1/stakeholders/", include("core_apps.companydata.urls")),
    
]

admin.site.site_header = "Terramo Tool Admin"
admin.site.site_title = "Terramo Tool Admin Portal"
admin.site.index_title = "Welcome to Terramo Tool Admin Portal"