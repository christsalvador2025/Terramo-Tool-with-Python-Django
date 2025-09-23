from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

class DoubleMaterialityConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core_apps.double_materiality"
    verbose_name = _("Double  Materiality")