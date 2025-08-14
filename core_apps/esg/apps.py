from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

class EsgConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core_apps.esg"
    verbose_name = _("ESG")

 
 