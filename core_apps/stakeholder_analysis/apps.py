from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

class StakeholderAnalysisConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core_apps.stakeholder_analysis"
    verbose_name = _("Stakeholder Analysis")

 