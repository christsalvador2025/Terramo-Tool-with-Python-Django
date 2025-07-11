from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

class CompanydataConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core_apps.companydata"
    verbose_name = _("CompanyData")

    def ready(self) -> None:
        import core_apps.companydata.signals