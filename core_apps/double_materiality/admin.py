from django.contrib import admin
from .models import DoubleMaterialityIROAssessment, DoubleMaterialitySelectionIROAssessment, DoubleMaterialityStakeholders
# Register your models here.

@admin.register(DoubleMaterialityStakeholders)
class DoubleMaterialityStakeholdersAdmin(admin.ModelAdmin):
    pass

@admin.register(DoubleMaterialitySelectionIROAssessment)
class DoubleMaterialitySelectionIROAssessmentAdmin(admin.ModelAdmin):
    pass

@admin.register(DoubleMaterialityIROAssessment)
class DoubleMaterialityIROAssessmentAdmin(admin.ModelAdmin):
    list_display = [
        'client',
        'question',
        'punkte',
        'impact',
        'risk',
        'chance',
        'has_report',
    ]
