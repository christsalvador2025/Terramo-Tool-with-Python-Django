from django.db import models

"""
*Model Navigation:
[1] DoubleMateriality Model

"""
# related models | outside models
from core_apps.clients.models import Client
from core_apps.esg.models import ESGQuestion, ESGQuestionResponse
from core_apps.authentication.models import Stakeholder, StakeholderGroup
from core_apps.user_auth.models import User 
 

# utils
from django.core.validators import MinValueValidator, MaxValueValidator

# permissions
from core_apps.user_auth.permissions import permissions

# utils | config | emails
from core_apps.common.models import TimeStampedModel

class DoubleMaterialityStakeholders(TimeStampedModel):
    """Doppelte Wesentlichkeit | DoubleMateriality Model for step 1
    Original Text: Auswahl Stakeholder
    English Translation: Stakeholder selection
    """
    client = models.ForeignKey(Client,on_delete=models.CASCADE, null=False, blank=False, related_name="doublemateriality_stakehoders_client")
    stakeholder = models.ForeignKey(Stakeholder,on_delete=models.CASCADE,null=False, blank=False,related_name="doublemateriality_stakehoders_stakeholder")
    is_included = models.BooleanField(default=False)
    weighting = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(3)], default=1)
    justification = models.TextField(max_length=600, null=True, blank=True)

    class Meta:
 
        ordering = ['client']
        # unique_together = ["company_name", "land"]
        indexes = [
            models.Index(fields=['client']),
        ]
    
    def __str__(self):
        return self.client.company_name


class DoubleMaterialitySelectionIROAssessment(TimeStampedModel):
    """
    Doppelte Wesentlichkeit | Auswahl für IRO-Bewertung | DoubleMateriality Model for step 2
    Original Text: Auswahl für IRO-Bewertung
    English Translation: Selection for IRO assessment or Selection for IRO evaluation
    """
    client = models.ForeignKey(Client,on_delete=models.CASCADE, null=False, blank=False, related_name="doublemateriality_selection_iro_assessment_client")
    question = models.ForeignKey(ESGQuestion,on_delete=models.CASCADE, null=False, blank=False, related_name="doublemateriality_selection_iro_assessment_question")
    punkte_rt = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(3)], default=None,null=False, blank=False, help_text="Score RT ( Choose from 1 to 3)")
    punkte_sh = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(3)], default=None,null=False, blank=False, help_text="Score SH ( Choose from 1 to 3)")
    relevant = models.BooleanField(default=False)
    justification = models.TextField(max_length=600, null=True, blank=True)

    class Meta:
 
        ordering = ['client']
        # unique_together = ["company_name", "land"]
        indexes = [
            models.Index(fields=['client']),
        ]
    
    def __str__(self):
        return self.client.company_name
    

class DoubleMaterialityIROAssessment(TimeStampedModel):
    """
    Doppelte Wesentlichkeit | IRO-Bewertung | DoubleMateriality Model for step 3
    Original Text: Auswahl für IRO-Bewertung
    English Translation: IRO assessment or IRO evaluation
    """
    client = models.ForeignKey(Client,on_delete=models.CASCADE, null=False, blank=False, related_name="doublemateriality_iro_assessment_client")
    question = models.ForeignKey(ESGQuestion,on_delete=models.CASCADE, null=False, blank=False, related_name="doublemateriality_iro_assessment_question")
    punkte = models.FloatField(help_text="Punkte or Score", null=False, blank=False,)
    impact = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(10)], default=1, help_text="Impact ( Choose from 1 to 10)")
    risk = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(10)], default=1, help_text="Risk ( Choose from 1 to 10)")
    chance = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(10)], default=1, help_text="Chance ( Choose from 1 to 10)")
    has_report = models.BooleanField(default=False)
    justification = models.TextField(max_length=600, null=True, blank=True)

    class Meta:
 
        ordering = ['client']
        # unique_together = ["company_name", "land"]
        indexes = [
            models.Index(fields=['client']),
        ]
    
    def __str__(self):
        return self.client.company_name