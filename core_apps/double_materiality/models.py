from django.db import models

"""
*Model Navigation:
[1] DoubleMateriality Model

"""
# related models | outside models
from core_apps.clients.models import Client
from core_apps.authentication.models import Stakeholder, StakeholderGroup
from core_apps.user_auth.models import User 

# permissions
from core_apps.user_auth.permissions import permissions

# utils | config | emails
from core_apps.common.models import TimeStampedModel

class DoubleMateriality(TimeStampedModel):
    """DoubleMateriality Model that holds the core of data"""
    pass