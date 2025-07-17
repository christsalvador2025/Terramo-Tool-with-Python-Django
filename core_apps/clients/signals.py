from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Client, DEFAULT_STAKEHOLDER_GROUP_NAMES
from core_apps.stakeholder_analysis.models import StakeholderGroup
from django.db import IntegrityError # To handle potential race conditions or unique_together issues

@receiver(post_save, sender=Client)
def create_default_stakeholder_groups(sender, instance, created, **kwargs):
    """
    Signal handler to create default stakeholder groups for a newly created company.
    """
    if created: # This ensures the code only runs when a NEW company is created, not on updates
        print(f"Creating default stakeholder groups for new company: {instance.company_name}")
        for group_name in DEFAULT_STAKEHOLDER_GROUP_NAMES:
            try:
                StakeholderGroup.objects.create(
                    client=instance,
                    name=group_name,
                    description=f"Default group for {group_name} of {instance.company_name}",
                    # created_by can be left null here if no specific admin user is tied to this automated creation
                    # Or, if you have a system user, you could try to get them:
                    # created_by=User.objects.get(username='system_admin_user') # Requires a system user
                )
            except IntegrityError:
                # This might happen if, somehow, a group with the same name already exists
                # for this company (e.g., if the signal was somehow triggered twice
                # before the first transaction completed, or if an admin manually
                # created one before the signal fired).
                print(f"Warning: Stakeholder group '{group_name}' already exists for company '{instance.company_name}'. Skipping.")
            except Exception as e:
                print(f"Error creating default stakeholder group '{group_name}' for company '{instance.company_name}': {e}")

