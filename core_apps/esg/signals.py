from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import ESGQuestionResponse
from django.core.cache import cache
import logging

logger = logging.getLogger(__name__)


# Option 1: Separate receivers (Recommended)
@receiver(post_save, sender=ESGQuestionResponse)
def invalidate_cache_on_save(sender, instance, **kwargs):
    """Invalidate cache when ESGQuestionResponse is saved"""
    try:
        print("Clearing product cache on save")
        logger.info(f"ESGQuestionResponse saved: {instance.id}, clearing cache")
        cache.delete_pattern('*clientadmin_stakeholder_analysis*')
    except Exception as e:
        logger.error(f"Error clearing cache on save: {e}")


@receiver(post_delete, sender=ESGQuestionResponse)
def invalidate_cache_on_delete(sender, instance, **kwargs):
    """Invalidate cache when ESGQuestionResponse is deleted"""
    try:
        print("Clearing product cache on delete")
        logger.info(f"ESGQuestionResponse deleted: {instance.id}, clearing cache")
        cache.delete_pattern('*clientadmin_stakeholder_analysis*')
    except Exception as e:
        logger.error(f"Error clearing cache on delete: {e}")


# # Option 2: Single function with manual connection (Alternative)
# def invalidate_product_cache(sender, instance, **kwargs):
#     """Invalidate product cache when ESGQuestionResponse changes"""
#     try:
#         print("Clearing product cache")
#         logger.info(f"ESGQuestionResponse changed: {instance.id}, clearing cache")
#         cache.delete_pattern('*clientadmin_stakeholder_analysis*')
#     except Exception as e:
#         logger.error(f"Error clearing cache: {e}")


# # Connect signals manually
# post_save.connect(invalidate_product_cache, sender=ESGQuestionResponse)
# post_delete.connect(invalidate_product_cache, sender=ESGQuestionResponse)


# # Option 3: Using dispatch_uid to prevent duplicate connections (Best practice)
# @receiver(post_save, sender=ESGQuestionResponse, dispatch_uid='esg_response_save_cache_clear')
# def invalidate_cache_on_save_with_uid(sender, instance, **kwargs):
#     """Invalidate cache when ESGQuestionResponse is saved"""
#     try:
#         print("Clearing product cache on save")
#         logger.info(f"ESGQuestionResponse saved: {instance.id}, clearing cache")
#         cache.delete_pattern('*clientadmin_stakeholder_analysis*')
#     except Exception as e:
#         logger.error(f"Error clearing cache on save: {e}")


# @receiver(post_delete, sender=ESGQuestionResponse, dispatch_uid='esg_response_delete_cache_clear')
# def invalidate_cache_on_delete_with_uid(sender, instance, **kwargs):
#     """Invalidate cache when ESGQuestionResponse is deleted"""
#     try:
#         print("Clearing product cache on delete")
#         logger.info(f"ESGQuestionResponse deleted: {instance.id}, clearing cache")
#         cache.delete_pattern('*clientadmin_stakeholder_analysis*')
#     except Exception as e:
#         logger.error(f"Error clearing cache on delete: {e}")