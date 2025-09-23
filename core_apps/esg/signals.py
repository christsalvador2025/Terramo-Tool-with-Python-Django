from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import ESGQuestionResponse
from django.core.cache import cache
from django.conf import settings
import logging

logger = logging.getLogger(__name__)
print(f"Using cache backend: {cache.__class__.__name__}")
def clear_stakeholder_analysis_cache():
    """Clear stakeholder analysis cache in a backend-agnostic way"""
    try:
        # Check if we're using Redis cache
        if hasattr(cache, 'delete_pattern'):
            # Redis backend - use pattern matching
            cache.delete_pattern('*clientadmin_stakeholder_analysis*')
            logger.info("Cleared cache using delete_pattern")
        else:
            # Fallback for other backends (like LocMemCache)
            # Generate possible cache keys to clear
            # This assumes your cache keys follow a predictable pattern
            
            # Import models to get active years and clients
            from .models import ESGYear
            from django.contrib.auth import get_user_model
            
            User = get_user_model()
            cache_keys_to_clear = []
            
            # Generate cache keys for all possible combinations
            active_years = ESGYear.objects.filter(is_active=True)
            users = User.objects.filter(client__isnull=False)
            
            for year in active_years:
                for user in users:
                    # Match the pattern used in your cache_page decorator
                    cache_key = f"views.decorators.cache.cache_page.clientadmin_stakeholder_analysis.{user.id}.{year.year}"
                    cache_keys_to_clear.append(cache_key)
            
            if cache_keys_to_clear:
                cache.delete_many(cache_keys_to_clear)
                logger.info(f"Cleared {len(cache_keys_to_clear)} specific cache keys")
            else:
                # Last resort - clear all cache
                cache.clear()
                logger.info("Cleared entire cache (fallback method)")
            
    except Exception as e:
        logger.error(f"Error clearing stakeholder analysis cache: {e}")

@receiver(post_save, sender=ESGQuestionResponse)
def invalidate_cache_on_save(sender, instance, **kwargs):
    """Invalidate cache when ESGQuestionResponse is saved"""
    print("Clearing product cache on save")
    logger.info(f"ESGQuestionResponse saved: {instance.id}, clearing cache")
    clear_stakeholder_analysis_cache()

@receiver(post_delete, sender=ESGQuestionResponse)
def invalidate_cache_on_delete(sender, instance, **kwargs):
    """Invalidate cache when ESGQuestionResponse is deleted"""
    print("Clearing product cache on delete")
    logger.info(f"ESGQuestionResponse deleted: {instance.id}, clearing cache")
    clear_stakeholder_analysis_cache()