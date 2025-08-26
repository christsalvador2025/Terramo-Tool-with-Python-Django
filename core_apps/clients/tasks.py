from celery import shared_task
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import transaction
import logging


from core_apps.esg.models import ESGYear, ESGQuestion, ESGQuestionResponse
logger = logging.getLogger(__name__)
User = get_user_model()

@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def create_esg_responses_for_user(self, user_id, questionnaire_type='client_admin'):
    """
    Create ESGQuestionResponse records for a client admin user asynchronously.
    
    Args:
        user_id (int): ID of the user to create ESG responses for
        questionnaire_type (str): Type of questionnaire ('client_admin', etc.)
        
    Returns:
        dict: Result summary with success status and details
    """
    logger.info(f"---------executing celey {user_id}, {questionnaire_type}")
    print(f"---------executing celey {user_id}, {questionnaire_type}")
    try:
        with transaction.atomic():
            # Get the user
            try:
                user = User.objects.get(id=user_id)
                print(f"---------- tryy ------------{user}")
            except User.DoesNotExist:
                error_msg = f"User with id {user_id} does not exist"
                logger.error(error_msg)
                return {
                    'success': False,
                    'error': error_msg,
                    'user_id': user_id
                }
            
            # Get current ESG year
            current_year = ESGYear.get_current_year()
            
            if not current_year:
                warning_msg = "No current ESG year found, skipping ESG response creation"
                logger.warning(warning_msg)
                return {
                    'success': False,
                    'warning': warning_msg,
                    'user_id': user_id,
                    'user_email': getattr(user, 'email', 'N/A')
                }
            
            # Get all active ESG questions for the current year
            active_questions = ESGQuestion.objects.filter(
                year=current_year,
                is_active=True
            ).select_related('category')
            
            if not active_questions.exists():
                warning_msg = f"No active ESG questions found for year {current_year.year}"
                logger.warning(warning_msg)
                return {
                    'success': False,
                    'warning': warning_msg,
                    'user_id': user_id,
                    'user_email': getattr(user, 'email', 'N/A'),
                    'esg_year': current_year.year
                }
            
            # Check if responses already exist to avoid duplicates
            existing_responses = ESGQuestionResponse.objects.filter(
                user=user,
                question__year=current_year,
                questionnaire_type=questionnaire_type
            ).count()
            
            if existing_responses > 0:
                info_msg = f"ESG responses already exist for user {user_id} in year {current_year.year}"
                logger.info(info_msg)
                return {
                    'success': True,
                    'message': info_msg,
                    'user_id': user_id,
                    'user_email': getattr(user, 'email', 'N/A'),
                    'existing_responses_count': existing_responses,
                    'action': 'skipped_duplicate'
                }
            
            # Create ESGQuestionResponse records
            responses_to_create = []
            for question in active_questions:
                response = ESGQuestionResponse(
                    question=question,
                    user=user,
                    questionnaire_type=questionnaire_type,
                    status='draft'
                )
                responses_to_create.append(response)
            
            # Bulk create for better performance
            created_responses = ESGQuestionResponse.objects.bulk_create(
                responses_to_create, 
                ignore_conflicts=True
            )
            
            success_msg = f"Created {len(responses_to_create)} ESG question responses for {user.email}"
            print(success_msg)  # Keep the print for console output
            logger.info(success_msg)
            
            return {
                'success': True,
                'message': success_msg,
                'user_id': user_id,
                'user_email': getattr(user, 'email', 'N/A'),
                'responses_created': len(responses_to_create),
                'esg_year': current_year.year,
                'questionnaire_type': questionnaire_type
            }
            
    except Exception as exc:
        error_msg = f"Failed to create ESG responses for user {user_id}: {str(exc)}"
        logger.error(error_msg, exc_info=True)
        print(f"---------- errorr ------------{exc}")
        # Retry the task if it fails
        try:
            raise self.retry(exc=exc, countdown=60, max_retries=3)
        except self.MaxRetriesExceededError:
            final_error = f"Max retries exceeded for user {user_id}: {str(exc)}"
            logger.error(final_error)
            return {
                'success': False,
                'error': final_error,
                'user_id': user_id,
                'max_retries_exceeded': True
            }

@shared_task(bind=True)
def bulk_create_esg_responses_for_users(self, user_ids, questionnaire_type='client_admin'):
    """
    Create ESG responses for multiple users in bulk.
    
    Args:
        user_ids (list): List of user IDs
        questionnaire_type (str): Type of questionnaire
        
    Returns:
        dict: Results summary with detailed breakdown
    """
    results = {
        'success': [],
        'failed': [],
        'warnings': [],
        'total': len(user_ids),
        'questionnaire_type': questionnaire_type,
        'started_at': timezone.now().isoformat()
    }
    
    for user_id in user_ids:
        try:
            # Queue individual tasks for each user
            task_result = create_esg_responses_for_user.delay(user_id, questionnaire_type)
            results['success'].append({
                'user_id': user_id,
                'task_id': task_result.id,
                'status': 'queued'
            })
        except Exception as e:
            results['failed'].append({
                'user_id': user_id,
                'error': str(e)
            })
            logger.error(f"Failed to queue ESG response task for user {user_id}: {e}")
    
    summary_msg = (f"Bulk ESG response creation queued: {results['total']} users, "
                  f"{len(results['success'])} successful, {len(results['failed'])} failed")
    logger.info(summary_msg)
    
    results['summary'] = summary_msg
    results['completed_at'] = timezone.now().isoformat()
    
    return results

@shared_task(bind=True)
def recreate_esg_responses_for_user(self, user_id, questionnaire_type='client_admin', force=False):
    """
    Recreate ESG responses for a user (delete existing and create new ones).
    Useful for when ESG questions are updated.
    
    Args:
        user_id (int): ID of the user
        questionnaire_type (str): Type of questionnaire
        force (bool): If True, will delete existing responses even if they have data
        
    Returns:
        dict: Result summary
    """
    try:
        with transaction.atomic():
            user = User.objects.get(id=user_id)
            current_year = ESGYear.get_current_year()
            
            if not current_year:
                return {
                    'success': False,
                    'error': 'No current ESG year found',
                    'user_id': user_id
                }
            
            # Delete existing responses
            existing_responses = ESGQuestionResponse.objects.filter(
                user=user,
                question__year=current_year,
                questionnaire_type=questionnaire_type
            )
            
            if existing_responses.exists() and not force:
                # Check if any responses have been filled out
                filled_responses = existing_responses.exclude(status='draft').count()
                if filled_responses > 0:
                    return {
                        'success': False,
                        'error': f'User has {filled_responses} filled responses. Use force=True to override.',
                        'user_id': user_id,
                        'existing_responses': existing_responses.count()
                    }
            
            deleted_count = existing_responses.count()
            existing_responses.delete()
            
            # Create new responses using the existing task
            creation_result = create_esg_responses_for_user.delay(user_id, questionnaire_type)
            
            return {
                'success': True,
                'message': f'Recreated ESG responses for user {user_id}',
                'user_id': user_id,
                'deleted_responses': deleted_count,
                'creation_task_id': creation_result.id,
                'force_used': force
            }
            
    except User.DoesNotExist:
        return {
            'success': False,
            'error': f'User with id {user_id} does not exist',
            'user_id': user_id
        }
    except Exception as exc:
        logger.error(f"Failed to recreate ESG responses for user {user_id}: {exc}")
        return {
            'success': False,
            'error': str(exc),
            'user_id': user_id
        }

@shared_task
def sync_missing_esg_responses():
    """
    Periodic task to find users who should have ESG responses but don't,
    and create them. Useful for cleanup and ensuring data consistency.
    """
    try:
        current_year = ESGYear.get_current_year()
        if not current_year:
            return {'success': False, 'error': 'No current ESG year found'}
        
        # Find users who should have ESG responses but don't
        # Adjust this query based on your user model and business logic
        from django.db.models import Count
        
        # Example: Find client admin users without ESG responses for current year
        users_without_responses = User.objects.filter(
            # Add your filtering logic here, e.g.:
            # groups__name='client_admin',  # Adjust based on your user roles
            is_active=True
        ).annotate(
            response_count=Count('esgquestionresponse', 
                               filter=models.Q(esgquestionresponse__question__year=current_year))
        ).filter(response_count=0)
        
        if not users_without_responses.exists():
            return {
                'success': True,
                'message': 'All eligible users have ESG responses',
                'users_processed': 0
            }
        
        # Queue tasks for users without responses
        queued_tasks = []
        for user in users_without_responses[:100]:  # Limit to prevent overwhelming
            task = create_esg_responses_for_user.delay(user.id)
            queued_tasks.append({
                'user_id': user.id,
                'task_id': task.id
            })
        
        return {
            'success': True,
            'message': f'Queued ESG response creation for {len(queued_tasks)} users',
            'users_processed': len(queued_tasks),
            'tasks': queued_tasks
        }
        
    except Exception as e:
        logger.error(f"Sync missing ESG responses task failed: {e}")
        return {
            'success': False,
            'error': str(e)
        }