# esg/utils.py
from django.db.models import Count, Q, Avg
from .models import ESGQuestion, ESGQuestionResponse, ESGCategory


def get_esg_completion_stats(user=None, client=None, year=None):
    """Calculate ESG completion statistics"""
    
    questions_qs = ESGQuestion.objects.filter(is_active=True)
    responses_qs = ESGQuestionResponse.objects.all()
    
    if year:
        questions_qs = questions_qs.filter(year__year=year)
    
    if user:
        if user.role == 'stakeholder':
            questions_qs = questions_qs.filter(questionnaire_type='stakeholder')
            responses_qs = responses_qs.filter(user=user)
        elif user.role == 'client_admin':
            questions_qs = questions_qs.filter(questionnaire_type='client_admin')
            responses_qs = responses_qs.filter(user__client=user.client)
    elif client:
        responses_qs = responses_qs.filter(user__client=client)
    
    total_questions = questions_qs.count()
    answered_questions = responses_qs.exclude(
        Q(priority=0) & Q(status_quo=0) & Q(comment='')
    ).count()
    
    completion_rate = (answered_questions / total_questions * 100) if total_questions > 0 else 0
    
    return {
        'total_questions': total_questions,
        'answered_questions': answered_questions,
        'completion_rate': round(completion_rate, 2)
    }


def get_category_stats(user=None, client=None, year=None):
    """Get statistics by ESG category"""
    
    categories = ESGCategory.objects.filter(is_active=True)
    category_stats = []
    
    for category in categories:
        questions_qs = ESGQuestion.objects.filter(
            category=category,
            is_active=True
        )
        
        if year:
            questions_qs = questions_qs.filter(year__year=year)
        
        responses_qs = ESGQuestionResponse.objects.filter(
            question__in=questions_qs
        )
        
        if user:
            if user.role == 'stakeholder':
                questions_qs = questions_qs.filter(questionnaire_type='stakeholder')
                responses_qs = responses_qs.filter(user=user)
            elif user.role == 'client_admin':
                questions_qs = questions_qs.filter(questionnaire_type='client_admin')
                responses_qs = responses_qs.filter(user__client=user.client)
        elif client:
            responses_qs = responses_qs.filter(user__client=client)
        
        total_questions = questions_qs.count()
        answered_questions = responses_qs.exclude(
            Q(priority=0) & Q(status_quo=0) & Q(comment='')
        ).count()
        
        avg_priority = responses_qs.exclude(priority=0).aggregate(
            avg=Avg('priority')
        )['avg'] or 0
        
        avg_status_quo = responses_qs.exclude(status_quo=0).aggregate(
            avg=Avg('status_quo')
        )['avg'] or 0
        
        category_stats.append({
            'category': category.display_name,
            'total_questions': total_questions,
            'answered_questions': answered_questions,
            'completion_rate': (answered_questions / total_questions * 100) if total_questions > 0 else 0,
            'avg_priority': round(avg_priority, 2),
            'avg_status_quo': round(avg_status_quo, 2)
        })
    
    return category_stats


def generate_esg_report_data(client=None, year=None):
    """Generate data for ESG reports"""
    
    data = {
        'overview': get_esg_completion_stats(client=client, year=year),
        'category_breakdown': get_category_stats(client=client, year=year),
        'priority_distribution': {},
        'status_quo_distribution': {}
    }
    
    responses_qs = ESGQuestionResponse.objects.all()
    if client:
        responses_qs = responses_qs.filter(user__client=client)
    if year:
        responses_qs = responses_qs.filter(question__year__year=year)
    
    # Priority distribution
    for choice in ESGQuestionResponse.PRIORITY_CHOICES:
        count = responses_qs.filter(priority=choice[0]).count()
        data['priority_distribution'][choice[1]] = count
    
    # Status quo distribution
    for choice in ESGQuestionResponse.STATUS_QUO_CHOICES:
        count = responses_qs.filter(status_quo=choice[0]).count()
        data['status_quo_distribution'][choice[1]] = count
    
    return data