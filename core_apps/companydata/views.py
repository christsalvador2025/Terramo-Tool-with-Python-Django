# core_app/views.py

from django.db import transaction
from django.utils import timezone
from django.urls import reverse
from django.shortcuts import get_object_or_404, redirect
from django.contrib.auth import login, authenticate, get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from rest_framework import viewsets, mixins, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken # Assuming JWT for token generation
from rest_framework import serializers

from core_apps.common.permissions import IsCompanyAdmin, IsCompanyUser, IsOwnerOrAdmin, IsSuperAdmin, IsSameCompany
# Import your models
from .models import Company, Product, CompanyProduct, ESGCategory, ESGQuestion, \
                    StakeholderGroup, StakeholderUser, ESGResponse, \
                    ESGResponseComment, StakeholderInvitation, AuditLog

# Import your serializers
from .serializers import (
    AuthTokenSerializer,
    UserSerializer,
    CompanySerializer,
    StakeholderGroupSerializer,
    StakeholderInvitationSerializer,
    BulkStakeholderInvitationSerializer,
    ESGQuestionSerializer,
    ESGResponseSerializer,
    StakeholderRegisterSerializer,
    StakeholderUserSerializer
)
from django_filters.rest_framework import DjangoFilterBackend
User = get_user_model()

# --- Utility for building absolute URLs ---
def build_full_url(request, path):
    """Constructs a full absolute URL."""
    current_site = get_current_site(request)
    scheme = 'https' if request.is_secure() else 'http'
    return f"{scheme}://{current_site.domain}{path}"

# --- Authentication Views ---

class CustomAuthToken(APIView):
    permission_classes = [AllowAny]
    serializer_class = AuthTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': UserSerializer(user).data
        })


# --- Admin/Internal User ViewSets ---

class CompanyViewSet(viewsets.ModelViewSet):
    queryset = Company.objects.all()
    serializer_class = CompanySerializer
    permission_classes = [IsAuthenticated] # Ensures only logged-in users can access

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.role == User.UserRole.SUPER_ADMIN:
            return Company.objects.all()
        elif user.role == User.UserRole.COMPANY_ADMIN and user.company:
            # Company Admins can only see/manage their own company
            return Company.objects.filter(id=user.company.id)
        return Company.objects.none() # Other roles cannot access companies directly

    def perform_create(self, serializer):
        # Automatically set the 'created_by' field
        serializer.save(created_by=self.request.user)


class StakeholderGroupViewSet(viewsets.ModelViewSet):
    queryset = StakeholderGroup.objects.all()
    serializer_class = StakeholderGroupSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.role == User.UserRole.SUPER_ADMIN:
            return StakeholderGroup.objects.all()
        elif user.role == User.UserRole.COMPANY_ADMIN and user.company:
            # Company Admins can only see/manage groups for their own company
            return StakeholderGroup.objects.filter(company=user.company)
        return StakeholderGroup.objects.none()

    def perform_create(self, serializer):
        user = self.request.user
        if user.role == User.UserRole.COMPANY_ADMIN and user.company:
            # Company Admin creates groups for their own company
            serializer.save(company=user.company, created_by=user)
        elif user.is_superuser or user.role == User.UserRole.SUPER_ADMIN:
            # Super Admin must specify a company_id in the request data
            company_id = self.request.data.get('company')
            if not company_id:
                raise serializers.ValidationError({"company": "Company ID is required for Super Admins to create a group."})
            company = get_object_or_404(Company, id=company_id)
            serializer.save(company=company, created_by=user)
        else:
            raise serializers.ValidationError("You do not have permission to create stakeholder groups.")

    @action(detail=True, methods=['get'], permission_classes=[IsAuthenticated])
    def get_invite_link(self, request, pk=None):
        """
        Action to retrieve the general group invitation link (using group.invite_token).
        Only accessible by Super Admins or Company Admins for that company.
        """
        group = self.get_object() # Retrieves the StakeholderGroup instance
        user = request.user
        if not (user.is_superuser or user.role == User.UserRole.SUPER_ADMIN or \
                (user.role == User.UserRole.COMPANY_ADMIN and user.company == group.company)):
            return Response({"detail": "You do not have permission to view this group's invite link."},
                            status=status.HTTP_403_FORBIDDEN)

        # Use the general group invite token for this link
        join_path = reverse('stakeholder_group_join_handler', args=[str(group.invite_token)])
        full_invite_url = build_full_url(request, join_path)
        return Response({"invite_link": full_invite_url}, status=status.HTTP_200_OK)


class ESGQuestionViewSet(viewsets.ModelViewSet):
    queryset = ESGQuestion.objects.all()
    serializer_class = ESGQuestionSerializer
    permission_classes = [IsAuthenticated] # Adjust as per your admin roles for questions

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.role == User.UserRole.SUPER_ADMIN:
            return ESGQuestion.objects.all()
        # Company Admins can view/manage questions too for their context
        elif user.role == User.UserRole.COMPANY_ADMIN and user.company:
            return ESGQuestion.objects.filter(is_active=True) # Or relevant questions for company
        return ESGQuestion.objects.none()

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class ESGResponseViewSet(viewsets.ModelViewSet):
    queryset = ESGResponse.objects.all()
    serializer_class = ESGResponseSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.role == User.UserRole.SUPER_ADMIN:
            return ESGResponse.objects.all()
        elif user.role in [User.UserRole.COMPANY_ADMIN, User.UserRole.COMPANY_USER] and user.company:
            # Admins/Company Users can see responses for their company
            return ESGResponse.objects.filter(company=user.company)
        elif user.role == User.UserRole.STAKEHOLDER:
            # Stakeholders can only see their own responses
            return ESGResponse.objects.filter(user=user, company=user.company)
        return ESGResponse.objects.none()

    def perform_create(self, serializer):
        # When an ESGResponse is created via API (e.g., by a stakeholder), link to their user and company
        serializer.save(company=self.request.user.company, user=self.request.user)


# --- Stakeholder-Facing Views (Public or Stakeholder Role) ---

# 1. Handles the general group invitation link (less secure, but broadly shareable)
class StakeholderGroupJoinHandler(APIView):
    permission_classes = [AllowAny] # Anyone can access this link

    def get(self, request, token, format=None):
        """
        Handles the /join-group/<uuid:token>/ link.
        Validates the StakeholderGroup's invite_token and redirects.
        """
        try:
            stakeholder_group = StakeholderGroup.objects.get(invite_token=token, is_active=True)
        except StakeholderGroup.DoesNotExist:
            return Response({"detail": "Invalid or inactive group invitation link."},
                            status=status.HTTP_404_NOT_FOUND)

        # If the user is already authenticated as a Stakeholder
        if request.user.is_authenticated and request.user.role == User.UserRole.STAKEHOLDER:
            # Check if they are already part of this group
            StakeholderUser.objects.get_or_create(user=request.user, stakeholder_group=stakeholder_group)
            # Redirect to their dashboard or survey as they are already logged in
            return redirect(reverse('stakeholder_dashboard'))
        else:
            # Not authenticated or not a stakeholder, redirect to registration/login
            # Pass the group_id as a query parameter for the registration page to use
            return redirect(reverse('stakeholder_registration_login') + f'?group_id={str(stakeholder_group.id)}')


# 2. NEW: Handles the individual email invitation link (more secure)
class StakeholderIndividualInvitationHandler(APIView):
    permission_classes = [AllowAny] # Anyone can access this link

    def get(self, request, token, format=None):
        """
        Handles the /invite/<uuid:token>/ link from individual email invitations.
        Validates the StakeholderInvitation token and redirects.
        """
        try:
            invitation = StakeholderInvitation.objects.get(token=token, status=StakeholderInvitation.Status.PENDING)
            # Check if the invitation has expired
            if invitation.expires_at and invitation.expires_at < timezone.now():
                invitation.status = StakeholderInvitation.Status.EXPIRED # Update status
                invitation.save() # Save the status change
                return Response({"detail": "Invitation link has expired."},
                                status=status.HTTP_400_BAD_REQUEST)
        except StakeholderInvitation.DoesNotExist:
            return Response({"detail": "Invalid, used, or expired invitation link."},
                            status=status.HTTP_404_NOT_FOUND)

        # If user is already authenticated as a Stakeholder
        if request.user.is_authenticated and request.user.role == User.UserRole.STAKEHOLDER:
            # Ensure the authenticated user's email matches the invitation email for security
            if request.user.email.lower() != invitation.email.lower():
                return Response({"detail": "This invitation is not for your account. Please log out and use the correct account associated with this invitation."},
                                status=status.HTTP_403_FORBIDDEN)

            # If user is authenticated and matches, directly add them to the group
            StakeholderUser.objects.get_or_create(
                user=request.user,
                stakeholder_group=invitation.stakeholder_group
            )
            # Mark the individual invitation as accepted
            invitation.status = StakeholderInvitation.Status.ACCEPTED
            invitation.accepted_at = timezone.now()
            invitation.save()
            return redirect(reverse('stakeholder_dashboard')) # Redirect to stakeholder dashboard

        else:
            # Not authenticated, redirect to registration/login
            # Pass the individual invitation token as a query parameter
            return redirect(reverse('stakeholder_registration_login') + f'?invitation_token={str(invitation.token)}')


# 3. Combined Stakeholder Registration & Login View
class StakeholderRegistrationLoginView(APIView):
    permission_classes = [AllowAny] # Publicly accessible

    def get(self, request, format=None):
        """
        Handles GET requests to the registration/login page.
        Primarily used by frontend to pre-fill or guide based on query params.
        """
        group_id = request.query_params.get('group_id')
        invitation_token = request.query_params.get('invitation_token')

        if invitation_token:
            try:
                invitation = StakeholderInvitation.objects.get(token=invitation_token, status=StakeholderInvitation.Status.PENDING)
                if invitation.expires_at and invitation.expires_at < timezone.now():
                    return Response({"detail": "Invitation link has expired."}, status=status.HTTP_400_BAD_REQUEST)
                return Response({"message": f"Please register or log in to join '{invitation.stakeholder_group.name}' via invitation.", "invited_email": invitation.email},
                                status=status.HTTP_200_OK)
            except StakeholderInvitation.DoesNotExist:
                return Response({"detail": "Invalid, used, or expired invitation token."}, status=status.HTTP_404_NOT_FOUND)
        elif group_id:
            try:
                stakeholder_group = StakeholderGroup.objects.get(id=group_id, is_active=True)
                return Response({"message": f"Please register or log in to join the '{stakeholder_group.name}' group."},
                                status=status.HTTP_200_OK)
            except StakeholderGroup.DoesNotExist:
                return Response({"detail": "Invalid or inactive group ID."}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({"detail": "A 'group_id' or 'invitation_token' is required to access this page."}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, format=None):
        """
        Handles POST requests for both new stakeholder registration and existing stakeholder login.
        It uses the StakeholderRegisterSerializer for unified validation and creation.
        """
        # Pass request context to serializer for various validations (e.g., build_full_url if needed)
        serializer = StakeholderRegisterSerializer(data=request.data, context={'request': request})

        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']

            # Retrieve objects stored in serializer context during validation
            stakeholder_group = serializer.context['stakeholder_group']
            invitation = serializer.context.get('invitation') # Will be None if not an individual invite

            user_exists = User.objects.filter(email=email).first()

            if user_exists:
                # User exists, attempt to log them in
                user = authenticate(request=request, email=email, password=password)
                if user:
                    login(request, user) # Log the existing user in
                    # Ensure the existing user is linked to the group
                    StakeholderUser.objects.get_or_create(user=user, stakeholder_group=stakeholder_group)
                    if invitation:
                        # If an invitation was used, mark it as accepted
                        invitation.status = StakeholderInvitation.Status.ACCEPTED
                        invitation.accepted_at = timezone.now()
                        invitation.save()
                    return Response({"detail": "Login successful.", "user_id": user.id}, status=status.HTTP_200_OK)
                else:
                    return Response({"detail": "Invalid password for existing user."}, status=status.HTTP_400_BAD_REQUEST)
            else:
                # User does not exist, proceed with registration (handled by serializer.save())
                user = serializer.save() # This creates the User and StakeholderUser, and updates invitation status
                login(request, user) # Log the newly registered user in
                return Response({"detail": "Registration successful.", "user_id": user.id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# 4. Stakeholder Magic Link Request (for existing stakeholders to login without password)
class StakeholderMagicLoginRequest(APIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        email = request.data.get('email')
        if not email:
            return Response({"email": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Find a stakeholder user with the given email
            user = User.objects.get(email=email, role=User.UserRole.STAKEHOLDER)
        except User.DoesNotExist:
            # Respond generically to prevent email enumeration attacks
            return Response({"detail": "If an account with that email exists, a login link has been sent."},
                            status=status.HTTP_200_OK)

        from django.contrib.auth.tokens import default_token_generator
        token = default_token_generator.make_token(user) # Generate a secure, one-time token

        # Construct the magic login link
        login_path = reverse('stakeholder_magic_login_authenticate', args=[str(user.id), token])
        magic_link_url = build_full_url(request, login_path)

        try:
            subject = "Your Terramo Login Link"
            # Ensure you have 'emails/magic_login_email.html' template
            message = render_to_string('emails/magic_login_email.html', {
                'user': user,
                'magic_link_url': magic_link_url,
                'expiration_minutes': 30 # Inform user about token expiry
            })
            send_mail(
                subject,
                message, # Plain text message for non-HTML clients
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False, # Set to True in production to avoid exposing errors
                html_message=message # HTML message for rich email clients
            )
            return Response({"detail": "If an account with that email exists, a login link has been sent."},
                            status=status.HTTP_200_OK)
        except Exception as e:
            # Log the error (e.g., using Django's logging)
            print(f"Error sending magic link email to {email}: {e}")
            return Response({"detail": "An error occurred while sending the email. Please try again later."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# 5. Stakeholder Magic Link Authentication (completes login via token)
class StakeholderMagicLoginAuthenticate(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64, token, format=None):
        """
        Handles the magic login link by validating the token and logging in the user.
        """
        from django.utils.http import urlsafe_base64_decode
        from django.contrib.auth.tokens import default_token_generator

        try:
            # Decode the user ID from base64
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            # Token is valid, log the user in
            login(request, user)
            return redirect(reverse('stakeholder_dashboard')) # Redirect to stakeholder's dashboard
        else:
            # Invalid or expired token
            return Response({"detail": "The login link is invalid or has expired. Please request a new one."},
                            status=status.HTTP_400_BAD_REQUEST)


# 6. Stakeholder ESG Survey Access and Submission
class StakeholderESGSurveyView(APIView):
    permission_classes = [IsAuthenticated] # Only authenticated users can access survey

    def get(self, request, format=None):
        """
        Retrieves all active ESG questions for the stakeholder to answer.
        """
        user = request.user
        if not (user.is_authenticated and user.role == User.UserRole.STAKEHOLDER and user.company):
            return Response({"detail": "Access Denied: Not a valid stakeholder or missing company link."},
                            status=status.HTTP_403_FORBIDDEN)
        
        # Get active questions, ordered by category and question order
        questions = ESGQuestion.objects.filter(category__is_active=True, is_active=True).order_by('category__order', 'order')
        serializer = ESGQuestionSerializer(questions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        """
        Submits ESG survey responses from a stakeholder.
        Expects a list of response objects.
        """
        user = request.user
        if not (user.is_authenticated and user.role == User.UserRole.STAKEHOLDER and user.company):
            return Response({"detail": "Access Denied: Not a valid stakeholder or missing company link."},
                            status=status.HTTP_403_FORBIDDEN)
        
        responses_data = request.data
        if not isinstance(responses_data, list):
            return Response({"detail": "Expected a list of responses in the request body."}, status=status.HTTP_400_BAD_REQUEST)
        
        with transaction.atomic(): # Ensure all responses are saved or none
            created_responses = []
            for response_data in responses_data:
                question_id = response_data.get('question')
                if not question_id:
                    transaction.set_rollback(True)
                    return Response({"detail": "Question ID missing in one of the responses."}, status=status.HTTP_400_BAD_REQUEST)
                
                try:
                    question = ESGQuestion.objects.get(id=question_id)
                except ESGQuestion.DoesNotExist:
                    transaction.set_rollback(True)
                    return Response({"detail": f"Question with ID {question_id} not found."}, status=status.HTTP_404_NOT_FOUND)
                
                # Prepare data for serializer (ensure user and company are not client-provided)
                response_serializer = ESGResponseSerializer(
                    data={
                        'question': question_id,
                        'answer': response_data.get('answer'),
                        'priority': response_data.get('priority'),
                        'status': response_data.get('status', ESGResponse.Status.COMPLETED), # Default to COMPLETED
                        'comment': response_data.get('comment'),
                    },
                    context={'request': request} # Pass request context for serializer's create method
                )
                
                if response_serializer.is_valid():
                    # Check if a response for this question by this user/company already exists
                    existing_response = ESGResponse.objects.filter(
                        user=user, company=user.company, question=question
                    ).first()

                    if existing_response:
                        # Update existing response
                        response = response_serializer.update(existing_response, response_serializer.validated_data)
                    else:
                        # Create new response
                        response = response_serializer.save() # user and company are set in serializer's create()
                    created_responses.append(ESGResponseSerializer(response).data)
                else:
                    transaction.set_rollback(True) # Rollback if any single response is invalid
                    return Response(response_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({"detail": "Survey responses submitted successfully.", "responses": created_responses},
                        status=status.HTTP_201_CREATED)


# 7. Bulk Stakeholder Invitation Sending
class BulkStakeholderInvitationView(APIView):
    permission_classes = [IsAuthenticated] # Only authenticated users can send invitations

    def post(self, request, format=None):
        """
        Handles sending bulk invitations to multiple email addresses for a specific stakeholder group.
        Each invitation gets a unique token.
        """
        serializer = BulkStakeholderInvitationSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            emails_to_invite = serializer.validated_data['emails']
            expires_at = serializer.validated_data.get('expires_at')

            stakeholder_group = serializer.context['stakeholder_group_obj'] # Validated group object

            # Permission check: Only Super Admin or Company Admin for this group's company
            user = request.user
            if not (user.is_superuser or user.role == User.UserRole.SUPER_ADMIN or \
                    (user.role == User.UserRole.COMPANY_ADMIN and user.company == stakeholder_group.company)):
                return Response({"detail": "You do not have permission to invite stakeholders to this group."},
                                status=status.HTTP_403_FORBIDDEN)

            sent_count = 0
            failed_emails_info = [] # Store tuple (email, error_message)
            invited_ids = []

            # Use a transaction to ensure database consistency.
            # If any database operation fails, the entire batch will be rolled back.
            # Email sending happens within the transaction. If email fails, it will also rollback.
            # For high-volume production, consider using a task queue (like Celery) for email sending
            # *after* the invitations are committed to the DB, for better robustness.
            try:
                with transaction.atomic():
                    for email in emails_to_invite:
                        try:
                            # Create the StakeholderInvitation record for each email
                            invitation = StakeholderInvitation.objects.create(
                                stakeholder_group=stakeholder_group,
                                email=email,
                                expires_at=expires_at if expires_at else timezone.now() + timezone.timedelta(days=7), # Default 7 days
                                sent_by=user,
                                status=StakeholderInvitation.Status.PENDING # Initial status
                            )
                            invited_ids.append(str(invitation.id))

                            # Build the invitation link using the individual invitation's unique token
                            invite_path = reverse('stakeholder_individual_invitation_handler', args=[str(invitation.token)])
                            full_invite_url = build_full_url(request, invite_path)

                            # Prepare and send the email
                            subject = f"You're invited to join {stakeholder_group.company.name}'s {stakeholder_group.name} group on Terramo"
                            message_html = render_to_string('emails/group_invitation_email.html', {
                                'group_name': stakeholder_group.name,
                                'company_name': stakeholder_group.company.name,
                                'invite_link': full_invite_url,
                                'sender_name': user.get_full_name() or user.email,
                                'expiration_days': int((invitation.expires_at - timezone.now()).days) if invitation.expires_at else 7
                            })
                            message_plain = f"You're invited to join {stakeholder_group.company.name}'s {stakeholder_group.name} group on Terramo. Use this link: {full_invite_url}"

                            send_mail(
                                subject,
                                message_plain, # Plain text fallback
                                settings.DEFAULT_FROM_EMAIL,
                                [email],
                                fail_silently=False,
                                html_message=message_html
                            )
                            sent_count += 1
                            AuditLog.objects.create( # Log each successful send
                                user=user,
                                action=AuditLog.Action.INVITE_SENT,
                                model_name='StakeholderInvitation',
                                object_id=invitation.id,
                                changes={'email': email, 'group_id': str(stakeholder_group.id), 'invitation_token': str(invitation.token)}
                            )

                        except Exception as e:
                            # If email sending or invitation creation fails for this specific email
                            failed_emails_info.append({"email": email, "error": str(e)})
                            # If you want to rollback the entire transaction if *any* email fails,
                            # re-raise the exception or use transaction.set_rollback(True)
                            # For this consolidated code, we let the outer try-except handle global rollback.
                            raise # Re-raise to trigger the outer transaction rollback
            except Exception as e:
                # This block catches any exception during the atomic transaction,
                # ensuring a full rollback if any part failed (DB or email send).
                return Response({"detail": f"An error occurred during invitation processing. No invitations were sent to the database. Error: {e}", "failed_emails": failed_emails_info},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # If we reach here, the transaction was successful (or no exceptions occurred within atomic block)
            if failed_emails_info:
                # This case is less likely with the 'raise' inside the loop, unless send_mail fails silently or if
                # you remove the 'raise' to allow partial DB success for email failures.
                return Response(
                    {"detail": f"Successfully sent {sent_count} invitations. Failed to send to: {', '.join([f['email'] for f in failed_emails_info])}",
                     "sent_invitation_ids": invited_ids,
                     "failed_emails_details": failed_emails_info},
                    status=status.HTTP_207_MULTI_STATUS # Partial success
                )
            else:
                return Response(
                    {"detail": f"Successfully sent {sent_count} invitations.",
                     "sent_invitation_ids": invited_ids},
                    status=status.HTTP_200_OK
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


# -------------------------
class StakeholderInvitationCreateSerializer(serializers.ModelSerializer):
    emails = serializers.ListField(
        child=serializers.EmailField(),
        write_only=True
    )
    
    class Meta:
        model = StakeholderInvitation
        fields = ['stakeholder_group', 'emails']
    
    def create(self, validated_data):
        emails = validated_data.pop('emails')
        stakeholder_group = validated_data['stakeholder_group']
        sent_by = self.context['request'].user
        
        invitations = []
        for email in emails:
            invitation, created = StakeholderInvitation.objects.get_or_create(
                stakeholder_group=stakeholder_group,
                email=email,
                defaults={
                    'sent_by': sent_by,
                    'expires_at': timezone.now() + timedelta(days=7)
                }
            )
            if created:
                invitations.append(invitation)
        
        return invitations
    
class StakeholderInvitationViewSet(viewsets.ModelViewSet):
    serializer_class = StakeholderInvitationSerializer
    permission_classes = [IsCompanyAdmin]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['stakeholder_group', 'status']
    ordering = ['-sent_at']
    
    def get_queryset(self):
        user = self.request.user
        if user.role == 'super_admin':
            return StakeholderInvitation.objects.select_related('stakeholder_group', 'sent_by')
        else:
            return StakeholderInvitation.objects.filter(
                stakeholder_group__company=user.company
            ).select_related('stakeholder_group', 'sent_by')
    def get_queryset(self):
        # Your existing get_queryset implementation
        user = self.request.user
        if user.role == 'super_admin':
            return super().get_queryset().select_related('stakeholder_group', 'sent_by')
        else:
            return super().get_queryset().filter(
                stakeholder_group__company=user.company
            ).select_related('stakeholder_group', 'sent_by')
    def get_serializer_class(self):
        if self.action == 'create':
            return StakeholderInvitationCreateSerializer
        return StakeholderInvitationSerializer
    
    @action(detail=False, methods=['post'])
    def accept_invitation(self, request):
        token = request.data.get('token')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        email = request.data.get('email')
        password = request.data.get('password')
        
        try:
            invitation = StakeholderInvitation.objects.get(
                token=token,
                status='pending',
                expires_at__gt=timezone.now()
            )
        except StakeholderInvitation.DoesNotExist:
            return Response({'error': 'Invalid or expired invitation'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Create user
        # from django.contrib.auth import get_user_model
        # User = get_user_model()
        
        userobs = User.objects.create_user(
            username=email,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password,
            role='stakeholder',
            company=invitation.stakeholder_group.company
        )
        
        # Add user to stakeholder group
        StakeholderUser.objects.create(
            stakeholder_group=invitation.stakeholder_group,
            user=userobs
        )
        
        # Update invitation status
        invitation.status = 'accepted'
        invitation.accepted_at = timezone.now()
        invitation.save()
        
        return Response({
            'message': 'Invitation accepted successfully',
            'user_id': userobs.id,
            'group': invitation.stakeholder_group.name
        })


class StakeholderUserViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = StakeholderUser.objects.all()
    serializer_class = StakeholderUserSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['stakeholder_group', 'is_active']
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Super admins can see all stakeholder users
        if self.request.user.role == 'super_admin':
            return queryset
        
        # Company admins and users can only see their company's stakeholder users
        if self.request.user.company:
            return queryset.filter(stakeholder_group__company=self.request.user.company)
        
        return queryset.none()