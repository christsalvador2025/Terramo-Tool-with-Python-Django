import uuid
from typing import Any, Optional
from django.conf import settings  # Import settings!
# from django.contrib.auth import get_user_model # REMOVE THIS LINE
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import IntegrityError, models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

# User = get_user_model() # REMOVE THIS LINE


class TimeStampedModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True # cannot create table in db


class ContentView(TimeStampedModel):
    content_type = models.ForeignKey(
        ContentType, on_delete=models.CASCADE, verbose_name=_("Content Type")
    )
    object_id = models.UUIDField(verbose_name=_("Object ID"))
    content_object = GenericForeignKey("content_type", "object_id")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,  
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="content_views",
        verbose_name=_("User"),
    )
    viewer_ip = models.GenericIPAddressField(
        verbose_name=_("Viewer IP Address"),
        null=True,
        blank=True,
    )
    last_viewed = models.DateTimeField()

    class Meta:
        verbose_name = _("Content View")
        verbose_name_plural = _("Content Views")
        # Ensure 'user' is part of unique_together. If user can be null,
        # unique_together with null=True needs special handling in databases.
        # For SQLite/PostgreSQL, it works as expected (NULL != NULL).
        # For MySQL, you might need a custom constraint or partial index.
        unique_together = ["content_type", "object_id", "user", "viewer_ip"]


    def __str__(self) -> str:
        # To access user.get_full_name, you'd need the User model.
        # You can either get it locally, or just rely on the instance's methods.
        # This string conversion should be fine as self.user will be a User instance at runtime.
        return (
            f"{self.content_type} viewed by "
            f"{self.user.get_full_name() if self.user else 'Anonymous'} from IP {self.viewer_ip}"
        )

    @classmethod
    def record_view(
        cls, 
        content_object: Any, 
        user: Optional["settings.AUTH_USER_MODEL"], # <--- CHANGE THIS: Use string literal for type hint
        viewer_ip: Optional[str]
    ) -> None:
        # If you need to perform an isinstance check here, you would do this:
        # from django.contrib.auth import get_user_model
        # ActualUser = get_user_model()
        # if user and isinstance(user, ActualUser):
        #    pass
        
        content_type = ContentType.objects.get_for_model(content_object)
        try:
            view, created = cls.objects.get_or_create(
                content_type=content_type,
                object_id=content_object.id,
                # For `user` in `defaults`, it's an instance, so it's fine.
                defaults={
                    "user": user, 
                    "viewer_ip": viewer_ip,
                    "last_viewed": timezone.now(),
                },
            )
            if not created:
                view.last_viewed = timezone.now()
                view.save()
        except IntegrityError:
            pass