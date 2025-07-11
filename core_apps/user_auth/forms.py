from django.contrib.auth.forms import UserChangeForm as DjangoUserChangeForm
from django.contrib.auth.forms import UserCreationForm as DjangoUserCreationForm
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .models import User


class UserCreationForm(DjangoUserCreationForm):
    class Meta:
        model = User
        fields = [
            "email",
            "first_name",
            "middle_name",
            "last_name",
            # "is_company_admin",
            # "is_decision_maker",
            "is_staff",
            "is_superuser",
        ]

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if User.objects.filter(email=email).exists():
            raise ValidationError(_("A user with that email already exists."))
        return email

    def clean_id(self):
        id = self.cleaned_data.get("id")
        if User.objects.filter(id=id).exists():
            raise ValidationError(_("A user with that ID number already exists."))
        return id

  
    def save(self, commit=True):
        user = super().save(commit=False)
        if commit:
            user.save()
        return user


class UserChangeForm(DjangoUserChangeForm):
    class Meta:
        model = User
        fields = [
            "email",
            "first_name",
            "middle_name",
            "last_name",
            # "is_company_admin",
            # "is_decision_maker",
            "is_active",
            "is_staff",
            "is_superuser",
        ]

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if User.objects.exclude(pk=self.instance.pk).filter(email=email).exists():
            raise ValidationError(_("A user with that email already exists."))
        return email

    def clean_id_no(self):
        id = self.cleaned_data.get("id")
        if User.objects.exclude(pk=self.instance.pk).filter(id=id).exists():
            raise ValidationError(_("A user with that ID number already exists."))
        return id

    # def clean(self):
    #     cleaned_data = super().clean()
    #     is_superuser = cleaned_data.get("is_superuser")
    #     security_question = cleaned_data.get("security_question")
    #     security_answer = cleaned_data.get("security_answer")

    #     if not is_superuser:
    #         if not security_question:
    #             self.add_error(
    #                 "security_question",
    #                 _("Security question is required for regular users"),
    #             )
    #         if not security_answer:
    #             self.add_error(
    #                 "security_answer",
    #                 _("Security answer is required for regular users"),
    #             )
    #     return cleaned_data
