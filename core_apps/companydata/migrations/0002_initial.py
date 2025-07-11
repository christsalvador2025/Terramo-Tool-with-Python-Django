# Generated by Django 4.2.15 on 2025-07-11 02:49

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("companydata", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="stakeholderuser",
            name="user",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="stakeholder_memberships",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="stakeholderinvitation",
            name="sent_by",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="stakeholderinvitation",
            name="stakeholder_group",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="invitations",
                to="companydata.stakeholdergroup",
            ),
        ),
        migrations.AddField(
            model_name="stakeholdergroup",
            name="company",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="stakeholder_groups",
                to="companydata.company",
            ),
        ),
        migrations.AddField(
            model_name="stakeholdergroup",
            name="created_by",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddIndex(
            model_name="product",
            index=models.Index(
                fields=["type", "is_active"], name="products_type_bc692b_idx"
            ),
        ),
        migrations.AddField(
            model_name="esgresponsecomment",
            name="response",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="comments",
                to="companydata.esgresponse",
            ),
        ),
        migrations.AddField(
            model_name="esgresponsecomment",
            name="user",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="esg_comments",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="esgresponse",
            name="company",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="esg_responses",
                to="companydata.company",
            ),
        ),
        migrations.AddField(
            model_name="esgresponse",
            name="question",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="responses",
                to="companydata.esgquestion",
            ),
        ),
        migrations.AddField(
            model_name="esgresponse",
            name="user",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="esg_responses",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="esgquestion",
            name="category",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="questions",
                to="companydata.esgcategory",
            ),
        ),
        migrations.AddIndex(
            model_name="esgcategory",
            index=models.Index(
                fields=["type", "is_active"], name="esg_categor_type_2aab0c_idx"
            ),
        ),
        migrations.AddField(
            model_name="companyproduct",
            name="company",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE, to="companydata.company"
            ),
        ),
        migrations.AddField(
            model_name="companyproduct",
            name="product",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE, to="companydata.product"
            ),
        ),
        migrations.AddField(
            model_name="company",
            name="created_by",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="created_companies",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="company",
            name="products",
            field=models.ManyToManyField(
                related_name="companies",
                through="companydata.CompanyProduct",
                to="companydata.product",
            ),
        ),
        migrations.AddField(
            model_name="auditlog",
            name="user",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="audit_logs",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddIndex(
            model_name="stakeholderuser",
            index=models.Index(
                fields=["stakeholder_group", "is_active"],
                name="companydata_stakeho_e75a6d_idx",
            ),
        ),
        migrations.AlterUniqueTogether(
            name="stakeholderuser",
            unique_together={("stakeholder_group", "user")},
        ),
        migrations.AddIndex(
            model_name="stakeholderinvitation",
            index=models.Index(fields=["token"], name="stakeholder_token_3fc5e9_idx"),
        ),
        migrations.AddIndex(
            model_name="stakeholderinvitation",
            index=models.Index(
                fields=["status", "expires_at"], name="stakeholder_status_c528a7_idx"
            ),
        ),
        migrations.AlterUniqueTogether(
            name="stakeholderinvitation",
            unique_together={("stakeholder_group", "email")},
        ),
        migrations.AddIndex(
            model_name="stakeholdergroup",
            index=models.Index(
                fields=["company", "is_active"], name="stakeholder_company_706423_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="stakeholdergroup",
            index=models.Index(
                fields=["invite_token"], name="stakeholder_invite__4aa0d9_idx"
            ),
        ),
        migrations.AlterUniqueTogether(
            name="stakeholdergroup",
            unique_together={("company", "name")},
        ),
        migrations.AddIndex(
            model_name="esgresponsecomment",
            index=models.Index(
                fields=["response", "created_at"], name="esg_respons_respons_72473f_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="esgresponse",
            index=models.Index(
                fields=["company", "question"], name="esg_respons_company_515b35_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="esgresponse",
            index=models.Index(
                fields=["user", "status"], name="esg_respons_user_id_31c9bd_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="esgresponse",
            index=models.Index(
                fields=["priority"], name="esg_respons_priorit_f38e77_idx"
            ),
        ),
        migrations.AlterUniqueTogether(
            name="esgresponse",
            unique_together={("company", "question", "user")},
        ),
        migrations.AddIndex(
            model_name="esgquestion",
            index=models.Index(
                fields=["category", "is_active"], name="esg_questio_categor_17719e_idx"
            ),
        ),
        migrations.AlterUniqueTogether(
            name="esgquestion",
            unique_together={("measure_key", "question_text")},
        ),
        migrations.AddIndex(
            model_name="companyproduct",
            index=models.Index(
                fields=["company", "is_active"], name="company_pro_company_31ff1d_idx"
            ),
        ),
        migrations.AlterUniqueTogether(
            name="companyproduct",
            unique_together={("company", "product")},
        ),
        migrations.AddIndex(
            model_name="company",
            index=models.Index(fields=["name"], name="companies_name_c7a1b3_idx"),
        ),
        migrations.AddIndex(
            model_name="company",
            index=models.Index(fields=["email"], name="companies_email_6c1508_idx"),
        ),
        migrations.AddIndex(
            model_name="company",
            index=models.Index(
                fields=["is_active"], name="companies_is_acti_e9a12b_idx"
            ),
        ),
        migrations.AlterUniqueTogether(
            name="company",
            unique_together={("name", "country")},
        ),
        migrations.AddIndex(
            model_name="auditlog",
            index=models.Index(
                fields=["user", "timestamp"], name="audit_logs_user_id_88267f_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="auditlog",
            index=models.Index(
                fields=["action", "timestamp"], name="audit_logs_action_474804_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="auditlog",
            index=models.Index(
                fields=["model_name", "object_id"], name="audit_logs_model_n_656046_idx"
            ),
        ),
    ]
