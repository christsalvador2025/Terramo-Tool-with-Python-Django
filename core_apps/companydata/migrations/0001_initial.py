# Generated by Django 4.2.15 on 2025-07-11 02:49

from django.db import migrations, models
import django.db.models.deletion
import django_countries.fields
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="AuditLog",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "action",
                    models.CharField(
                        choices=[
                            ("create", "Create"),
                            ("update", "Update"),
                            ("delete", "Delete"),
                            ("login", "Login"),
                            ("logout", "Logout"),
                            ("invite_sent", "Invite Sent"),
                            ("response_submitted", "Response Submitted"),
                        ],
                        max_length=20,
                    ),
                ),
                ("model_name", models.CharField(max_length=50)),
                ("object_id", models.UUIDField(blank=True, null=True)),
                ("changes", models.JSONField(blank=True, default=dict)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.TextField(blank=True)),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "db_table": "audit_logs",
                "ordering": ["-timestamp"],
            },
        ),
        migrations.CreateModel(
            name="Company",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(max_length=200)),
                ("email", models.EmailField(max_length=254)),
                ("phone", models.CharField(blank=True, max_length=20)),
                ("address", models.TextField(blank=True)),
                ("contact_person_name", models.CharField(max_length=100)),
                ("contact_person_email", models.EmailField(max_length=254)),
                ("contact_person_phone", models.CharField(blank=True, max_length=20)),
                (
                    "country",
                    django_countries.fields.CountryField(
                        default="US", max_length=2, verbose_name="Country"
                    ),
                ),
                ("is_active", models.BooleanField(default=True)),
            ],
            options={
                "verbose_name_plural": "Companies",
                "db_table": "companies",
                "ordering": ["name", "email"],
            },
        ),
        migrations.CreateModel(
            name="CompanyProduct",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("purchased_at", models.DateTimeField(auto_now_add=True)),
                ("expires_at", models.DateTimeField(blank=True, null=True)),
                ("is_active", models.BooleanField(default=True)),
            ],
            options={
                "db_table": "company_products",
            },
        ),
        migrations.CreateModel(
            name="ESGCategory",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("name", models.CharField(max_length=100)),
                (
                    "type",
                    models.CharField(
                        choices=[
                            ("environmental", "Environmental"),
                            ("social", "Social"),
                            ("corporate_governance", "Corporate Governance"),
                        ],
                        max_length=30,
                    ),
                ),
                ("description", models.TextField(blank=True)),
                ("order", models.PositiveIntegerField(default=0)),
                ("is_active", models.BooleanField(default=True)),
            ],
            options={
                "verbose_name_plural": "ESG Categories",
                "db_table": "esg_categories",
                "ordering": ["order", "name"],
            },
        ),
        migrations.CreateModel(
            name="ESGQuestion",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "measure_key",
                    models.CharField(
                        blank=True, default=None, max_length=100, null=True
                    ),
                ),
                (
                    "question_text",
                    models.TextField(blank=True, default=None, null=True),
                ),
                (
                    "question_description",
                    models.TextField(blank=True, default=None, null=True),
                ),
                (
                    "question_type",
                    models.CharField(
                        choices=[
                            ("multiple_choice", "Multiple Choice"),
                            ("single_choice", "Single Choice"),
                            ("text", "Text"),
                            ("rating", "Rating"),
                            ("boolean", "Yes/No"),
                        ],
                        default="multiple_choice",
                        max_length=20,
                    ),
                ),
                ("options", models.JSONField(blank=True, default=list)),
                ("is_required", models.BooleanField(default=False)),
                ("is_active", models.BooleanField(default=True)),
            ],
            options={
                "db_table": "esg_questions",
                "ordering": ["category", "measure_key"],
            },
        ),
        migrations.CreateModel(
            name="ESGResponse",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("answer", models.JSONField()),
                (
                    "priority",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("low", "Low"),
                            ("medium", "Medium"),
                            ("high", "High"),
                            ("critical", "Critical"),
                        ],
                        max_length=10,
                        null=True,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("in_progress", "In Progress"),
                            ("completed", "Completed"),
                            ("reviewed", "Reviewed"),
                        ],
                        default="pending",
                        max_length=15,
                    ),
                ),
                ("comment", models.TextField(blank=True)),
            ],
            options={
                "db_table": "esg_responses",
            },
        ),
        migrations.CreateModel(
            name="ESGResponseComment",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("comment", models.TextField()),
                ("is_internal", models.BooleanField(default=False)),
            ],
            options={
                "db_table": "esg_response_comments",
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="Product",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(max_length=100)),
                (
                    "type",
                    models.CharField(
                        choices=[
                            ("esg_check", "ESG Check"),
                            ("stakeholder_analysis", "Stakeholder Analysis"),
                            ("double_materiality", "Double Materiality"),
                        ],
                        max_length=30,
                    ),
                ),
                ("description", models.TextField(blank=True)),
                (
                    "price",
                    models.DecimalField(
                        blank=True, decimal_places=2, max_digits=10, null=True
                    ),
                ),
                ("is_active", models.BooleanField(default=True)),
            ],
            options={
                "db_table": "products",
            },
        ),
        migrations.CreateModel(
            name="StakeholderGroup",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(max_length=100)),
                ("description", models.TextField(blank=True)),
                (
                    "invite_token",
                    models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
                ),
                ("is_active", models.BooleanField(default=True)),
            ],
            options={
                "db_table": "stakeholder_groups",
                "ordering": ["company"],
            },
        ),
        migrations.CreateModel(
            name="StakeholderInvitation",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("email", models.EmailField(max_length=254)),
                ("token", models.UUIDField(default=uuid.uuid4, unique=True)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("accepted", "Accepted"),
                            ("expired", "Expired"),
                        ],
                        default="pending",
                        max_length=10,
                    ),
                ),
                ("sent_at", models.DateTimeField(auto_now_add=True)),
                ("accepted_at", models.DateTimeField(blank=True, null=True)),
                ("expires_at", models.DateTimeField()),
            ],
            options={
                "db_table": "stakeholder_invitations",
            },
        ),
        migrations.CreateModel(
            name="StakeholderUser",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("joined_at", models.DateTimeField(auto_now_add=True)),
                ("is_active", models.BooleanField(default=True)),
                (
                    "stakeholder_group",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="stakeholder_users",
                        to="companydata.stakeholdergroup",
                    ),
                ),
            ],
        ),
    ]
