from os import getenv, path
from dotenv import load_dotenv
from .base import *  # noqa
from .base import BASE_DIR


prod_env_file = path.join(BASE_DIR, ".envs", ".env.production")

if path.isfile(prod_env_file):
    load_dotenv(prod_env_file)

SECRET_KEY = getenv("SECRET_KEY")

DEBUG = getenv("DEBUG")

SITE_NAME = getenv("SITE_NAME")

ADMINS = [("Terramo Admin", "terramoadmin@gmail.com")]

ALLOWED_HOSTS = [""]

ADMIN_URL = getenv("ADMIN_URL")

EMAIL_BACKEND = "djcelery_email.backends.CeleryEmailBackend"
EMAIL_HOST = getenv("EMAIL_HOST")
EMAIL_HOST_USER = getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = getenv("SMTP_MAILGUN_PASSWORD")
EMAIL_PORT = getenv("EMAIL_PORT")
EMAIL_USE_TLS = True
DEFAULT_FROM_EMAIL = getenv("DEFAULT_FROM_EMAIL")
DOMAIN = getenv("DOMAIN")
ADMIN_EMAIL = getenv("ADMIN_EMAIL")

MAX_UPLOAD_SIZE = 1 * 1024 * 1024

CSRF_TRUSTED_ORIGINS = ["", ""]

LOCKOUT_DURATION = timedelta(minutes=10)

LOGIN_ATTEMPTS = 3

OTP_EXPIRATION = timedelta(minutes=1)

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

SECURE_SSL_REDIRECT = getenv("SECURE_SSL_REDIRECT")

SESSION_COOKIE_SECURE = True

CSRF_COOKIE_SECURE = True

SECURE_HSTS_SECONDS = 300

SECURE_HSTS_INCLUDE_SUBDOMAINS = getenv("SECURE_HSTS_INCLUDE_SUBDOMAINS")

SECURE_HSTS_PRELOAD = getenv("SECURE_HSTS_PRELOAD", default=True)

SECURE_CONTENT_TYPE_NOSNIFF = getenv("SECURE_CONTENT_TYPE_NOSNIFF")

# LOGGING = {
#     "version": 1,
#     "disable_existing_loggers": False,
#     "handlers": {"loguru": {"class": "interceptor.InterceptHandler"}},
#     "root": {"handlers": ["loguru"], "level": "DEBUG"},
    
# }

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters":{"require_debug_false": {"()": "django.utils.log.RequireDebugFalse"}},
    "formatters": {
    "verbose": {
        "format": "%(levelname)s %(name)-12s %(asctime)s %(module)s %(process)d %(thread)d %(message)s"
    }
    },
    "handlers": {
        "mail_admins": {
            "level": "ERROR",
            "filters": ["require_debug_false"],
            "class": "django.utils.log.AdminEmailHandler",
        },
        "console": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        }
    },
    "root": {"level": "INFO", "handlers": ["console"]},
    "loggers": {
        "django.request": {
            "handlers": ["mail_admins"],
            "level": "ERROR",
            "propagate": True,
        },
        "django.security.DisallowedHost": {
            "handlers": ["console", "mail_admins"],
            "level": "ERROR",
            "propagate": True,
        },
    },


}