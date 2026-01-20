from pathlib import Path
import os
from dotenv import load_dotenv
import dj_database_url
from django.core.exceptions import ImproperlyConfigured

# =====================================================
# Base Directory
# =====================================================
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables (local development only)
load_dotenv(BASE_DIR / ".env")

# =====================================================
# Helper for required environment variables
# =====================================================
def get_env(name, default=None, required=False):
    value = os.getenv(name, default)
    if required and value is None:
        raise ImproperlyConfigured(f"Missing required environment variable: {name}")
    return value

# =====================================================
# Core Security Settings
# =====================================================
SECRET_KEY = get_env("SECRET_KEY", required=True)

DEBUG = get_env("DEBUG", "False") == "True"

ALLOWED_HOSTS = get_env(
    "ALLOWED_HOSTS",
    "localhost,127.0.0.1,.vercel.app"
).split(",")

# =====================================================
# Application Definition
# =====================================================
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third-party
    'rest_framework',
    'rest_framework.authtoken',
    'corsheaders',
    'whitenoise.runserver_nostatic',

    # Local
    'api',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# =====================================================
# CORS Configuration
# =====================================================
CORS_ALLOW_ALL_ORIGINS = True

CORS_ALLOWED_ORIGINS = [
  
]

# =====================================================
# Authentication & REST Framework
# =====================================================
AUTH_USER_MODEL = 'api.User'

AUTHENTICATION_BACKENDS = [
    'api.backends.EmailBackend',
    'django.contrib.auth.backends.ModelBackend',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ],
}

# =====================================================
# Database Configuration (Supabase / PostgreSQL)
# =====================================================
DATABASES = {
    'default': dj_database_url.config(
        default=get_env("DATABASE_URL", required=True),
        conn_max_age=600,
        conn_health_checks=True,
        ssl_require=True,
    )
}

DATABASES['default']['OPTIONS'] = {
    'sslmode': 'require',
}

# =====================================================
# Email Configuration (Primary)
# =====================================================
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = get_env("GMAIL_USER")
EMAIL_HOST_PASSWORD = get_env("GMAIL_PASS")
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

# =====================================================
# Signal / Notification Email Configuration
# =====================================================
SIGNAL_EMAIL_HOST = get_env("SIGNAL_EMAIL_HOST", "smtp.gmail.com")
SIGNAL_EMAIL_PORT = int(get_env("SIGNAL_EMAIL_PORT", 587))
SIGNAL_EMAIL_USE_TLS = get_env("SIGNAL_EMAIL_USE_TLS", "True") == "True"
SIGNAL_EMAIL_HOST_USER = get_env("SIGNAL_EMAIL_HOST_USER")
SIGNAL_EMAIL_HOST_PASSWORD = get_env("SIGNAL_EMAIL_HOST_PASSWORD")
SIGNAL_DEFAULT_FROM_EMAIL = get_env("SIGNAL_DEFAULT_FROM_EMAIL")

# =====================================================
# Supabase Configuration
# =====================================================
SUPABASE_URL = get_env("SUPABASE_URL")
SUPABASE_KEY = get_env("SUPABASE_KEY")
SUPABASE_SERVICE_KEY = get_env("SUPABASE_SERVICE_KEY")
SUPABASE_BUCKET = get_env("SUPABASE_BUCKET", "files")

# =====================================================
# URLs & Templates
# =====================================================
ROOT_URLCONF = 'myproject.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'myproject.wsgi.application'

# =====================================================
# Static & Media Files
# =====================================================
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# =====================================================
# Cache Configuration (OTP Persistence)
# =====================================================
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'otp_cache_table',
        'TIMEOUT': 600,
        'KEY_PREFIX': 'project_otp:',
    }
}

# =====================================================
# Password Validation
# =====================================================
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# =====================================================
# Internationalization
# =====================================================
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Kolkata'
USE_TZ = True

# =====================================================
# Default Primary Key
# =====================================================
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# =====================================================
# Frontend URL
# =====================================================
HOMEPAGE_URL = get_env("HOMEPAGE_URL")

# =====================================================
# Render / Deployment
# =====================================================
RENDER_EXTERNAL_HOSTNAME = get_env("RENDER_EXTERNAL_HOSTNAME")
