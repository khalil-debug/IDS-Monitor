"""
Django settings for IDS project.

Generated by 'django-admin startproject' using Django 5.0.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

from pathlib import Path
import os
import logging

# Configure basic logging
logger = logging.getLogger(__name__)

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv("SECRET_KEY", "django-insecure-cxp7dkb25vnakx7y2o2+ehec6cngy94y3(+f#pjp8qh2yf6u5x")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']  # Allow all hosts in development, restrict in production


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "network_monitor",
    "chartjs",
    "django_celery_beat",
    "django_celery_results",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "IDS.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "IDS.wsgi.application"


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

IS_DOCKER = os.path.exists('/.dockerenv') or os.environ.get('DOCKER_CONTAINER')
# Check for explicit endpoint mode (local/windows)
ENDPOINT_MODE = os.environ.get('ENDPOINT_MODE', os.name == 'nt') == 'true' or os.name == 'nt'

if os.environ.get('USE_SQLITE') == 'true' or ENDPOINT_MODE:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }
    logger.info("Using SQLite database for endpoint mode")
elif IS_DOCKER or os.environ.get('DATABASE_URL'):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("POSTGRES_DB", "ids"),
            "USER": os.getenv("POSTGRES_USER", "postgres"),
            "PASSWORD": os.getenv("POSTGRES_PASSWORD", "postgres"),
            "HOST": os.getenv("POSTGRES_HOST", "db"),
            "PORT": os.getenv("POSTGRES_PORT", "5432"),
        }
    }
    logger.info("Using PostgreSQL database")
else:
    # Default to SQLite if nothing else is specified
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }
    logger.info("Using default SQLite database configuration")

# Uncomment this for PostgreSQL in production
# DATABASES = {
#     "default": {
#         "ENGINE": "django.db.backends.postgresql",
#         "NAME": os.getenv("POSTGRES_DB"),
#         "USER": os.getenv("POSTGRES_USER"),
#         "PASSWORD": os.getenv("POSTGRES_PASSWORD"),
#         "HOST": "db",
#         "PORT": "5432",
#     }
# }


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = "static/"
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Media files (uploads, etc.)
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Local fallback configuration for endpoints
LOCAL_STORAGE_PATH = os.path.join(BASE_DIR, 'local_storage')
USE_LOCAL_FALLBACK = os.environ.get('USE_LOCAL_FALLBACK', os.name == 'nt') == 'true' or os.name == 'nt'
ALLOW_PROCESSING_ON_ENDPOINTS = os.environ.get('ALLOW_PROCESSING_ON_ENDPOINTS', 'true') == 'true'

# Notification fallback paths
if not os.path.exists(os.path.join(LOCAL_STORAGE_PATH, 'notifications')):
    os.makedirs(os.path.join(LOCAL_STORAGE_PATH, 'notifications'), exist_ok=True)
if not os.path.exists(os.path.join(LOCAL_STORAGE_PATH, 'logs')):
    os.makedirs(os.path.join(LOCAL_STORAGE_PATH, 'logs'), exist_ok=True)
if not os.path.exists(os.path.join(LOCAL_STORAGE_PATH, 'sync')):
    os.makedirs(os.path.join(LOCAL_STORAGE_PATH, 'sync'), exist_ok=True)

# Celery Configuration
# ------------------

# Check for endpoint mode
ENDPOINT_MODE = os.environ.get('ENDPOINT_MODE', os.name == 'nt') == 'true' or os.name == 'nt'

# Fallback to disk settings
USE_DB_AS_BROKER = os.environ.get('USE_DB_AS_BROKER', ENDPOINT_MODE) == 'true'
CELERY_TASK_ALWAYS_EAGER = os.environ.get('CELERY_TASK_ALWAYS_EAGER', ENDPOINT_MODE) == 'true'

# RabbitMQ is now preferred over Redis for better message reliability
if os.environ.get('USE_REDIS'):
    CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
elif os.environ.get('USE_RABBITMQ', 'true').lower() == 'true':
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'amqp://guest:guest@localhost:5672//')
else:
    # Neither Redis nor RabbitMQ, use DB or eager mode
    CELERY_TASK_ALWAYS_EAGER = True
    if USE_DB_AS_BROKER:
        CELERY_BROKER_URL = 'django://'

# Try to connect to broker, fall back if needed
if not CELERY_TASK_ALWAYS_EAGER and os.getenv('CELERY_FALLBACK_TO_DISK', DEBUG):
    try:
        from kombu import Connection
        
        # Try to connect to the configured broker first
        with Connection(CELERY_BROKER_URL) as conn:
            conn.connect()
            logger.info(f"Successfully connected to broker: {CELERY_BROKER_URL.split('@')[0] if '@' in CELERY_BROKER_URL else CELERY_BROKER_URL.split('://')[0]}")
            
    except Exception as e:
        # If broker is unavailable, use Django database as broker
        # This is a fallback for development/endpoints - not recommended for production!
        logger.warning(f"Celery broker connection failed, falling back to Django DB or eager mode: {str(e)}")
        
        try:
            import kombu.transport.django
            
            CELERY_BROKER_URL = 'django://'
            if 'kombu.transport.django' not in INSTALLED_APPS:
                INSTALLED_APPS += ('kombu.transport.django',)
            logger.info("Using Django database as message broker")
            
        except ImportError:
            # If Django transport not available, use eager mode
            logger.warning("kombu.transport.django not installed, falling back to eager mode")
            logger.warning("Run 'pip install django-celery-results' to install required package")
            CELERY_TASK_ALWAYS_EAGER = True 
            logger.info("Using eager mode - tasks will execute immediately")

CELERY_TASK_EAGER_PROPAGATES = True

# Store task results in Django database
CELERY_RESULT_BACKEND = 'django-db'

CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'

# Celery task routes and queues
CELERY_TASK_DEFAULT_QUEUE = 'default'
CELERY_TASK_QUEUES = {
    'default': {'exchange': 'default', 'routing_key': 'default'},
    'priority': {'exchange': 'priority', 'routing_key': 'priority'},
}

# Default task execution settings
CELERY_TASK_SOFT_TIME_LIMIT = 300
CELERY_TASK_TIME_LIMIT = 600
CELERY_WORKER_HIJACK_ROOT_LOGGER = False  # Don't hijack the root logger
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000

# Retry settings for tasks
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_TASK_DEFAULT_RETRY_DELAY = 60
CELERY_TASK_MAX_RETRIES = 3

# Log Settings - Enhance logging for better debugging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'ids.log'),
            'formatter': 'verbose',
        },
    },
    'loggers': {
        '': {  # Root logger
            'handlers': ['console'],
            'level': 'INFO',
        },
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'network_monitor': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'celery': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# Create logs directory if it doesn't exist
if not os.path.exists(os.path.join(BASE_DIR, 'logs')):
    os.makedirs(os.path.join(BASE_DIR, 'logs'))
