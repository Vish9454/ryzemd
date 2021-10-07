from datetime import datetime, timedelta

DEBUG = True
ALLOWED_HOSTS = ['*']

# Database
# https://docs.djangoproject.com/en/1.11/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE':'django.contrib.gis.db.backends.postgis',
        'NAME': 'ryzemd',
        'USER':'ryzemd',
        'PASSWORD':'ryzemd123',
        'HOST':'localhost'
        # 'PORT': '5433'
    }
}


# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'yhm%15=&speynwd3^eye4pw*ww^v%-lxcir)l!zsfz%1x97)r^'


# DATABASES = {
#     'default': {
#         'ENGINE':'django.contrib.gis.db.backends.postgis',
#         'NAME': 'ryzme_db',
#         'USER':'root',
#         'PASSWORD':'HRkdK7Vs1Db',
#         'HOST':'dev-rds.cdnye3zhg6lq.us-east-1.rds.amazonaws.com'
#         # 'PORT': '5433'
#     }
# 


# https://docs.djangoproject.com/en/dev/ref/settings/#logging
# LOGGING = {
#     'version': 1,
#     'handlers': {
#         'console': {
#             'class': 'logging.StreamHandler',
#         },
#     },
#     'loggers': {
#         'django.db.backends': {
#             'level': 'DEBUG',
#         },
#     },
#     'root': {
#         'handlers': ['console'],
#     }
# }


# sendgrid connection (SMTP CONNECTION)
SEND_GRID_API_KEY = (
    "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"
)
FROM_EMAIL = "support@ryzemdcorp.com"
EMAIL_HOST = "smtp.sendgrid.net"
EMAIL_HOST_USER = "Vignesh_Jeyaraman"
EMAIL_HOST_PASSWORD = "Algoworks@123"
EMAIL_PORT = 587
EMAIL_USE_TLS = True

# Rest framework setting for pagination and authentication

REST_FRAMEWORK = {
# 'DEFAULT_FILTER_BACKENDS': ('django_filters.rest_framework.DjangoFilterBackend',),
    'DEFAULT_PAGINATION_CLASS':'pagination.Pagination',
    'DEFAULT_AUTHENTICATION_CLASSES': ('rest_framework.authentication.TokenAuthentication', 
    'rest_framework.authentication.BasicAuthentication',
    'rest_framework.authentication.SessionAuthentication',),
    'EXCEPTION_HANDLER': 'custom_exception.common_exception.custom_exception_handler',
    'DEFAULT_VERSIONING_CLASS': 'rest_framework.versioning.NamespaceVersioning'

}

INTERNAL_IPS='127.0.0.1'


DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
AWS_ACCESS_KEY_ID = 'AKIAS3FVIQNB757RXOVQ'
AWS_SECRET_ACCESS_KEY = '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'
AWS_STORAGE_BUCKET_NAME = 'ryzme-dev'
AWS_REGION = 'N.virginia'
AWS_S3_HOST = 's3.%s.amazonaws.com' % AWS_REGION
# As it is a public library.
AWS_DEFAULT_ACL = 'public-read'
AWS_QUERYSTRING_AUTH = False


emailverification_url = "http://ryzme-adminpanel-dev.s3-website-us-east-1.amazonaws.com/auth/verify-otp"

forgotpassword_url = "http://ryzme-adminpanel-dev.s3-website-us-east-1.amazonaws.com/auth/reset-password"


#for approving docs at admin (profile api)
docverification_url = "http://http://ec2-3-214-81-106.compute-1.amazonaws.com/api/v1.0/ryzemd/accounts/myprofile/"

FCM_SERVER_KEY = "AAAAG6Nl50A:APA91bF_dS220KMBzCrXV9z7exYehBXEKCAkVIbazgngDCv7vBfNKRda5or1_YMwPbj7B9kqhxGBBy7bFt7Zc44B85LV03OpPrUDPc6QHHlnFHTC2L6xWwW3NYCa9YSIdyv21JAKm8xe"

STRIPE_SECRET_KEY = ""
