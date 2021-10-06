"""ryzemd URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include
from django.conf.urls import url
from config import settings

urlpatterns = [
    path('admin/', admin.site.urls),
    path("api/v1.0/ryzemd/accounts/", include(("apps.accounts.urls", "accounts"), namespace='v1.0')),
    path("api/v1.0/ryzemd/images/", include(("apps.images.urls", "images"), namespace='v1.0')),
    path("api/v1.0/ryzemd/payments/", include(("apps.payments.urls", "payments"), namespace='v1.0')),
    # API versioning is done here(for impact from dynamic shifts)
    path("api/v2.0/ryzemd/accounts/", include(("apps.accounts.urls", "accounts"), namespace='v2.0')),
]

if settings.DEBUG:
    import debug_toolbar
    urlpatterns += [
        url(r'^__debug__/', include(debug_toolbar.urls)),
    ]