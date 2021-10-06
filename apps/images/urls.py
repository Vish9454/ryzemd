from django.urls import path

from apps.images import views

urlpatterns = [
    path("upload_image", views.UploadImageView.as_view(), name="upload-image"),
    path(
        "upload_multiple_image",
        views.UploadMultipleImageView.as_view(),
        name="upload-image",
    ),
]
