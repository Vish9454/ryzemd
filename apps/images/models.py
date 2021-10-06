import os

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import ugettext_lazy as _


def upload_to(instance, filename):
    return "images/{}".format(filename)


def allowed_file_extension(value):

    ext = os.path.splitext(value.name)[1]  # [0] returns path+filename
    valid_extensions = [".jpg", ".png", ".jpeg", ".webp",".pdf"]
    if not ext.lower() in valid_extensions:
        raise ValidationError("Unsupported file extension.")


class AllImage(models.Model):
    image = models.ImageField(upload_to=upload_to, validators=[allowed_file_extension])
    name = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(_("date created"), auto_now_add=True)
    updated_at = models.DateTimeField(_("date updated"), auto_now=True)

    @property
    def url(self):
        return self.image.url if self.image else None
