import boto3
from rest_framework import serializers
from apps.images.models import AllImage

from config.local import (
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    AWS_STORAGE_BUCKET_NAME,
    AWS_REGION,
)
from utils import DynamicFieldsModelSerializer


class AllImageSerializer(DynamicFieldsModelSerializer):
    name = serializers.SerializerMethodField()

    class Meta:
        model = AllImage
        fields = ("id", "name", "url")

    def get_name(self, obj):
        return obj.image.name
