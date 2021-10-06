import uuid
from rest_framework import views
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from apps.images.models import AllImage
from custom_exception.common_exception import get_custom_error_message
from apps.images.serializers import AllImageSerializer
from response import CustomResponse
from rest_framework.permissions import IsAuthenticated


class UploadImageView(views.APIView):
    parser_classes = (MultiPartParser,)
    image_content = "file"
    serializer_class = AllImageSerializer

    def post(self, request):
        upload = request.data.get(self.image_content, None)
        if not upload:
            return Response(get_custom_error_message("Missing image data."))

        path = "{}_{}".format(uuid.uuid4(), upload.name)
        image_obj = AllImage(name=upload.name)
        image_obj.image.save(path, upload)

        serializer = self.serializer_class(instance=image_obj)
        return CustomResponse({"result": serializer.data})


class UploadMultipleImageView(views.APIView):

    parser_classes = (MultiPartParser,)
    image_content = "file"
    serializer_class = AllImageSerializer

    def post(self, request):

        result = []
        if not request.data.getlist("file"):
            return Response(get_custom_error_message("Missing image data."))

        for i in request.data.getlist("file"):
            path = "{}_{}".format(uuid.uuid4(), i.name)
            image_obj = AllImage(name=i.name)
            image_obj.image.save(path, i)
            serializer = self.serializer_class(instance=image_obj)
            result.append(serializer.data)
        return CustomResponse({"result": result})
