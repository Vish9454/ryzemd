from apps.accounts.models import MedicalHistory, FamilyMember, User
from apps.accounts.serializers import MedicalResponseSerializer, ListMemberSerializer
from custom_exception.common_exception import CustomApiException
from utils import get_serialized_data

location_error = "list medical history"


def user_in_auth_medicalhistory(family_mem_id, request):
    if not family_mem_id:
        queryset = MedicalHistory.objects.filter(user=request.user.id, familymember=None,
                                                 is_deleted=False).order_by('-created_at').first()

        serializer = get_serialized_data(
            obj=queryset,
            serializer=MedicalResponseSerializer,
            fields=request.query_params.get("fields"),
        )
        return serializer.data
    else:
        queryset = FamilyMember.objects.filter(id=family_mem_id, user_id=request.user.id,
                                               is_deleted=False).prefetch_related(
            'family_member_medical_history').first()
        if not queryset:
            raise CustomApiException(
                status_code=400,
                message="The family member is not of this user",
                location=location_error)
        serializer = get_serialized_data(
            obj=queryset,
            serializer=ListMemberSerializer,
            fields=request.query_params.get("fields"),
        )
        """
        This was customized resonsse , so below things are returned
        """
        x = serializer.data.items()
        for k, v in x:
            if k == 'family_member_medical_history':
                try:
                    return_json = v[0]
                except IndexError:
                    raise CustomApiException(
                        status_code=400,
                        message="The family member has no medical history",
                        location="list medical history ")
        return return_json


def user_in_params_medicalhistory(family_mem_id, user_id, request):
    if not family_mem_id:
        if request.user.user_role == User.PATIENT:
            raise CustomApiException(
                status_code=400,
                message="The auth is not of Admin or remove the query params to see the medical history of patient",
                location=location_error)
        queryset_user_id_query_params = MedicalHistory.objects.filter(user=user_id, familymember=None,
                                                                      is_deleted=False).order_by(
            '-created_at').first()
        serializer = get_serialized_data(
            obj=queryset_user_id_query_params,
            serializer=MedicalResponseSerializer,
            fields=request.query_params.get("fields"),
        )
        return serializer.data
    else:
        queryset = FamilyMember.objects.filter(id=family_mem_id, user_id=request.query_params.get('user_id'),
                                               is_deleted=False).prefetch_related(
            'family_member_medical_history').first()
        if not queryset:
            raise CustomApiException(
                status_code=400,
                message="The family member is not of this user",
                location=location_error)
        serializer = get_serialized_data(
            obj=queryset,
            serializer=ListMemberSerializer,
            fields=request.query_params.get("fields"),
        )
        x = serializer.data.items()
        for k, v in x:
            if k == 'family_member_medical_history':
                try:
                    return_json = v[0]
                except IndexError:
                    raise CustomApiException(
                        status_code=400,
                        message="The family member has no medical history",
                        location=location_error)
        return return_json
