from rest_framework import serializers

from apps.accounts.models import DoctorMedicalDoc


def verify_by_admin(validated_data, instance, user_id, doc_object):
    if validated_data.get("user_doctormedicaldoc") or validated_data.get("user_doctormedicaldoc") == []:
        user_doctormedicaldoc = validated_data.pop("user_doctormedicaldoc")
    else:
        user_doctormedicaldoc = None
    if user_doctormedicaldoc:
        for doc_obj in user_doctormedicaldoc:
            if DoctorMedicalDoc.objects.filter(document_id=doc_obj).exists():
                raise serializers.ValidationError({
                    "status": 400, "error": {
                        "location": "document verify",
                        "message": "The document already exists."
                    }})
            # here duplicate ids were  causing trouble hence try except block is put
            try:
                DoctorMedicalDoc.objects.create(doctor=instance, document=doc_obj)
            except Exception:
                pass
    doc_object.update(**validated_data, status_doctor=3)
    return validated_data
