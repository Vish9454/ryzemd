import re
from datetime import datetime

from rest_framework import serializers

from apps.accounts.models import User, DoctorMedicalDoc, TempDoctorMedicalDoc, TempDoctorWorkInfo
from apps.images.models import AllImage

# Make a regular expression
# for validating an Email
regex = '^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$'


def ios_personal_validations(personal_info_list, doc_obj, request):
    """
    This is done because when the request is sent to update , the parameters which are not given has to be set as null
    """
    for i in personal_info_list:
        if i not in list(request.data.get("personal")):
            if i == 'profile_image':
                doc_obj.profile_image_id = None
            elif i == 'dob':
                doc_obj.dob = None
            elif i == 'name':
                doc_obj.name = None
            elif i == 'zip_code':
                doc_obj.zip_code = None
            elif i == 'state':
                doc_obj.state = None
            elif i == 'address':
                doc_obj.address = None
            elif i == 'city':
                doc_obj.city = None
            elif i == 'lat' or i == 'lng':
                doc_obj.lat = doc_obj.lng == 0
                User.objects.filter(id=request.user.id).update(cordinate=None)
            doc_obj.save()


def phone_email_validation(details):
    if details.get('email') is None or details.get('phone_number') is None:
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": "validation",
                "message": "Email or phone number cannot be empty."
            }})


def address_lat_lng_validation(details, instance, request):
    if (details.get('address') is None or details.get('address') == "") or (
            details.get('lat') is None or details.get('lng') is None) or (
            details.get('lat') == "" or details.get('lng') == ""):
        # if the lat and lng and address has to be empty then do lat & lng = 0 and address as none
        User.objects.filter(id=instance.id).update(lat=0, lng=0, cordinate=None)
        # pop gives error if the parameters are not passed in request
        try:
            request.data.get("personal").pop("lat")
            request.data.get("personal").pop("lng")
        except Exception:
            pass


def phone_email_exist_validation(details, instance, request):
    if User.objects.filter(email=details.get('email')).exclude(id=request.user.id).exists(
    ) or not re.search(regex, details.get('email')):
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": "email validation",
                "message": "Email already registered or not in correct format."
            }})
    if User.objects.filter(phone_number=details.get('phone_number')).exclude(id=request.user.id).exists():
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": "phone number validation",
                "message": "Phone no. already registered."
            }})


def lat_lng_address_validation(details):
    if details.get('address') and not (details.get('lat') and details.get('lng')):
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": "address validation",
                "message": "Please enter lat and lng if address is given"
            }
        })


def profile_image_validations(details, instance, request):
    if User.objects.filter(profile_image=details.get('profile_image')).exclude(id=request.user.id).exclude(
            profile_image__isnull=True).exists():
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": "profile image validation",
                "message": "Already same Image is saved"
            }})


def dob_validation(details):
    if details.get('dob'):
        today = datetime.now().date()
        dob = datetime.strptime(details['dob'], '%Y-%m-%d')
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        if age < 18:
            raise serializers.ValidationError({
                "status": 400,
                "error": {
                    "location": "age validation",
                    "message": "Please enter the age greater then 18"
                }
            })


def zipcode_validation(details):
    if details.get('zip_code') or details.get('zip_code') == "":
        try:
            int(details.get('zip_code'))
        except Exception:
            raise serializers.ValidationError({
                "status": 400,
                "error": {
                    "location": "zipcode validation",
                    "message": "Please enter the correct zipcode."
                }
            })


def general_personal_validations(details, instance, request):
    """
    email can never be None so direct validation is put instead of checking for if details.get('email')
    same goes with phone number and rest have if conditions
    """
    phone_email_validation(details)
    address_lat_lng_validation(details, instance, request)
    # for validating an Email
    # pass the regular expression
    # and the string in search() method
    phone_email_exist_validation(details, instance, request)
    lat_lng_address_validation(details)
    profile_image_validations(details, instance, request)
    dob_validation(details)
    zipcode_validation(details)


def general_professional_validations(details, request):
    if User.objects.filter(medical_practice_id=details.get('medical_practice_id')).exclude(
            id=request.user.id).exclude(medical_practice_id__isnull=True).exists(

    ) or TempDoctorWorkInfo.objects.filter(
        medical_practice_id=details.get('medical_practice_id')).exclude(
        user_id=request.user.id).exclude(medical_practice_id__isnull=True).exists():
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": "License validation",
                "message": "License is already registered or in verifying state with Admin"
            }})
    if details.get('tempdoctorinfo_documents'):
        doc_med_obj = DoctorMedicalDoc.objects.filter(document_id__in=details.get('tempdoctorinfo_documents')).exclude(
            doctor_id=request.user.id)
        temp_doc_med_obj = TempDoctorMedicalDoc.objects.filter(document_id__in=details.get('tempdoctorinfo_documents'))
        if doc_med_obj or temp_doc_med_obj:
            raise serializers.ValidationError({
                "status": 400,
                "error": {
                    "location": "Doctor Documents validation",
                    "message": "These documents are registered or in verifying state with Admin"
                }})
        # this condition wil never come that document id is sent wrong, however the FE wants the check as API will crash
        # if the ids are sent wrong from FE , this loop is making the API heavy
        for i in details.get('tempdoctorinfo_documents'):
            if i not in AllImage.objects.filter().values_list('id', flat=True):
                raise serializers.ValidationError({
                    "status": 400,
                    "error": {
                        "location": "Doctor Documents validation",
                        "message": "The document ids are wrong."
                    }})

    if details.get('experience'):
        try:
            int(details.get('experience'))
        except Exception:
            raise serializers.ValidationError({
                "status": 400,
                "error": {
                    "location": "experience validation",
                    "message": "Please enter the correct experience."
                }
            })
