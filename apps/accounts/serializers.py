"""importing packages"""
import random
from datetime import datetime, date, timedelta, time

from django.contrib.auth import authenticate
from django.contrib.contenttypes.models import ContentType
from django.contrib.gis.geos import Point
from pytz import utc
from rest_framework import serializers, fields
from rest_framework.authtoken.models import Token

from apps.accounts.adminbookingupdate import cancelbooking, destination_address, source_address, hub_change
from apps.accounts.booking import (booknow_mobiledoctor, booknow_hubvisit, booknow_videoconfer, booklater_mobiledoctor,
                                   booklater_videoconfer, booklater_hubvisit, get_dynamic_shift_id)
from apps.accounts.doctorassigndaily_functions import (validate_van, validate_virtual_room, validate_room,
                                                       doctorpayment,
                                                       create_doctorassign_van, create_doctorassign_virtualroom,
                                                       create_doctorassign_room, update_doctorassign_van,
                                                       update_doctorassign_virtualroom, update_doctorassign_room,
                                                       payment_deduction_method)
from apps.accounts.edit_doctor_profile_validations import (ios_personal_validations,
                                                           general_personal_validations,
                                                           )
from apps.accounts.models import (DoctorAssignDaily, SymptomsItems, State, City, User, OTP, Hub,
                                  HubDocs, Room, Van, FamilyMember, InsuranceDetails, EmergencyContacts, Ticket,
                                  VirtualRoom, MedicalHistory, MedicalHistoryItems,
                                  RatingDocAndApp, ContentManagement, Booking, DoctorMedicalDoc, DeviceManagement,
                                  TempDoctorWorkInfo, RolesManagement, DynamicShiftManagement,
                                  TempDoctorMedicalDoc, UserActivity, Symptoms, Designation_Amount, DoctorPerDayAmount,
                                  InsuranceVerification, DoctorDailyAvailability, CancelledBookings
                                  )
from apps.accounts.shift_management import create_shift_validations, update_shift_validations
from apps.accounts.utils import (
    generate_forgot_password_otp,
    generate_email_verification_url,
    generate_verify_admin_otp,
    generate_forgot_password_url
)
from apps.accounts.verifydocworkinfo import verify_by_admin
from apps.images.models import AllImage
from apps.images.serializers import AllImageSerializer
from config.local import docverification_url, emailverification_url, forgotpassword_url
from custom_exception.common_exception import (
    CustomApiException,
)
from utils import (
    send_forget_password_otp,
    send_verification_email,
    send_doc_verification_email,
    send_verify_admin_email,
    send_forgot_password_email,
    DynamicFieldsModelSerializer,
    send_subadmin_cred_email
)

url_otp_variable = "?url_otp="
date_string = '%Y-%m-%d'
date_time_string = '%Y-%m-%d %H:%M:%S'


class StateSerializer(serializers.ModelSerializer):
    class Meta:
        model = State
        fields = "__all__"


class CitySerializer(serializers.ModelSerializer):
    class Meta:
        model = City
        fields = "__all__"


class MedicalHistoryItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = MedicalHistoryItems
        fields = "__all__"


class SymptomAllViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = SymptomsItems
        fields = "__all__"


class SignupSerializer(serializers.ModelSerializer):
    """
    Signup serializer for Admin and sub-admin
    """

    email = serializers.EmailField(required=True, min_length=3, max_length=70)
    password = serializers.CharField(
        required=False, write_only=True, min_length=8, max_length=15
    )
    phone_number = serializers.CharField(required=True, min_length=10, max_length=20)
    profile_image = serializers.PrimaryKeyRelatedField(
        queryset=AllImage.objects.all(), many=False, required=False, allow_null=True
    )
    lat = serializers.FloatField(required=False)
    lng = serializers.FloatField(required=False)

    def validate(self, attrs):
        """
            method used to check if medical practice id exists in database.
        :param attrs:
        :return: attrs
        """
        try:
            if attrs["user_role"] == User.DOCTOR and User.objects.filter(
                    medical_practice_id=attrs["medical_practice_id"]).exists():
                raise serializers.ValidationError("License number already registered.")
        except Exception:
            pass
        if attrs.get('address') and (not attrs.get('lat') or not attrs.get('lng')):
            raise serializers.ValidationError("Please provide lat and lng of address")

        if attrs["user_role"] == User.PATIENT:
            dob = attrs["dob"]
            today = datetime.now().date()
            age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

            if age < 18:
                raise serializers.ValidationError(
                    "Your age is less than 18 year, not eligible for singup!."
                )

        return attrs

    def validate_email(self, email):
        """
            method used to check email already exist in database.
        :param email:
        :return: email
        """
        email = email.lower()
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email is already registered")
        return email

    def validate_phone_number(self, phone_number):
        """
            method used to check phone number already exist in database.
        :param phone number:
        :return: phone number
        """
        if User.objects.filter(phone_number=phone_number).exists():
            raise serializers.ValidationError("Phone Number registered already.")
        return phone_number

    def validate_medical_practice_id(self, medical_practice_id):
        if User.objects.filter(medical_practice_id=medical_practice_id).exists():
            raise serializers.ValidationError("License number already registered.")
        return medical_practice_id

    def validate_profile_image(self, profile_image):
        if User.objects.filter(profile_image=profile_image).exists():
            raise serializers.ValidationError("Profile image already exists.")
        return profile_image

    class Meta:
        model = User
        fields = (
            "name",
            "first_name",
            "last_name",
            "email",
            "password",
            "address",
            "lat",
            "lng",
            "phone_number",
            "user_role",
            "city",
            "state",
            "zip_code",
            "dob",
            "designation",
            "medical_practice_id",
            "speciality",
            "experience",
            "shift",
            "is_profile_approved",
            "profile_image",
            "stripe_customer_id",
            "is_stripe_customer",
            "dynamicshift",
        )

    def create(self, validated_data):
        """
        We have overridden the create method of the modelserializer.
        In this we are validating hospital data too hence we have also overridden
        create method inside hospital serializer and calling it from here.
        """
        is_admin = self.context.get("is_admin")
        lat = validated_data.get('lat')
        lng = validated_data.get('lng')
        point = Point(x=lng, y=lat, srid=4326)
        validated_data.update({"cordinate": point})
        user_obj = User.objects.create(**validated_data)
        user_obj.set_password(validated_data.get("password"))
        user_obj.save()
        # email verification
        try:
            email_url = generate_email_verification_url(user_obj)
            validated_data.update({"email_url": email_url})

            # doc verification at admin
            if is_admin:
                url = forgotpassword_url + url_otp_variable + email_url + "&otp_type=1"
            else:
                url = emailverification_url + url_otp_variable + email_url
                if user_obj.user_role == User.DOCTOR:
                    try:
                        admin_obj = User.objects.filter(user_role=User.ADMIN).first()
                        doc_url = docverification_url + str(user_obj.id)
                        send_doc_verification_email(admin_obj.email, doc_url)
                    except Exception:
                        pass

            send_verification_email(user_obj.email, url)

        except Exception:
            pass

        return user_obj


class LoginSerializer(serializers.ModelSerializer):
    """
    Login Serializer to validate user credentials.
    """

    email = serializers.EmailField(required=True, min_length=3, max_length=70)
    password = serializers.CharField(
        required=True, write_only=True, min_length=8, max_length=20
    )

    ADMIN = 1
    SUBADMIN = 2
    PATIENT = 3
    DOCTOR = 4
    ROLE = (
        (ADMIN, "Admin"),
        (SUBADMIN, "Subadmin"),
        (PATIENT, "Patient"),
        (DOCTOR, "Doctor"),
    )
    user_role = serializers.ChoiceField(choices=ROLE)

    class Meta:
        model = User
        fields = ("email", "password", "user_role")

    def validate(self, attrs):

        user_obj = (
            User.objects.select_related("auth_token", "profile_image")
                .filter(email=attrs["email"].lower())
                .first()
        )

        if user_obj:
            if user_obj.user_role != attrs["user_role"]:
                raise serializers.ValidationError("Invalid role")
        else:
            raise serializers.ValidationError(
                "Invalid login credentials. Please try again"
            )

        user = authenticate(email=attrs["email"].lower(), password=attrs["password"])
        if user is not None:
            attrs["user"] = user
        else:
            raise serializers.ValidationError(
                "Invalid login credentials. Please try again"
            )

        return attrs


class PatientSerializer(DynamicFieldsModelSerializer):
    """
    Serializer to serialize patient fields
    """

    class Meta:
        model = User
        fields = (
            "first_name",
            "last_name",
            "name",
            "email",
            "password",
            "address",
            "lat",
            "lng",
            "phone_number",
            "user_role",
            "city",
            "state",
            "zip_code",
            "dob",
        )


class DoctorSerializer(DynamicFieldsModelSerializer):
    """
    Serializer to serialize doctor fields
    """

    class Meta:
        model = User
        fields = (
            "name",
            "email",
            "password",
            "address",
            "lat",
            "lng",
            "phone_number",
            "user_role",
            "city",
            "state",
            "zip_code",
            "dob",
            "designation",
            "medical_practice_id",
            "speciality",
            "experience",
            "shift",
            "is_profile_approved",
            "dynamicshift"
        )


class EditPatientSerializer(serializers.ModelSerializer):
    """
    Edit Patient serializer
    """

    email = serializers.EmailField(required=True, min_length=3, max_length=70)
    phone_number = serializers.CharField(required=True, min_length=10, max_length=20)
    profile_image = serializers.PrimaryKeyRelatedField(queryset=AllImage.objects.all(), many=False, required=False)
    lat = serializers.FloatField(required=False)
    lng = serializers.FloatField(required=False)

    def validate_email(self, email):
        """
            method used to check email already exist in database.
        :param email:
        :return: email
        """
        patient_obj = self.context.get('patient_obj')
        email = email.lower()
        if patient_obj.email != email and User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email is registered alraedy")
        return email

    def validate_phone_number(self, phone_number):
        """
            method used to check phone number already exist in database.
        :param phone number:
        :return: phone number
        """
        if User.objects.filter(phone_number=phone_number).exists():
            raise serializers.ValidationError("The Phone Number is already in use.")
        return phone_number

    def validate_profile_image(self, profile_image):
        if User.objects.filter(profile_image=profile_image).exists():
            raise serializers.ValidationError("This Image is saved")
        return profile_image

    def validate_dob(self, dob):
        """
        Patient age has to be greater then 18
        """
        today = datetime.now().date()
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        if age < 18:
            raise serializers.ValidationError(
                "Please enter the age greater then 18"
            )
        return dob

    def validate(self, attrs):
        """The fields which has to be updated will only be sent as json """
        if attrs.get('address') and (not attrs.get('lat') or not attrs.get('lng')):
            raise serializers.ValidationError("Kindly provide lat and lng of address")
        return attrs

    def update(self, instance, validated_data):
        # only when address is given then the lat and lng executes to give the point
        if validated_data.get('address'):
            lat = validated_data.get('lat')
            lng = validated_data.get('lng')
            point = Point(x=lng, y=lat, srid=4326)
            validated_data.update({"cordinate": point})
            # email verification
        if validated_data.get('email') and (instance.email != validated_data.get('email')):
            User.objects.filter(id=instance.id).update(email=validated_data.get('email'))
            obj = User.objects.get(id=instance.id)
            email_url = generate_email_verification_url(obj)
            url = emailverification_url + url_otp_variable + email_url
            send_verification_email(obj.email, url)
            User.objects.filter(id=instance.id).update(is_email_verified=False)
            # validated_data.update({"is_email_verified": False})
        User.objects.filter(id=instance.id).update(**validated_data)
        return instance

    class Meta:
        model = User
        fields = (
            "id",
            "first_name",
            "last_name",
            "name",
            "email",
            "password",
            "address",
            "lat",
            "lng",
            "phone_number",
            "user_role",
            "city",
            "state",
            "zip_code",
            "dob",
            "profile_image",
        )


class TokenSerializer(serializers.ModelSerializer):
    """
    Serializer to serialize user's Token
    """

    class Meta:
        model = Token
        fields = ("key",)


# this serializer is for doctor edit profile on line no 1352,added here because in userserializer,
# user_doctormedicaldoc is used
class DoctorDocumentSerializer(DynamicFieldsModelSerializer):
    document = AllImageSerializer(allow_null=True, fields=("id", "url", "name"))

    class Meta:
        model = DoctorMedicalDoc
        fields = ("id", "document", "doctor")


class DeviceManagementSerializer(DynamicFieldsModelSerializer):
    class Meta:
        model = DeviceManagement
        fields = ("id", 'device_uuid', 'fcm_token', 'user')


class RoleManagementLoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = RolesManagement
        fields = ("id", 'modules_access', 'user_role', 'is_deleted')


class VerifyOTPSerializer(serializers.Serializer):
    """
    Serializer to validate users OTP
    """
    email = serializers.EmailField(required=False)
    otp_type = serializers.IntegerField(required=False)
    otp = serializers.CharField(required=True)

    def validate(self, attrs):
        """to validate attributes"""

        # email verification
        otp = attrs.get("otp")

        if not attrs.get("email"):
            otp_obj = OTP.objects.filter(
                otp=otp, otp_type=OTP.VERIFICATION_OTP, is_used=False
            ).first()

        else:
            user_obj = User.objects.filter(email=attrs.get("email")).first()
            if not user_obj:
                raise serializers.ValidationError("No user found.")

            otp_obj = OTP.objects.filter(otp=otp, otp_type=attrs.get("otp_type"), is_used=False).first()

        if not otp_obj:
            raise serializers.ValidationError("Invalid OTP")

        user_obj = User.objects.filter(id=otp_obj.user.id).first()
        if not user_obj:
            raise serializers.ValidationError("No user found.")

        if otp_obj.otp_type == OTP.VERIFICATION_OTP:
            user_obj.is_email_verified = True
            user_obj.save()
        otp_obj.is_used = True
        otp_obj.save()
        return attrs


class ForgotPasswordSerializer(serializers.Serializer):
    """Serializer to send OTP to user's email and phone number when they opt for forgot password"""

    ADMIN = 1
    SUBADMIN = 2
    PATIENT = 3
    DOCTOR = 4
    ROLE = (
        (ADMIN, "Admin"),
        (SUBADMIN, "Subadmin"),
        (PATIENT, "Patient"),
        (DOCTOR, "Doctor"),
    )

    user_role = serializers.ChoiceField(choices=ROLE)
    email = serializers.CharField(required=True, max_length=50)
    otp = serializers.CharField(required=False)

    def validate(self, attrs):
        """validating attributes"""
        email = attrs.get("email").lower()

        user = User.objects.filter(email=email).first()
        if not user:
            raise serializers.ValidationError("User isnt present")

        if user.user_role != attrs.get("user_role"):
            raise serializers.ValidationError("Invalid role")

        if user.user_role in [User.PATIENT, User.DOCTOR]:
            otp = generate_forgot_password_otp(user)
            attrs["otp"] = otp
            try:
                send_forget_password_otp(user.email, otp)
            except Exception:
                pass
        else:
            try:
                forgot_url = generate_forgot_password_url(user)
                attrs["otp"] = forgot_url
                url = forgotpassword_url + url_otp_variable + forgot_url + "&otp_type=2"
                send_forgot_password_email(user.email, url)

            except Exception:
                pass

        attrs["user"] = user
        attrs["email"] = email

        return attrs


class ResendOTPSerializer(VerifyOTPSerializer):
    """
    Serializer for resending OTP. We have inherited VerifyOTPSerializer to reuse its functionality.
    """

    otp = serializers.CharField(required=False)
    otp_type = serializers.IntegerField(required=True)

    def validate(self, attrs):
        """to validate attributes"""

        request = self.context.get("request")
        user_obj = User.objects.filter(email=request.data.get("email")).first()
        if not user_obj:
            raise serializers.ValidationError("Invalid email.")
        if request.data.get('otp_type') not in [OTP.FORGOT_PASSWORD_OTP, OTP.LOGIN_OTP]:
            raise serializers.ValidationError("Invalid otp type")

        if request.data.get('otp_type') == OTP.FORGOT_PASSWORD_OTP:
            """resend otp for forgot password"""
            otp = generate_forgot_password_otp(user_obj)
            attrs["otp"] = otp
            try:
                send_forget_password_otp(user_obj.email, otp)
            except Exception:
                pass
        elif request.data.get('otp_type') == OTP.LOGIN_OTP:
            """resend otp for resending otp"""
            otp = generate_verify_admin_otp(user_obj)
            attrs["otp"] = otp
            try:
                send_verify_admin_email(user_obj.email, otp)
            except Exception:
                pass

        return attrs


class ResetPasswordSerializer(serializers.Serializer):
    """method to reset user's password"""

    email = serializers.CharField(required=False, max_length=50)
    password = serializers.CharField(
        required=True, write_only=True, min_length=8, max_length=20
    )
    confirm_password = serializers.CharField(
        required=True, write_only=True, min_length=8, max_length=20
    )
    otp = serializers.CharField(required=False)

    def validate(self, attrs):
        """validating attributes"""
        user_obj = self.context.get("user_obj")
        otp_obj = self.context.get("otp_obj")
        if attrs.get("password") != attrs.get("confirm_password"):
            raise serializers.ValidationError(
                "Password and confirm password does not match"
            )

        # deleting token to signout user out of other device
        Token.objects.filter(user=user_obj).delete()
        token, created = Token.objects.get_or_create(user=user_obj)
        attrs["token"] = token.key
        user_obj.set_password(attrs["password"])
        user_obj.save()
        if otp_obj:
            otp_obj.is_used = True
            otp_obj.save()

        return attrs


class ChangePasswordSerializer(serializers.Serializer):
    """Login Serializer to validate user credentials"""

    old_password = serializers.CharField(
        required=True, write_only=True, min_length=8, max_length=20
    )
    new_password = serializers.CharField(
        required=True, write_only=True, min_length=8, max_length=20
    )

    def validate(self, attrs):
        """to validate attributes"""
        request = self.context.get("request")
        user_obj = authenticate(
            email=request.user.email.lower(), password=attrs.get("old_password")
        )
        if not user_obj:
            raise serializers.ValidationError("Old Password is incorrect")
        user_obj.set_password(attrs["new_password"])
        user_obj.save()

        # deleting token to signout user out of other device
        Token.objects.filter(user=user_obj).delete()
        token, created = Token.objects.get_or_create(user=user_obj)
        attrs["token"] = token.key
        return attrs


class HubDocumentSerializer(DynamicFieldsModelSerializer):
    """
        This serializer will be used for hub documents.
    """

    document = AllImageSerializer(allow_null=True, fields=("id", "url", "name"))

    class Meta:
        model = HubDocs
        fields = ("id", "document", "hub")


class HubResponseSerializer(DynamicFieldsModelSerializer):
    """
        Serializer for listing hubs at admin
    """

    hub_documents = HubDocumentSerializer(many=True, fields=("document", "hub"))

    class Meta:
        model = Hub
        fields = ("id", "hub_documents", "hub_name", "is_deleted", "address", "lat", "lng", "cordinate", "amount")


class ListHubSerializer(serializers.ModelSerializer):
    """
        Serializer for listing all hubs at admin
    """

    class Meta:
        model = Hub
        fields = ("id", "hub_name", "is_deleted", "address", "lat", "lng", "cordinate", "amount")


class HubSerializer(serializers.Serializer):
    """
        Serializer to Create Hub in Admin Panel
    """

    hub_name = serializers.CharField(required=True)
    hub_documents = serializers.PrimaryKeyRelatedField(
        required=False, queryset=AllImage.objects.all(), many=True
    )
    address = serializers.CharField(required=True)
    lat = serializers.FloatField(required=True)
    lng = serializers.FloatField(required=True)
    amount = serializers.FloatField(required=True)

    class Meta:
        """meta class"""
        model = Hub
        fields = ("hub_documents", "hub_name", "address", "lat", "lng", "amount")

    def validate(self, validated_data):
        # uploading same doc
        try:
            if HubDocs.objects.filter(document__in=validated_data.get("hub_documents")).exists():
                raise serializers.ValidationError("This document is already added.")
        except Exception:
            pass
        return validated_data

    def create(self, validated_data):
        """create hub"""
        if validated_data.get("hub_documents"):
            hub_documents = validated_data.pop("hub_documents")
        else:
            hub_documents = None

        lat = validated_data.get("lat")
        lng = validated_data.get("lng")
        point = Point(x=lng, y=lat, srid=4326)
        validated_data.update({"cordinate": point})

        obj = Hub.objects.create(**validated_data)

        if hub_documents:
            for doc_obj in hub_documents:
                HubDocs.objects.create(hub=obj, document=doc_obj)

        return obj

    def update(self, instance, validated_data):
        """updating hub"""
        lat = validated_data.get("lat")
        lng = validated_data.get("lng")
        point = Point(x=lng, y=lat, srid=4326)
        validated_data.update({"cordinate": point})
        if validated_data.get("hub_documents"):
            hub_documents = validated_data.pop("hub_documents")
        else:
            hub_documents = None
        Hub.objects.filter(id=instance.id).update(**validated_data)

        # update documents
        if hub_documents:
            for doc_obj in hub_documents:
                HubDocs.objects.update_or_create(hub=instance, document=doc_obj)

        return validated_data


class RoomResponseSerializer(serializers.ModelSerializer):
    """
        Serializer for listing rooms at admin
    """

    class Meta:
        model = Room
        fields = ("id", "hub", "room_number", "is_deleted", "status")


class ListRoomSerializer(serializers.ModelSerializer):
    """
        Serializer for listing all rooms at admin
    """

    class Meta:
        model = Room
        fields = ("id", "hub", "room_number", "is_deleted", "status")


class RoomSerializer(serializers.ModelSerializer):
    """
        Serializer to Create Room in Admin Panel
    """

    class Meta:
        """meta class"""
        model = Room
        fields = ("id", "room_number", "hub", "is_deleted", "status")

    def create(self, validated_data):
        """create room"""

        if Room.objects.filter(room_number=validated_data.get("room_number"), hub=validated_data.get("hub"),
                               is_deleted=False).exists():
            raise CustomApiException(
                status_code=400, message="This room is already added in this hub.", location="add room"
            )
        obj = Room.objects.create(**validated_data)
        return obj

    def update(self, instance, validated_data):
        """updating room"""
        Room.objects.filter(id=instance.id).update(**validated_data)
        return validated_data


class VanResponseSerializer(serializers.ModelSerializer):
    """
        Serializer for listing vans at admin
    """

    class Meta:
        model = Van
        fields = ("id", "hub", "van_number", "is_deleted", "status", "level_type")


class ListVanSerializer(serializers.ModelSerializer):
    """
        Serializer for listing all vans at admin
    """

    class Meta:
        model = Van
        fields = ("id", "hub", "van_number", "is_deleted", "status", "level_type")


class VanSerializer(serializers.ModelSerializer):
    """
        Serializer to Create van in Admin Panel
    """

    class Meta:
        """meta class"""
        model = Van
        fields = ("van_number", "hub", "is_deleted", "status", "level_type")

    def create(self, validated_data):
        """create van"""

        if Van.objects.filter(van_number=validated_data.get("van_number"), is_deleted=False).exists():
            raise CustomApiException(
                status_code=400, message="This van is already added.", location="add van"
            )
        obj = Van.objects.create(**validated_data)
        return obj

    def update(self, instance, validated_data):
        """updating van"""
        if Van.objects.filter(van_number=validated_data.get("van_number")).exists():
            raise CustomApiException(
                status_code=400, message="This van is already present.", location="add van"
            )
        Van.objects.filter(id=instance.id).update(**validated_data)
        return validated_data


class FamilyResponseSerializer(serializers.ModelSerializer):
    """
        Serializer for listing Family member in patient
    """

    class Meta:
        model = FamilyMember
        fields = "__all__"


class TicketResponseSerializer(serializers.ModelSerializer):
    """
        Serializer for listing tickets at admin
    """

    class Meta:
        model = Ticket
        fields = ('__all__')


class TicketSerializer(serializers.ModelSerializer):
    is_resolved = serializers.BooleanField(required=False)

    class Meta:
        model = Ticket
        fields = ("tick_name", "email_add", "ticket_regard_type", "add_note", "is_resolved", "new_text")

    def create(self, validated_data):
        """Creating a ticket"""
        email = validated_data.get("email_add").lower()
        user_obj = User.objects.filter(email=email).first()
        if not user_obj:
            raise CustomApiException(
                status_code=400, message="User is not present", location="Add Tickets"
            )

        validated_data.update({"user": user_obj})
        ticket_obj = Ticket.objects.create(**validated_data)

        return ticket_obj

    def update(self, instance, validated_data):
        """updating Ticket"""

        if validated_data.get("email_add"):
            email = validated_data.get("email_add").lower()
            user_obj = User.objects.filter(email=email).first()
            if not user_obj:
                raise CustomApiException(
                    status_code=400, message="User not found", location="Update Tickets"
                )
            validated_data.update({"user": user_obj})
        Ticket.objects.filter(id=instance.id).update(**validated_data)
        return validated_data


class VirtualRoomSerializer(serializers.ModelSerializer):
    """Serializer to Create Virtual Room in Admin Panel"""

    def create(self, validated_data):
        """create virtual room"""
        if VirtualRoom.objects.filter(room_number=validated_data.get("room_number"), hub=validated_data.get("hub"),
                                      is_deleted=False).exists():
            raise CustomApiException(
                status_code=400, message="This virtual room is already added in this hub.", location="add virtual room"
            )
        obj = VirtualRoom.objects.create(**validated_data)
        return obj

    def update(self, instance, validated_data):
        """update Virtual room"""
        VirtualRoom.objects.filter(id=instance.id).update(**validated_data)
        return validated_data

    class Meta:
        """meta class"""
        model = VirtualRoom
        fields = ("id", "room_number", "hub", "is_deleted", "status")


class VirtualRoomResponseSerializer(serializers.ModelSerializer):
    """Serializer for listing virtual rooms at admin"""

    class Meta:
        model = VirtualRoom
        fields = ("id", "hub", "room_number", "is_deleted", "status")


class ListVirtualRoomSerializer(serializers.ModelSerializer):
    """Serializer for listing all rooms at admin"""

    class Meta:
        model = VirtualRoom
        fields = ("id", "hub", "room_number", "status", "is_deleted")


class FamilySerializer(serializers.ModelSerializer):
    """
        Serializer to Create family member in patient
    """

    class Meta:
        """meta class"""
        model = FamilyMember
        fields = "__all__"

    def validate_dob(self, dob):
        """
        The age of family member has to be greater then zero, age cannot be less then 0
        """
        today = datetime.now().date()
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        if age < 0:
            raise serializers.ValidationError(
                "Kindly enter correct age"
            )
        return dob

    def create(self, validated_data):
        """create family member"""

        if FamilyMember.objects.filter(name=validated_data.get("name"), relation=validated_data.get("relation"),
                                       user=validated_data.get("user")).exists():
            raise CustomApiException(
                status_code=400, message="This member is already added.", location="add family member"
            )
        obj = FamilyMember.objects.create(**validated_data)
        return obj


class InsuranceResponseSerializer(serializers.ModelSerializer):
    """serializer to listing insurance details"""
    profile_image = AllImageSerializer(allow_null=True, many=True)

    class Meta:
        model = InsuranceDetails
        fields = '__all__'


class InsuranceSerializer(serializers.ModelSerializer):
    """serializer to create insurance details"""

    def validate_policyid(self, policyid):
        if InsuranceDetails.objects.filter(policyid=policyid, is_deleted=False).exists():
            raise serializers.ValidationError("PolicyID already exixts.")
        return policyid

    def validate_securitynumber(self, securitynumber):
        if InsuranceDetails.objects.filter(securitynumber=securitynumber, is_deleted=False).exists():
            raise serializers.ValidationError("Securitynumber already exixts.")
        if len(str(securitynumber)) < 9 or len(str(securitynumber)) > 12:
            raise serializers.ValidationError("Securitynumber has to be between 9 to 12 digits")
        return securitynumber

    def create(self, validated_data):
        familymember_id = self.context.get("familymember_id")
        try:
            profile_images = validated_data.pop('profile_image')
            print(profile_images)
        except Exception:
            pass

        obj = InsuranceDetails.objects.create(**validated_data)
        try:
            if profile_images:
                for image in profile_images:
                    obj.profile_image.add(image)
        except Exception:
            pass
        if familymember_id:
            familyobj = FamilyMember.objects.filter(id=familymember_id).first()
            obj.familymember_id = familyobj.id
            obj.save()
        return obj

    def update(self, instance, validated_data):
        request = self.context.get('request')

        delete_image_ids = request.data.get('delete_images')
        try:
            profile_images = validated_data.pop("profile_image")
        except Exception:
            pass
        # adding images
        try:
            if profile_images:
                for profile_image in profile_images:
                    instance.profile_image.add(profile_image)
        except Exception:
            pass
        InsuranceDetails.objects.filter(id=instance.id).update(**validated_data)
        instance_obj = InsuranceDetails.objects.filter(id=instance.id).first()
        # deleting images
        try:
            for image_id in delete_image_ids:
                obj = InsuranceDetails.profile_image.through.objects.filter(allimage_id=image_id).first().delete()
        except Exception:
            pass
        return instance

    class Meta:
        model = InsuranceDetails
        fields = '__all__'


class ListInsuranceSerializer(serializers.ModelSerializer):
    """serializer to listing all insurance details"""
    profile_image = AllImageSerializer(allow_null=True, many=True)

    class Meta:
        model = InsuranceDetails
        fields = ('id', 'created_at', 'updated_at', 'name', 'groupid', 'policyid', 'securitynumber', 'is_deleted',
                  'user', 'familymember', 'profile_image')


class AdminListInsuranceSerializer(serializers.ModelSerializer):
    """serializer to listing all insurance details"""

    class Meta:
        model = InsuranceDetails
        fields = ('id', 'created_at', 'updated_at', 'name', 'groupid', 'policyid', 'securitynumber', 'is_deleted',
                  'user', 'familymember')


class EmergencyResponseSerializer(serializers.ModelSerializer):
    """serializer to listing emergency contacts"""

    class Meta:
        model = EmergencyContacts
        fields = '__all__'


class EmergencySerializer(serializers.ModelSerializer):
    """serializer to listing all emergency contacts"""
    phone_number = serializers.CharField(required=True, min_length=10, max_length=20)

    def validate_phone_number(self, phone_number):
        if EmergencyContacts.objects.filter(phone_number=phone_number, is_deleted=False).exists():
            raise serializers.ValidationError("Your phone number is alreday registered")
        return phone_number

    class Meta:
        model = EmergencyContacts
        fields = '__all__'


class ListEmergencySerializer(serializers.ModelSerializer):
    """serializer to listing all emergency contacts"""

    class Meta:
        model = EmergencyContacts
        fields = ('__all__')


class MedicalHistoryItemsSerializer(serializers.ModelSerializer):
    class Meta:
        model = MedicalHistoryItems
        fields = ('id', 'medicalhistory_name')


class MedicalResponseSerializer(DynamicFieldsModelSerializer):
    """serializer to listing medical history"""
    items = MedicalHistoryItemsSerializer(many=True)

    class Meta:
        model = MedicalHistory
        fields = ('id', 'familymember', 'items', 'specialrequest', 'is_deleted')


# noinspection PyUnboundLocalVariable
class MedicalSerializer(serializers.ModelSerializer):
    """serializer to create medical history"""

    def create(self, validated_data):
        request = self.context.get("request")
        familymember_id = self.context.get("familymember_id")
        validated_data.update({"user_id": request.user.id})
        if familymember_id:
            validated_data.update({"familymember_id": familymember_id})
        try:
            items = validated_data.pop("items")
        except Exception:
            pass
        medical_obj = MedicalHistory.objects.create(**validated_data)

        try:
            if items:
                # here from the list the id_obj are taken out and through manytomany query the table if filled
                # the table is as - accounts_medicalhistory_items
                # ManytoMany query is applied here for adding
                for item_obj in items:
                    medical_obj.items.add(item_obj)
        except Exception:
            pass
        return medical_obj

    def update(self, instance, validated_data):
        # validated_data.get("items") gives error if items is not passed(as manytomany field) or passed empty so try block used
        try:
            items = validated_data.pop("items")
        except Exception:
            pass
        MedicalHistory.objects.filter(id=instance.id).update(**validated_data)
        # update doesnt give the object , it gives boolean hence med_obj is created for the instance
        med_obj = MedicalHistory.objects.get(id=instance.id)
        try:
            if items:
                # We are fistly clearing the manytomany fields for that particular object and then
                # entering the new objects passed by the user
                # add function is used to add the med_obj and item_obj in the 3rd table which is created by manytomany field
                # clear just clears the id's from 3rd table created by manytomany field
                # do not use delete ,else it will delete the entries of original tables along with 3rd table

                med_obj.items.clear()
                for item_obj in items:
                    med_obj.items.add(item_obj)
            else:
                med_obj.items.clear()
        except Exception:
            pass
        return instance

    class Meta:
        model = MedicalHistory
        exclude = ('user',)


# edit by admin serializer
class EditDoctorSerializer(serializers.ModelSerializer):
    """
    Edit Doctor serializer by the admin only
    """

    email = serializers.EmailField(required=True, min_length=3, max_length=70)
    phone_number = serializers.CharField(required=True, min_length=10, max_length=20)
    profile_image = serializers.PrimaryKeyRelatedField(queryset=AllImage.objects.all(), many=False, required=False)
    lat = serializers.FloatField(required=False)
    lng = serializers.FloatField(required=False)

    def validate_email(self, email):
        """
            method used to check email already exist in database.
        :param email:
        :return: email
        """
        email = email.lower()
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email is already registered , kindly give another emailid")
        return email

    def validate_phone_number(self, phone_number):
        """
            method used to check phone number already exist in database.
        :param phone number:
        :return: phone number
        """
        if User.objects.filter(phone_number=phone_number).exists():
            raise serializers.ValidationError("Phone Number already registered with different mailid.")
        return phone_number

    def validate_profile_image(self, profile_image):
        if User.objects.filter(profile_image=profile_image).exists():
            raise serializers.ValidationError("Same Image is saved")
        return profile_image

    def validate_medical_practice_id(self, medical_practice_id):
        if User.objects.filter(medical_practice_id=medical_practice_id).exists():
            raise serializers.ValidationError("Already same Medical Id is saved")
        return medical_practice_id

    def validate_admin_medical_practice_id(self, admin_medical_practice_id):
        """
        We are validating if same medical id is passed many times then converting it to set removes duplicates
        and then converting it back to list
        """
        admin_medical_practice_id = set(admin_medical_practice_id)
        return list(admin_medical_practice_id)

    def validate(self, attrs):
        """The fields which has to be updated will only be sent as json """
        if attrs.get('address') and (not attrs.get('lat') or not attrs.get('lng')):
            raise serializers.ValidationError("kindly provide latitude and longitude of address")
        return attrs

    def update(self, instance, validated_data):
        # only when address is given then the lat and lng executes to give the point
        if validated_data.get('address'):
            lat = validated_data.get('lat')
            lng = validated_data.get('lng')
            point = Point(x=lng, y=lat, srid=4326)
            validated_data.update({"cordinate": point})
        obj = User.objects.filter(id=instance.id).update(**validated_data)
        return obj

    class Meta:
        model = User
        fields = (
            "name",
            "email",
            "password",
            "address",
            "lat",
            "lng",
            "phone_number",
            "user_role",
            "city",
            "state",
            "zip_code",
            "dob",
            "designation",
            "medical_practice_id",
            "speciality",
            "experience",
            "shift",
            "is_profile_approved",
            "profile_image",
            "admin_medical_practice_id",
            "dynamicshift"
        )


# 15th dec code

class NestedSerializerForRating(serializers.ModelSerializer):
    profile_image = AllImageSerializer(allow_null=True)

    class Meta:
        model = User
        fields = ['id', 'name', 'profile_image']


class RatingSerializer(serializers.ModelSerializer):
    """serializer to creating and updating rating app and doctor"""

    def create(self, validated_data):
        request = self.context.get("request")
        user = request.user
        validated_data.update({"patient_id": user.id})
        user_obj = RatingDocAndApp.objects.create(**validated_data)
        return user_obj

    def update(self, instance, validated_data):
        RatingDocAndApp.objects.filter(id=instance.id).update(**validated_data, is_deleted=False)
        return validated_data

    class Meta:
        model = RatingDocAndApp
        fields = ('__all__')


class RatingResponseSerializer(serializers.ModelSerializer):
    """serializer for response all rating app"""
    doctor = NestedSerializerForRating(many=False, read_only=True)
    patient = NestedSerializerForRating(many=False, read_only=True)

    class Meta:
        model = RatingDocAndApp
        fields = ('id',
                  'doctor',
                  'patient',
                  'review',
                  'rating',
                  'comment_box',
                  'rating_doc_or_app')


# 17th dec
class GetDocRatingInfoResponseSerializer(serializers.ModelSerializer):
    """serializer for getting doc img and name"""
    profile_image = AllImageSerializer(allow_null=True)

    class Meta:
        model = User
        fields = ['id', 'name', 'profile_image']


# admin update
class AdminUpdateSerializer(serializers.ModelSerializer):
    """Admin name,photo,email,phone no """
    phone_number = serializers.CharField(required=True, min_length=10, max_length=20)

    def validate_profile_image(self, profile_image):
        if User.objects.filter(profile_image=profile_image).exists():
            raise serializers.ValidationError("Same Image is already saved")
        return profile_image

    def validate_email(self, email):
        email = email.lower()
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("This EmailId is already registered")
        return email

    def validate_phone_number(self, phone_number):
        if User.objects.filter(phone_number=phone_number).exists():
            raise serializers.ValidationError("Phone Number already registered.")

        return phone_number

    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'profile_image', 'phone_number']


# 23 dec
class ContentManagementDocumentSerializer(serializers.ModelSerializer):
    """This serializer will be used for Content management documents."""

    # Here profile_image is the name for serialized pdf which will be passed
    # on line 1222 this serializer is used,AllimageSerializer also can be used
    class Meta:
        model = AllImage
        fields = ('__all__')


class ContentManagementSerializer(serializers.ModelSerializer):
    """serializer to creating and updating the content management"""
    cm_phone_number = serializers.CharField(required=True, min_length=10, max_length=20)

    def validate_cm_email(self, cm_email):
        cm_email = cm_email.lower()
        if ContentManagement.objects.filter(cm_email=cm_email).exists():
            raise serializers.ValidationError("Same Email already present.")
        return cm_email

    def validate_cm_phone_number(self, cm_phone_number):
        if ContentManagement.objects.filter(cm_phone_number=cm_phone_number).exists():
            raise serializers.ValidationError("Same Phone number already present.")
        return cm_phone_number

    def validate_cm_terms_condition_pdf(self, cm_terms_condition_pdf):
        if ContentManagement.objects.filter(cm_terms_condition_pdf=cm_terms_condition_pdf).exists():
            raise serializers.ValidationError("Same terms and conditions already present.")
        return cm_terms_condition_pdf

    def validate_cm_legal_terms_pdf(self, cm_legal_terms_pdf):
        if ContentManagement.objects.filter(cm_legal_terms_pdf=cm_legal_terms_pdf).exists():
            raise serializers.ValidationError("Same legal terms already present.")
        return cm_legal_terms_pdf

    def create(self, validated_data):
        user_obj = ContentManagement.objects.create(**validated_data)
        return user_obj

    class Meta:
        model = ContentManagement
        fields = ('__all__')


class ContentManagementResponseSerializer(serializers.ModelSerializer):
    """serializer for response all content management"""
    cm_terms_condition_pdf = ContentManagementDocumentSerializer(many=False, read_only=True)
    cm_legal_terms_pdf = ContentManagementDocumentSerializer(many=False, read_only=True)

    class Meta:
        model = ContentManagement
        fields = ('id',
                  'cm_email',
                  'cm_phone_number',
                  'cm_terms_condition_pdf',
                  'cm_legal_terms_pdf'
                  )


# modified the listmember seializer for adding medical history of the member

class MedicalResponseSerializerForfamilyMember(DynamicFieldsModelSerializer):
    items = MedicalHistoryItemsSerializer(many=True)

    class Meta:
        model = MedicalHistory
        exclude = ("user", "created_at", "updated_at")


class ListMemberSerializer(DynamicFieldsModelSerializer):
    """serializer to listing all family members"""
    family_member_medical_history = MedicalResponseSerializerForfamilyMember(many=True)

    class Meta:
        model = FamilyMember
        fields = ('id', 'user', 'name', 'dob', 'relation', 'is_deleted', 'family_member_medical_history',)


class EditDoctorPersonalInfoSerializer(serializers.ModelSerializer):
    # editing personal info and sending email verification link to the doctor for updating it
    # for work info details edit notification will be sent to admin
    email = serializers.EmailField(required=True, min_length=3, max_length=70)
    phone_number = serializers.CharField(required=True, min_length=10, max_length=20)
    profile_image = serializers.PrimaryKeyRelatedField(queryset=AllImage.objects.all(), many=False, required=False,
                                                       allow_null=True)
    lat = serializers.FloatField(required=False)
    lng = serializers.FloatField(required=False)

    def update(self, instance, validated_data):
        details = self.context.get("details")
        request = self.context.get("request")
        doc_obj = self.context.get("doc_obj")
        # for ios , if the address or other parameter is set null or empty then they will not send it in the request
        # body , hence we will create a list and the parameters which are not in request will be set null or 0.
        personal_info_list = ['profile_image', 'dob', 'name', 'zip_code', 'state', 'address', 'lat', 'lng', 'city']
        ios_personal_validations(personal_info_list, doc_obj, request)
        general_personal_validations(details, instance, request)
        try:
            point = Point(x=float(details.get('lat')), y=float(details.get('lng')), srid=4326)
            User.objects.filter(id=instance.id).update(cordinate=point, lat=float(details.get('lat')),
                                                       lng=float(details.get('lng')))
        except Exception:
            pass
        User.objects.filter(id=instance.id).update(**details)
        return_obj = User.objects.filter(id=instance.id).first()
        """
        email will be updated and then the verification link will be sent to the email to check is_email_verified
        """
        if not details.get('email') == instance.email:
            email_url = generate_email_verification_url(return_obj)
            url = emailverification_url + url_otp_variable + email_url
            send_verification_email(return_obj.email, url)
            User.objects.filter(id=instance.id).update(is_email_verified=False)
        return return_obj

    class Meta:
        model = User
        fields = (
            "first_name",
            "last_name",
            "name",
            "email",
            "password",
            "address",
            "lat",
            "lng",
            "phone_number",
            "user_role",
            "city",
            "state",
            "zip_code",
            "dob",
            "profile_image"
        )


class RetriveShiftManagementSerializer(serializers.ModelSerializer):
    class Meta:
        model = DynamicShiftManagement
        fields = ("__all__")


# personal details update response serializer
class DocEditDoctorResponseSerializer(DynamicFieldsModelSerializer):
    """
    Serializer to serializer user fields.
    """
    profile_image = AllImageSerializer(allow_null=True)
    dynamicshift = RetriveShiftManagementSerializer(allow_null=True)

    # personal details update
    class Meta:
        model = User
        fields = (
            "name",
            "first_name",
            "last_name",
            "email",
            "password",
            "address",
            "lat",
            "lng",
            "phone_number",
            "user_role",
            "city",
            "state",
            "zip_code",
            "dob",
            "designation",
            "medical_practice_id",
            "speciality",
            "experience",
            "shift",
            "is_profile_approved",
            "profile_image",
            "stripe_customer_id",
            "is_stripe_customer",
            "dynamicshift"
        )


class TemporaryEditDoctorInfoSerializer(serializers.Serializer):
    # temporary table for adding in professional details of doctor
    tempdoctorinfo_documents = serializers.PrimaryKeyRelatedField(
        required=False, queryset=AllImage.objects.all(), many=True
    )
    experience = serializers.FloatField(required=False)

    def update(self, instance, validated_data):
        # saving to the temporary table
        doc_obj = self.context.get("doc_obj")
        details = self.context.get("details")
        request = self.context.get("request")
        med_obj = self.context.get("med_obj")
        # here the doctor status is updated because the admin has to list doctors with status in UI(kindly check User model)
        User.objects.filter(id=request.user.id).update(status_doctor=2)
        # deleting documents which are present from before
        try:
            TempDoctorMedicalDoc.objects.filter(tempdoctorinfo_id=med_obj.id).all().delete()
        except Exception:
            pass
        TempDoctorWorkInfo.objects.filter(user_id=instance.user_id).update(
            user_id=instance.user_id,
            designation=details.get('designation'),
            medical_practice_id=details.get('medical_practice_id'),
            speciality=details.get('speciality'),
            shift=details.get('shift'),
            experience=details.get('experience')
        )
        # update documents
        if details.get('tempdoctorinfo_documents'):
            tempdoctorinfo_documents = details.pop('tempdoctorinfo_documents')
        else:
            tempdoctorinfo_documents = None
        if tempdoctorinfo_documents:
            if len(tempdoctorinfo_documents) > 3:
                raise serializers.ValidationError({
                    "status": 400,
                    "error": {
                        "location": "documents update",
                        "message": "The documents have to less then or equal to 3"
                    }
                })
            else:
                for med_obj in tempdoctorinfo_documents:
                    TempDoctorMedicalDoc.objects.update_or_create(tempdoctorinfo=instance, document_id=med_obj)
        noti_obj = User.objects.filter(user_role=1).first()
        filtered_obj = noti_obj.user_device.filter(is_active=True).all()
        title = "Doctor Professional Information Notice"
        message = "Kindly check the doctor's professional information"
        data = {"email": doc_obj.email}
        # send_notification(user_device_obj=filtered_obj,
        #                 title="Doctor Professional Information Notice",
        #                 message="Kindly check the doctor's professional information",
        #                 data={"email":doc_obj.email})
        UserActivity.objects.create(sender_id=doc_obj.id, receiver_id=noti_obj.id,
                                    activity_type=1, title=title, message=message, payload=data
                                    )
        return instance

    # tempdoctorinfo_documents is used as nested serializer for document update
    class Meta:
        model = TempDoctorWorkInfo
        fields = ('id', 'designation', 'medical_practice_id', 'speciality', 'experience',
                  'shift', 'tempdoctorinfo_documents'
                  )


class TempDoctorDocumentSerializer(serializers.ModelSerializer):
    # this is the nested serializer to get the id,name,url to the TemporaryDocWorkInfoResponseSerializer
    document = AllImageSerializer(allow_null=True, fields=("id", "url", "name"))

    class Meta:
        model = TempDoctorMedicalDoc
        fields = ("id", "tempdoctorinfo", "document", "is_deleted")


class TemporaryDocWorkInfoResponseSerializer(serializers.ModelSerializer):
    """
    professional details update response serializer
    """
    tempdoctorinfo_documents = TempDoctorDocumentSerializer(many=True)

    # professional details update
    class Meta:
        model = TempDoctorWorkInfo
        fields = ('id', 'designation', 'medical_practice_id', 'speciality', 'experience',
                  'shift', 'tempdoctorinfo_documents'
                  )


class VerifyDocWorkInfoSerializer(serializers.ModelSerializer):
    user_doctormedicaldoc = serializers.PrimaryKeyRelatedField(
        required=False, queryset=AllImage.objects.all(), many=True, allow_null=True
    )

    def update(self, instance, validated_data):
        user_id = self.context.get("user_id")
        request = self.context.get("request")
        if request.data.get("is_profile_approved") == True:
            verify_by_admin(validated_data, instance, user_id)
        User.objects.filter(id=user_id).update(is_profile_approved=request.data.get("is_profile_approved"))
        if request.data.get("is_profile_approved") == False:
            User.objects.filter(id=user_id).update(status_doctor=4)
        delete_from_temp_table_obj = TempDoctorWorkInfo.objects.filter(user_id=user_id).first()
        try:
            delete_from_temp_table_obj.delete()
        except Exception:
            pass
        return instance

    class Meta:
        model = User
        fields = (
            'designation',
            'medical_practice_id',
            'speciality',
            'experience',
            'shift',
            'user_doctormedicaldoc'
        )


class VerifyDocWorkInfoResponseSerializer(DynamicFieldsModelSerializer):
    """
    Serializer to serializer user fields.
    """
    user_doctormedicaldoc = DoctorDocumentSerializer(many=True)

    # user_doctormedicaldoc is used as nested serializer for document update
    class Meta:
        model = User
        fields = ('id', 'designation', 'medical_practice_id', 'speciality', 'experience', 'shift',
                  'is_profile_approved', 'admin_medical_practice_id', 'user_doctormedicaldoc'
                  )


# 20 Jan
class SymptomSerializer(serializers.ModelSerializer):
    def validate(self, validated_data):
        booking_id = self.context.get("booking_id")
        user_id = self.context.get("user_id")
        # if in query params the booking id passed doesnt exists then raise error
        if not Booking.objects.filter(id=booking_id).exists():
            raise serializers.ValidationError("The booking Id doesnt exist")
        if not Booking.objects.filter(patient_id=user_id).exists():
            raise serializers.ValidationError("The booking and authentication are not same")
        return validated_data

    def update(self, instance, validated_data):
        # validated_data.get("items") gives error if items is not passed(as manytomany field) or passed empty so try block used
        booking_id = self.context.get("booking_id")
        request = self.context.get("request")
        try:
            items = validated_data.pop("items")
        except Exception:
            pass
        # update doesnt give the object , it gives boolean hence med_obj is created for the instance
        symp_obj = Symptoms.objects.get(booking_id=booking_id)
        symp_obj.additional_info = request.data.get("additional_info")
        symp_obj.save()
        if not symp_obj:
            raise serializers.ValidationError({
                "status": 400,
                "error": {
                    "location": "Update symptoms",
                    "message": "Kindly create symptoms first"
                }})
        try:
            if items:
                symp_obj.items.clear()
                for item_obj in items:
                    symp_obj.items.add(item_obj)
            else:
                symp_obj.items.clear()
        except Exception:
            pass
        return symp_obj

    class Meta:
        model = Symptoms
        fields = ('__all__')


class SymptomsItemsSerializer(DynamicFieldsModelSerializer):
    is_selected = serializers.SerializerMethodField('IsSelected')

    def to_representation(self, instance):
        data = super(SymptomsItemsSerializer, self).to_representation(instance)
        dic = {}
        dic[data.get('category')] = [
            {"id": data.get('id'), "name": data.get('subcategory'), "is_selected": data.get('is_selected')}]
        return dic

    def IsSelected(self, obj):
        symptom_obj = self.context.get('symptom_obj')
        if obj.id in symptom_obj.items.values_list('id', flat=True):
            return True
        else:
            return False

    class Meta:
        model = SymptomsItems
        fields = ('id', 'subcategory', 'category', 'is_selected')


class SymptomResponseSerializer(DynamicFieldsModelSerializer):
    """serializer to listing symptoms along with its category and subcategory"""
    items = SymptomsItemsSerializer(many=True)

    class Meta:
        model = Symptoms
        fields = ('__all__')


# 25Jan
class RequestvisitSerializer(serializers.ModelSerializer):

    def validate(self, attrs):
        request = self.context.get('request')
        if attrs.get('source_address') and (not request.data.get('source_lat') or not request.data.get('source_lng')):
            raise serializers.ValidationError("Kindly give lat and lng")
        if attrs.get("familymember") and attrs.get("booking_for") == 1:
            raise serializers.ValidationError("booking for is passed for patient and in familymember id is given")
        if not attrs.get("familymember") and attrs.get("booking_for") == 2:
            raise serializers.ValidationError(
                "booking for is passed for familymember and in familymember id is not given")
        return attrs

    def create(self, validated_data):
        request = self.context.get('request')
        lat = float(request.data.get('source_lat'))
        lng = float(request.data.get('source_lng'))
        point = Point(x=lng, y=lat, srid=4326)
        validated_data.update({"source_cordinate": point})
        validated_data.update({"patient": request.user})
        obj = Booking.objects.create(**validated_data)
        Symptoms.objects.create(booking_id=obj)
        return obj

    def update(self, instance, validated_data):
        lat = float(validated_data.get('source_lat'))
        lng = float(validated_data.get('source_lng'))
        point = Point(x=lng, y=lat, srid=4326)
        validated_data.update({"source_cordinate": point})
        if validated_data.get('booking_for') == Booking.PATIENTSELF:
            # Booking.PatientSelf is 1
            Booking.objects.filter(id=instance.id).update(familymember_id=None)
        Booking.objects.filter(id=instance.id).update(**validated_data)
        obj = Booking.objects.get(id=instance.id)
        return obj

    class Meta:
        model = Booking
        fields = ('__all__')


class BookingListNestedSerializer(DynamicFieldsModelSerializer):
    profile_image = AllImageSerializer(allow_null=True)

    class Meta:
        model = User
        fields = ['id', 'name', 'profile_image', 'dob', 'experience', 'medical_practice_id']


class RequestvisitResponseSerializer(serializers.ModelSerializer):
    doctor = BookingListNestedSerializer(allow_null=True, many=False)

    class Meta:
        model = Booking
        fields = ('__all__')


"""
For Book now there is seperate API triggering
"""


class BookNowLaterVisitSerializer(serializers.ModelSerializer):
    def validate(self, attrs):
        if not attrs.get('visit_type'):
            raise serializers.ValidationError("Please provide visit_type")
        if not attrs.get('visit_now_later'):
            raise serializers.ValidationError("Kindly provide the visit_now_later")
        if not attrs.get('hub'):
            raise serializers.ValidationError("Please provide nearest hub ")
        return attrs

    def update(self, instance, validated_data):
        request = self.context.get('request')
        # here we are storing the visit type and visit now or later in the obj of booking
        # so that in coming lines we can use status=BOOKING_CREATED(same api mey kaam ho jaae)
        Booking.objects.filter(id=instance.id).update(visit_type=validated_data.get('visit_type'))
        Booking.objects.filter(id=instance.id).update(visit_now_later=validated_data.get('visit_now_later'))
        Booking.objects.filter(id=instance.id).update(hub_id=validated_data.get('hub'))
        # mapping the hub "amount" to the booking "total_amount"
        Booking.objects.filter(id=instance.id).update(
            total_amount=Hub.objects.get(id=validated_data.get('hub').id).amount)
        booking_obj = Booking.objects.get(id=instance.id)
        if booking_obj.visit_now_later == Booking.VISIT_NOW:
            if validated_data.get('visit_type') == Booking.MOBILE_DOCTOR:
                # here all the doctor for today who are assigned van in the hub are in obj
                doctor_assigned = DoctorAssignDaily.objects.filter(
                    content_type_id=ContentType.objects.get(model='van').id,
                    visit_type=1,
                    hub_id=booking_obj.hub_id,
                    shift=request.data.get("shift"),
                    # shift start time and end time is taken as booking can at 8:50 and at 9:00 the shift gets over
                    shift_start_time__lte=request.data.get("datetime"),
                    shift_end_time__gte=request.data.get("datetime")
                )
                # print(doctor_assigned,"doctor_assigned is as -")
                if not doctor_assigned:
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "Update Booking, doctor unavailable",
                            "message": "The doctor is not available for this visit"
                        }})
                # here the vans which are booked and not cancelled are stored in that hub
                vans_booked = Booking.objects.filter(visit_start_time__lte=request.data.get("datetime"),
                                                     visit_end_time__gte=request.data.get("datetime"),
                                                     hub_id=booking_obj.hub_id).exclude(van_id=(None,)).exclude(
                    state=2)
                # print(vans_booked,"vans_booked is as -")
                # Now the doctors assigned vans and vans booked for that duration is obtained
                # (for that hub , during ride now time),hence we take out the difference betwween them
                # here we get the id's as in queryset <QuerySet [(4,), (5,), (8,), (2,), (9,), (7,), (10,), (11,)]>
                id_vans_booked = vans_booked.values_list('van_id')
                id_doctor_assigned_van = doctor_assigned.values_list('object_id')
                # print(id_doctor_assigned_van,"id_doctor_assigned_van is as -")
                # queryset difference is taken out and id_doctor_assigned_van-id_vans_booked=available vans
                van_avail = id_doctor_assigned_van.difference(id_vans_booked)
                # print(van_avail,"van_avail is as -")
                # [0] is used as tuple is in the queryset
                try:
                    remove_from_tuple = random.choice(van_avail)[0]
                except Exception:
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "Update Booking , doctor unavailable",
                            "message": "The doctor is not available for this visit type"
                        }})
                # 1
                return_avail_van_obj = Van.objects.get(id=remove_from_tuple)
                # print(return_avail_van_obj,"return_avail_van_obj is as -")
                Booking.objects.filter(id=instance.id).update(van_id=return_avail_van_obj)
                # here the doctor_id is stored in the booking table
                doctor_id = DoctorAssignDaily.objects.get(object_id=remove_from_tuple,
                                                          content_type_id=ContentType.objects.get(model='van').id,
                                                          visit_type=1,
                                                          hub_id=booking_obj.hub_id,
                                                          shift=request.data.get('shift'),
                                                          shift_start_time__lte=request.data.get("datetime"),
                                                          shift_end_time__gte=request.data.get("datetime")
                                                          )
                Booking.objects.filter(id=instance.id).update(doctor_id=doctor_id.doctor_id)
            if validated_data.get('visit_type') == Booking.VIDEO_CONFERENCING:
                # option is 2 for Booking.VIDEO_CONFERENCING
                doctor_assigned = DoctorAssignDaily.objects.filter(
                    content_type_id=ContentType.objects.get(model='virtualroom').id,
                    visit_type=2,
                    hub_id=booking_obj.hub_id,
                    shift=request.data.get("shift"),
                    shift_start_time__lte=request.data.get("datetime"),
                    shift_end_time__gte=request.data.get("datetime")
                )
                if not doctor_assigned:
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "Update Booking, unavailable doctor",
                            "message": "The doctor isn't available for this visit type."
                        }})
                virtualroom_booked = Booking.objects.filter(visit_start_time__lte=request.data.get("datetime"),
                                                            visit_end_time__gte=request.data.get("datetime"),
                                                            hub_id=validated_data.get('hub')).exclude(
                    virtualroom_id=(None,)).exclude(state=2)
                id_vr_booked = virtualroom_booked.values_list('virtualroom_id')
                id_doctor_assigned_vr = doctor_assigned.values_list('object_id')
                vr_avail = id_doctor_assigned_vr.difference(id_vr_booked)
                try:
                    remove_from_tuple = random.choice(vr_avail)[0]
                except Exception:
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "Update Booking , unavailable doctor",
                            "message": "The doctor is not available for this visittype"
                        }})
                return_avail_vr_obj = VirtualRoom.objects.get(id=remove_from_tuple)
                Booking.objects.filter(id=instance.id).update(virtualroom_id=return_avail_vr_obj)
                doctor_id = DoctorAssignDaily.objects.get(object_id=remove_from_tuple,
                                                          content_type_id=ContentType.objects.get(
                                                              model='virtualroom').id,
                                                          visit_type=2,
                                                          hub_id=booking_obj.hub_id,
                                                          shift=request.data.get("shift"),
                                                          shift_start_time__lte=request.data.get("datetime"),
                                                          shift_end_time__gte=request.data.get("datetime")
                                                          )
                Booking.objects.filter(id=instance.id).update(doctor_id=doctor_id.doctor_id)
            if validated_data.get('visit_type') == Booking.HUB_VISIT:
                # option is 3 for Booking.HUB_VISIT
                doctor_assigned = DoctorAssignDaily.objects.filter(
                    content_type_id=ContentType.objects.get(model='room').id,
                    visit_type=3,
                    hub_id=booking_obj.hub_id,
                    shift=request.data.get("shift"),
                    shift_start_time__lte=request.data.get("datetime"),
                    shift_end_time__gte=request.data.get("datetime")
                )
                if not doctor_assigned:
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "Doctor Unavailable",
                            "message": "Doctor is not available for this visit type."
                        }})
                room_booked = Booking.objects.filter(visit_start_time__lte=request.data.get("datetime"),
                                                     visit_end_time__gte=request.data.get("datetime"),
                                                     hub_id=validated_data.get('hub')).exclude(
                    room_id=(None,)).exclude(state=2)
                id_room_booked = room_booked.values_list('room_id')
                id_doctor_assigned_room = doctor_assigned.values_list('object_id')
                room_avail = id_doctor_assigned_room.difference(id_room_booked)
                try:
                    remove_from_tuple = random.choice(room_avail)[0]
                except Exception:
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "Doctor Unavailable, Update Booking",
                            "message": "Doctor isn't available for this visit type."
                        }})
                return_avail_room_obj = Room.objects.get(id=remove_from_tuple)
                Booking.objects.filter(id=instance.id).update(room_id=return_avail_room_obj)
                doctor_id = DoctorAssignDaily.objects.get(object_id=remove_from_tuple,
                                                          content_type_id=ContentType.objects.get(model='room').id,
                                                          visit_type=3,
                                                          hub_id=booking_obj.hub_id,
                                                          shift=request.data.get("shift"),
                                                          shift_start_time__lte=request.data.get("datetime"),
                                                          shift_end_time__gte=request.data.get("datetime")
                                                          )
                Booking.objects.filter(id=instance.id).update(doctor_id=doctor_id.doctor_id)
        # Booking later update
        if booking_obj.visit_now_later == Booking.VISIT_LATER:
            if not (validated_data.get('visit_start_time') or validated_data.get('visit_end_time')):
                raise serializers.ValidationError({
                    "status": 400,
                    "error": {
                        "location": "Update Booking, Time",
                        "message": "kindly provide both visit start and end time"
                    }})
            Booking.objects.filter(id=instance.id).update(visit_start_time=validated_data.get('visit_start_time'))
            Booking.objects.filter(id=instance.id).update(visit_end_time=validated_data.get('visit_end_time'))
            # When the request is as {"visit_type":2,"shift":2,"date":"2021-10-03","visit_space":21,"doctor":9}
            # and the same booking is updated at different date and rest are same then vr will also be same
            # so the vr_avail will be id_vr_booked <QuerySet [(21,)]> - id_doctor_assigned_vr <QuerySet [(21,)]> = 0
            # so below is updated
            Booking.objects.filter(id=instance.id).update(doctor_id=None, visit_type=None, co_pay=None,
                                                          van_id=None, virtualroom_id=None, room_id=None)
            book_obj_now = Booking.objects.get(id=instance.id)
            # thie is for van booking
            if validated_data.get('visit_type') == Booking.MOBILE_DOCTOR:
                doctor_assigned = DoctorAssignDaily.objects.filter(
                    content_type_id=ContentType.objects.get(model='van').id,
                    visit_type=1,
                    hub_id=book_obj_now.hub_id,
                    shift_start_time__lte=book_obj_now.visit_start_time,
                    shift_end_time__gte=book_obj_now.visit_end_time)
                if not doctor_assigned:
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "Update booking",
                            "message": "Doctor is not available  for this visit type, Please contact Admin"
                        }})
                vans_booked = Booking.objects.filter(visit_start_time__lte=book_obj_now.visit_start_time,
                                                     visit_end_time__gte=book_obj_now.visit_end_time,
                                                     hub_id=book_obj_now.hub_id).exclude(van_id=(None,)).exclude(
                    state=2)
                id_vans_booked = vans_booked.values_list('van_id')
                id_doctor_assigned_van = doctor_assigned.values_list('object_id')
                van_avail = id_doctor_assigned_van.difference(id_vans_booked)
                try:
                    remove_from_tuple = random.choice(van_avail)[0]
                except Exception:
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "update booking ,  doctor unavailable",
                            "message": "Doctor's aren't available for this visit type."
                        }})
                return_avail_van_obj = Van.objects.get(id=remove_from_tuple)
                Booking.objects.filter(id=instance.id).update(van_id=return_avail_van_obj)
                doctor_id = DoctorAssignDaily.objects.get(object_id=remove_from_tuple,
                                                          content_type_id=ContentType.objects.get(model='van').id,
                                                          visit_type=1,
                                                          hub_id=book_obj_now.hub_id,
                                                          shift_start_time__lte=book_obj_now.visit_start_time,
                                                          shift_end_time__gte=book_obj_now.visit_end_time)
                Booking.objects.filter(id=instance.id).update(doctor_id=doctor_id.doctor_id)
            # for the booking later of the video conferencing
            if validated_data.get('visit_type') == Booking.VIDEO_CONFERENCING:
                doctor_assigned = DoctorAssignDaily.objects.filter(
                    content_type_id=ContentType.objects.get(model='virtualroom').id,
                    visit_type=2,
                    hub_id=book_obj_now.hub_id,
                    shift_start_time__lte=book_obj_now.visit_start_time,
                    shift_end_time__gte=book_obj_now.visit_end_time)
                if not doctor_assigned:
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "Virtual Room ",
                            "message": "Doctor's aren't available for this visit."
                        }})
                virtualroom_booked = Booking.objects.filter(visit_start_time__lte=book_obj_now.visit_start_time,
                                                            visit_end_time__gte=book_obj_now.visit_end_time,
                                                            hub_id=book_obj_now.hub_id).exclude(
                    virtualroom_id=(None,)).exclude(
                    state=2)
                id_vr_booked = virtualroom_booked.values_list('virtualroom_id')
                id_doctor_assigned_vr = doctor_assigned.values_list('object_id')
                vr_avail = id_doctor_assigned_vr.difference(id_vr_booked)
                try:
                    remove_from_tuple = random.choice(vr_avail)[0]
                except Exception:
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "Update Booking , virtual room",
                            "message": "Please contact Admin, the doctor is not available for this visit."
                        }})
                return_avail_vr_obj = VirtualRoom.objects.get(id=remove_from_tuple)
                Booking.objects.filter(id=instance.id).update(virtualroom_id=return_avail_vr_obj)
                doctor_id = DoctorAssignDaily.objects.get(object_id=remove_from_tuple,
                                                          content_type_id=ContentType.objects.get(
                                                              model='virtualroom').id,
                                                          visit_type=2,
                                                          hub_id=book_obj_now.hub_id,
                                                          shift_start_time__lte=book_obj_now.visit_start_time,
                                                          shift_end_time__gte=book_obj_now.visit_end_time)
                Booking.objects.filter(id=instance.id).update(doctor_id=doctor_id.doctor_id)
            # here book later for the hub visit
            if validated_data.get('visit_type') == Booking.HUB_VISIT:
                doctor_assigned = DoctorAssignDaily.objects.filter(
                    content_type_id=ContentType.objects.get(model='room').id,
                    visit_type=3,
                    hub_id=book_obj_now.hub_id,
                    shift_start_time__lte=book_obj_now.visit_start_time,
                    shift_end_time__gte=book_obj_now.visit_end_time)
                if not doctor_assigned:
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "Update Booking, Room unavailable",
                            "message": "The doctor is not available for the visit type"
                        }})
                rooms_booked = Booking.objects.filter(visit_start_time__lte=book_obj_now.visit_start_time,
                                                      visit_end_time__gte=book_obj_now.visit_end_time,
                                                      hub_id=book_obj_now.hub_id).exclude(room_id=(None,)).exclude(
                    state=2)
                id_room_booked = rooms_booked.values_list('room_id')
                id_doctor_assigned_room = doctor_assigned.values_list('object_id')
                room_avail = id_doctor_assigned_room.difference(id_room_booked)
                try:
                    remove_from_tuple = random.choice(room_avail)[0]
                except Exception:
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "Update Booking, Room Unavailable",
                            "message": "The doctor is not available for this visit type."
                        }})
                return_avail_room_obj = Room.objects.get(id=remove_from_tuple)
                Booking.objects.filter(id=instance.id).update(room_id=return_avail_room_obj)
                doctor_id = DoctorAssignDaily.objects.get(object_id=remove_from_tuple,
                                                          content_type_id=ContentType.objects.get(model='room').id,
                                                          visit_type=3,
                                                          hub_id=book_obj_now.hub_id,
                                                          shift_start_time__lte=book_obj_now.visit_start_time,
                                                          shift_end_time__gte=book_obj_now.visit_end_time)
                Booking.objects.filter(id=instance.id).update(doctor_id=doctor_id.doctor_id)
        obj = Booking.objects.get(id=instance.id)
        obj.destination_lat = obj.hub.lat
        obj.destination_lng = obj.hub.lng
        point = Point(x=float(obj.destination_lng), y=float(obj.destination_lat), srid=4326)
        obj.destination_cordinate = point
        obj.destination_address = obj.hub.address
        obj.visit_type = validated_data.get('visit_type')
        obj.save()
        return obj

    class Meta:
        model = Booking
        fields = ('__all__')


class BookNowVisitlaterResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = ('id', 'hub_id', 'doctor_id', 'visit_type', 'van_id', 'virtualroom_id', 'room_id', 'visit_now_later',
                  'total_amount')


# visit start and end time for the book now
class BookNowStartEndTimeSerializer(serializers.ModelSerializer):
    def update(self, instance, validated_data):
        booking_obj = Booking.objects.get(id=instance.id)
        if booking_obj.visit_type == Booking.MOBILE_DOCTOR:
            if (validated_data.get('visit_start_time') + timedelta(hours=1)) != validated_data.get('visit_end_time'):
                raise serializers.ValidationError({
                    "status": 400,
                    "error": {
                        "location": "start end time",
                        "message": "Enter timing with 1 hr difference"
                    }})
            booking_obj.visit_start_time = validated_data.get('visit_start_time')
            booking_obj.visit_end_time = validated_data.get('visit_end_time')
        if booking_obj.visit_type == Booking.VIDEO_CONFERENCING or booking_obj.visit_type == Booking.HUB_VISIT:
            if (validated_data.get('visit_start_time') + timedelta(minutes=30)) != validated_data.get('visit_end_time'):
                raise serializers.ValidationError({
                    "status": 400,
                    "error": {
                        "location": "start end time",
                        "message": "Enter timing with 30 min difference"
                    }})
            booking_obj.visit_start_time = validated_data.get('visit_start_time')
            booking_obj.visit_end_time = validated_data.get('visit_end_time')
        booking_obj.state = validated_data.get('state')
        booking_obj.save()
        return booking_obj

    class Meta:
        model = Booking
        fields = ('__all__')


class BookNowStartEndTimeResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = ('id', 'visit_start_time', 'visit_end_time', 'state')


# noinspection PyUnboundLocalVariable
class DoctorAssignSerializer(serializers.ModelSerializer):

    def validate_date(self, date):
        # date valiadation for the assigning doctor to hub
        """
         For ex- if the booking is for 6:30 am then shift 3 of previous day doctor will be assigned ,
         if not there then patient mey contact admin and on urgent basis the doctor might be assigned
         for the previous day shift 3 for making the booing possible.
         Hence previous day doctor assignement is possible
         """
        if date < date.today() - timedelta(days=1):
            raise serializers.ValidationError("Kindly enter correct date")
        return date

    def validate(self, attrs):
        request = self.context.get("request")
        user_obj = User.objects.filter(id=request.data.get('doctor'), user_role=4).first()
        if not user_obj:
            raise serializers.ValidationError("Kindly assign to Doctor only")
        """
           validating that if doctor is on leave or not
        """
        if DoctorDailyAvailability.objects.filter(doctor=user_obj, date=request.data.get('date'),
                                                  is_available=False).exists():
            raise serializers.ValidationError("Doctor is not available for this day")
        # van = ContentType.objects.get(model='van');van_id = van.id
        # room = ContentType.objects.get(model='room');room_id = room.id
        # virtualroom = ContentType.objects.get(model='virtualroom');virtualroom_id = virtualroom.id
        # doctor will not be assigned if these are the creteria below
        # this is for van booked ie. mobile doctor ie. visit_type=1
        # the  visit_type  and the shift timingsare the pivot for bifurcation
        # issse, van , vr or room tab hi assign hoga jab van,room,vr free ho, matlab book na hue ho
        if request.data.get('visit_type') == 1:
            try:
                assign_van = Van.objects.get(id=request.data.get('visit_space'))
            except Exception:
                raise serializers.ValidationError("Invalid van id")
            if request.data.get('shift') == 1:
                if Booking.objects.filter(van_id=request.data.get('visit_space'),
                                          visit_start_time__date=request.data.get('date'),
                                          visit_start_time__time__gte="07:00:00",
                                          visit_end_time__time__lte="15:00:00",
                                          hub_id=assign_van.hub_id
                                          ).exclude(state=2):
                    raise serializers.ValidationError("Van is booked, please assign another Van")
            if request.data.get('shift') == 2:
                if Booking.objects.filter(van_id=request.data.get('visit_space'),
                                          visit_start_time__date=request.data.get('date'),
                                          visit_start_time__time__gte="15:00:00",
                                          visit_end_time__time__lte="22:00:00",
                                          hub_id=assign_van.hub_id
                                          ).exclude(state=2):
                    raise serializers.ValidationError("The Van is booked")
            # here or is used to get the date as timing of shift 3 cross the date to another
            if request.data.get('shift') == 3:
                if (Booking.objects.filter(van_id=request.data.get('visit_space'),
                                           visit_start_time__date=request.data.get('date'),
                                           visit_start_time__time__gte="22:00:00",
                                           hub_id=assign_van.hub_id
                                           ).exclude(state=2)
                        or
                        Booking.objects.filter(van_id=request.data.get('visit_space'),
                                               visit_end_time__date=datetime.strptime(request.data.get('date'),
                                                                                      '%Y-%m-%d'
                                                                                      ) + timedelta(days=1),
                                               visit_end_time__time__lte="07:00:00",
                                               hub_id=assign_van.hub_id
                                               ).exclude(state=2)):
                    raise serializers.ValidationError("Van is booked")
        # doctor will not be assigned if these are the creteria below
        # this is for video conferencing ie. virtual room ie. visit_type=2
        # the shift timings and the visit_type are the pivot for bifurcation
        if request.data.get('visit_type') == 2:
            try:
                assign_virtualroom = VirtualRoom.objects.get(id=request.data.get('visit_space'))
            except Exception:
                raise serializers.ValidationError("Invalid VR id")
            if request.data.get('shift') == 1:
                if Booking.objects.filter(virtualroom_id=request.data.get('visit_space'),
                                          visit_start_time__date=request.data.get('date'),
                                          visit_start_time__time__gte="07:00:00",
                                          visit_end_time__time__lte="15:00:00",
                                          hub_id=assign_virtualroom.hub_id
                                          ).exclude(state=2):
                    raise serializers.ValidationError("The Virtual room is booked")
            if request.data.get('shift') == 2:
                if Booking.objects.filter(virtualroom_id=request.data.get('visit_space'),
                                          visit_start_time__date=request.data.get('date'),
                                          visit_start_time__time__gte="15:00:00",
                                          visit_end_time__time__lte="22:00:00",
                                          hub_id=assign_virtualroom.hub_id
                                          ).exclude(state=2):
                    raise serializers.ValidationError("Virtual room is booked, please assign another virtual room")
            # here or is used to get the date as timing of shift 3 cross the date to another
            if request.data.get('shift') == 3:
                if (Booking.objects.filter(virtualroom_id=request.data.get('visit_space'),
                                           visit_start_time__date=request.data.get('date'),
                                           visit_start_time__time__gte="22:00:00",
                                           hub_id=assign_virtualroom.hub_id
                                           ).exclude(state=2)
                        or
                        Booking.objects.filter(virtualroom_id=request.data.get('visit_space'),
                                               visit_end_time__date=datetime.strptime(request.data.get('date'),
                                                                                      '%Y-%m-%d'
                                                                                      ) + timedelta(days=1),
                                               visit_end_time__time__lte="07:00:00",
                                               hub_id=assign_virtualroom.hub_id
                                               ).exclude(state=2)):
                    raise serializers.ValidationError("Virtual room is booked")
        # doctor will not be assigned if these are the creteria below
        # this is for hub visit ie. room ie. visit_type=3
        # the shift timings and the visit_type are the pivot for bifurcation
        if request.data.get('visit_type') == 3:
            try:
                assign_room = Room.objects.get(id=request.data.get('visit_space'))
            except Exception:
                raise serializers.ValidationError("Invalid room id")
            if request.data.get('shift') == 1:
                if Booking.objects.filter(room_id=request.data.get('visit_space'),
                                          visit_start_time__date=request.data.get('date'),
                                          visit_start_time__time__gte="07:00:00",
                                          visit_end_time__time__lte="15:00:00",
                                          hub_id=assign_room.hub_id
                                          ).exclude(state=2):
                    raise serializers.ValidationError("This Room is booked")
            if request.data.get('shift') == 2:
                if Booking.objects.filter(room_id=request.data.get('visit_space'),
                                          visit_start_time__date=request.data.get('date'),
                                          visit_start_time__time__gte="15:00:00",
                                          visit_end_time__time__lte="22:00:00",
                                          hub_id=assign_room.hub_id
                                          ).exclude(state=2):
                    raise serializers.ValidationError("This Room is booked, please assign another room")
            # here or is used to get the date as timing of shift 3 cross the date to another
            if request.data.get('shift') == 3:
                if (Booking.objects.filter(room_id=request.data.get('visit_space'),
                                           visit_start_time__date=request.data.get('date'),
                                           visit_start_time__time__gte="22:00:00",
                                           hub_id=assign_room.hub_id
                                           ).exclude(state=2)
                        or
                        Booking.objects.filter(room_id=request.data.get('visit_space'),
                                               visit_end_time__date=datetime.strptime(request.data.get('date'),
                                                                                      '%Y-%m-%d'
                                                                                      ) + timedelta(days=1),
                                               visit_end_time__time__lte="07:00:00",
                                               hub_id=assign_room.hub_id
                                               ).exclude(state=2)):
                    raise serializers.ValidationError("Room is booked")

        return attrs

    # create the doctor assign daily
    def create(self, validated_data):
        request = self.context.get("request")
        # We are using visit_space i.e Generic foreign key usage, so regular create cannot be used
        # try block is used to give it a check that if Van is not present then except block throws validation error
        if validated_data.get('visit_type') == 1:
            try:
                assign_van = Van.objects.get(id=request.data.get('visit_space'))
                """
                Here generic relation could be used to check for the ,van jo kissi aur doctor ko 
                same shift pe, same din pe assign toh nai hai!!! 
                """
                if DoctorAssignDaily.objects.filter(object_id=assign_van.id,
                                                    date=request.data.get('date'),
                                                    shift=request.data.get('shift'),
                                                    visit_type=request.data.get('visit_type')).exists():
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "Assign Doctor",
                            "message": "The Van is assigned to the other doctor"
                        }})
                assign_obj = DoctorAssignDaily.objects.create(visit_type=1, visit_space=assign_van,
                                                              hub_id=assign_van.hub_id)
            except Van.DoesNotExist:
                raise serializers.ValidationError({
                    "status": 400,
                    "error": {
                        "location": "assign  doctor",
                        "message": "Invalid visit_space i.e Van id !!"
                    }})
        if validated_data.get('visit_type') == 2:
            try:
                assign_virtualroom = VirtualRoom.objects.get(id=request.data.get('visit_space'))
                if DoctorAssignDaily.objects.filter(object_id=assign_virtualroom.id,
                                                    date=request.data.get('date'),
                                                    shift=request.data.get('shift'),
                                                    visit_type=request.data.get('visit_type')).exists():
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "Assign doctor",
                            "message": "The Virtual Room is assigned to the other doctor . "
                        }})
                assign_obj = DoctorAssignDaily.objects.create(visit_type=2, visit_space=assign_virtualroom,
                                                              hub_id=assign_virtualroom.hub_id)
            except VirtualRoom.DoesNotExist:
                raise serializers.ValidationError({
                    "status": 400,
                    "error": {
                        "location": "Assign  doctor",
                        "message": "Invalid visit_space i.e Virtual Room id !!"
                    }})
        if validated_data.get('visit_type') == 3:
            try:
                assign_room = Room.objects.get(id=request.data.get('visit_space'))
                if DoctorAssignDaily.objects.filter(object_id=assign_room.id,
                                                    date=request.data.get('date'),
                                                    shift=request.data.get('shift'),
                                                    visit_type=request.data.get('visit_type')).exists():
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "Assign  Doctor",
                            "message": "The Room is assigned to the other doctor"
                        }})
                assign_obj = DoctorAssignDaily.objects.create(visit_type=3, visit_space=assign_room,
                                                              hub_id=assign_room.hub_id)
            except Room.DoesNotExist:
                raise serializers.ValidationError({
                    "status": 400,
                    "error": {
                        "location": "assign doctor.",
                        "message": "Invalid visit_space i.e Room id !!"
                    }})
        assign_obj.date = validated_data.get('date')
        # validated_data.get('doctor') will give us object as doctor is the fk assigned in the model
        doctor_obj = User.objects.get(id=validated_data.get('doctor').id)
        assign_obj.doctor_id = doctor_obj.id
        assign_obj.date = request.data.get('date')
        assign_obj.shift = request.data.get('shift')
        str_to_date_type = datetime.strptime(request.data.get('date'), '%Y-%m-%d').date()
        shift_date_with_zero_time = datetime.combine(str_to_date_type, time.min)

        if request.data.get('shift') == DoctorAssignDaily.MORNING:
            assign_obj.shift_start_time = shift_date_with_zero_time + timedelta(hours=7)
            assign_obj.shift_end_time = shift_date_with_zero_time + timedelta(hours=15)
        if request.data.get('shift') == DoctorAssignDaily.AFTERNOON:
            assign_obj.shift_start_time = shift_date_with_zero_time + timedelta(hours=15)
            assign_obj.shift_end_time = shift_date_with_zero_time + timedelta(hours=22)
        if request.data.get('shift') == DoctorAssignDaily.EVENING:
            assign_obj.shift_start_time = shift_date_with_zero_time + timedelta(hours=22)
            assign_obj.shift_end_time = shift_date_with_zero_time + timedelta(hours=31)
        working_hours = assign_obj.shift_end_time - assign_obj.shift_start_time
        working_hours_value_to_format = datetime.strptime(str(working_hours), '%H:%M:%S').time()
        assign_obj.workinghours = working_hours_value_to_format
        assign_obj.save()
        designation_obj = Designation_Amount.objects.filter(designation_type=doctor_obj.designation).first()

        """
        convert string time to integer format to calculate the amount_perday
        """
        str_value = str(working_hours)
        value_split = str_value.split(":")  # ['07', '10', '00']
        """
        Here if the working hour is  07:10:00 then amount perday will be calculated 
        according to  07:00:00 i.e. 7 hours.
        If the working hour is  07:40:00 then amount perday will be calculated 
        according to  07:30:00 ie.7.5 hours.
        """
        if int(value_split[1]) < 30:
            value_split[1] = 0
        elif int(value_split[1]) <= 59:
            value_split[1] = 5
        value_decimal = int(value_split[0]) + (int(value_split[1]) / 10)  # 07:40:00 to 7.5 hour
        amount_perday = float(value_decimal) * float(designation_obj.designation_amount)
        if not DoctorPerDayAmount.objects.filter(payment_perday_date=assign_obj.date, user_id=doctor_obj.id).exists():
            DoctorPerDayAmount.objects.create(payment_perday_date=assign_obj.date,
                                              user_id=doctor_obj.id,
                                              workinghours=working_hours_value_to_format,
                                              designation_amount=designation_obj,
                                              amount_perday=amount_perday)
        else:
            adminpayment_obj = DoctorPerDayAmount.objects.filter(payment_perday_date=assign_obj.date,
                                                                 user_id=doctor_obj.id).first()
            adminpayment_obj.amount_perday = adminpayment_obj.amount_perday + amount_perday
            # below 3 lines are for adding the datetime.time with datetime.time
            a_datetime = datetime.combine(date.today(), adminpayment_obj.workinghours)
            new_datetime = a_datetime + timedelta(hours=working_hours_value_to_format.hour)
            combined_workinghours = new_datetime.time()
            adminpayment_obj.workinghours = combined_workinghours
            # if the doctor works for 24 hours then 24:00:00 doesnt exist , hence we will show 23:59:59
            if str(adminpayment_obj.workinghours) == '00:00:00':
                adminpayment_obj.workinghours = time(23, 59, 59)
            adminpayment_obj.save()
        return assign_obj

    """
    we are updating the doctor which is assigned on daily basis
    """

    def update(self, instance, validated_data):
        request = self.context.get('request')
        obj = DoctorAssignDaily.objects.get(id=instance.id)
        if validated_data.get('visit_type') == 1:
            try:
                # filtering and updating doesnt work for generic foreign key
                # the error will be as  Use a value compatible with GenericForeignKey.
                # We have to update it as an object
                # mobile doctor ka content_type_id=14(van) hai toh check lagaya hai
                assign_van = Van.objects.get(id=request.data.get('visit_space'))
                if DoctorAssignDaily.objects.filter(object_id=assign_van.id,
                                                    date=request.data.get('date'),
                                                    shift=request.data.get('shift'),
                                                    content_type_id=ContentType.objects.get(model='van').id,
                                                    hub_id=obj.hub_id).exclude(id=obj.id).exists():
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "assign doctor .",
                            "message": "The Van is assigned to the other doctor"
                        }})
                obj.visit_type = 1
                obj.visit_space = assign_van
            except Van.DoesNotExist:
                raise serializers.ValidationError({
                    "status": 400,
                    "error": {
                        "location": "assign doctor . ",
                        "message": "Invalid visit_space i.e Van id !!"
                    }})
        if validated_data.get('visit_type') == 2:
            try:
                assign_virtualroom = VirtualRoom.objects.get(id=request.data.get('visit_space'))
                if DoctorAssignDaily.objects.filter(object_id=assign_virtualroom.id,
                                                    date=request.data.get('date'),
                                                    shift=request.data.get('shift'),
                                                    content_type_id=ContentType.objects.get(model='virtualroom').id,
                                                    hub_id=obj.hub_id).exclude(id=obj.id).exists():
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "assign  doctor.",
                            "message": "The Virtual Room is  assigned to the other doctor."
                        }})
                obj.visit_type = 2
                obj.visit_space = assign_virtualroom
            except VirtualRoom.DoesNotExist:
                raise serializers.ValidationError({
                    "status": 400,
                    "error": {
                        "location": "assign  doctor . ",
                        "message": "Invalid visit_space i.e Virtual Room id !!"
                    }})
        if validated_data.get('visit_type') == 3:
            try:
                assign_room = Room.objects.get(id=request.data.get('visit_space'))
                if DoctorAssignDaily.objects.filter(object_id=assign_room.id,
                                                    date=request.data.get('date'),
                                                    shift=request.data.get('shift'),
                                                    content_type_id=ContentType.objects.get(model='room').id,
                                                    hub_id=obj.hub_id).exclude(id=obj.id).exists():
                    raise serializers.ValidationError({
                        "status": 400,
                        "error": {
                            "location": "assign  doctor .",
                            "message": "The Virtual Room is assigned to the other doctor"
                        }})
                obj.visit_type = 3
                obj.visit_space = assign_room
            except Room.DoesNotExist:
                raise serializers.ValidationError({
                    "status": 400,
                    "error": {
                        "location": " assign doctor  ",
                        "message": "Invalid visit_space i.e Room id !!"
                    }})
        obj.date = validated_data.get('date')
        doctor_obj = User.objects.get(id=validated_data.get('doctor').id)
        """
        here if the doctor is updated then booking will change the doctor id and payment will deduct from old doctor
        old_doctor_obj = obj
        new_doctor_obj = doctor_obj
        """
        obj.doctor_id = doctor_obj.id
        obj.date = request.data.get('date')
        obj.shift = request.data.get('shift')
        str_to_date_type = datetime.strptime(request.data.get('date'), '%Y-%m-%d').date()
        shift_date_with_zero_time = datetime.combine(str_to_date_type, time.min)
        if request.data.get('shift') == DoctorAssignDaily.MORNING:
            obj.shift_start_time = shift_date_with_zero_time + timedelta(hours=7)
            obj.shift_end_time = shift_date_with_zero_time + timedelta(hours=15)
        if request.data.get('shift') == DoctorAssignDaily.AFTERNOON:
            obj.shift_start_time = shift_date_with_zero_time + timedelta(hours=15)
            obj.shift_end_time = shift_date_with_zero_time + timedelta(hours=22)
        if request.data.get('shift') == DoctorAssignDaily.EVENING:
            obj.shift_start_time = shift_date_with_zero_time + timedelta(hours=22)
            obj.shift_end_time = shift_date_with_zero_time + timedelta(hours=31)
        working_hours = obj.shift_end_time - obj.shift_start_time
        working_hours_value_to_format = datetime.strptime(str(working_hours), '%H:%M:%S').time()
        obj.workinghours = working_hours_value_to_format
        designation_obj = Designation_Amount.objects.filter(designation_type=doctor_obj.designation).first()

        """
        convert string time to integer format to calculate the amount_perday
        """
        str_value = str(working_hours)
        value_split = str_value.split(":")  # ['07', '10', '00']
        """
        Here if the working hour is  07:10:00 then amount perday will be calculated 
        according to  07:00:00 i.e. 7 hours.
        If the working hour is  07:40:00 then amount perday will be calculated 
        according to  07:30:00 ie.7.5 hours.
        """
        if int(value_split[1]) < 30:
            value_split[1] = 0
        elif int(value_split[1]) <= 59:
            value_split[1] = 5
        value_decimal = int(value_split[0]) + (int(value_split[1]) / 10)  # 07:40:00 to 7.5 hour
        amount_perday = float(value_decimal) * float(designation_obj.designation_amount)
        """
        here if the doctor is updated then booking will change the doctor id and payment will deduct from old doctor
        new_doctor_obj = doctor_obj(from Users table)
        obj = this is old doctor object(doctor assign daily table) but new values are stored in it , 
        however it is not saved to db yet        
        """
        old_doctor_obj = DoctorAssignDaily.objects.get(id=instance.id)
        if old_doctor_obj.doctor_id != doctor_obj.id:
            adminpayment_obj = DoctorPerDayAmount.objects.create(payment_perday_date=obj.date,
                                                                 user_id=doctor_obj.id,
                                                                 designation_amount=designation_obj,
                                                                 amount_perday=amount_perday,
                                                                 workinghours=working_hours_value_to_format)
            DoctorPerDayAmount.objects.filter(payment_perday_date=old_doctor_obj.date,
                                              user_id=old_doctor_obj.doctor_id).first().delete()
        else:
            adminpayment_obj = DoctorPerDayAmount.objects.filter(payment_perday_date=old_doctor_obj.date,
                                                                 user_id=doctor_obj.id).first()
            adminpayment_obj.amount_perday = amount_perday
            adminpayment_obj.payment_perday_date = obj.date
            adminpayment_obj.workinghours = working_hours_value_to_format
            adminpayment_obj.designation_obj = designation_obj
        # if the doctor works for 24 hours then 24:00:00 doesnt exist , hence we will show 23:59:59
        if str(adminpayment_obj.workinghours) == '00:00:00' and working_hours != time(0, 0, 0):
            adminpayment_obj.workinghours = time(23, 59, 59)
        adminpayment_obj.save()
        obj.save()
        return obj

    class Meta:
        model = DoctorAssignDaily
        fields = ('__all__')


class DoctorPerDayPaymentSerializer(serializers.Serializer):
    class Meta:
        model = DoctorPerDayAmount
        fields = ('__all__')

    def update(self, instance, validated_data):
        """
        here working hours are updated along with the amount per day to be paid
        """
        request = self.context.get('request')
        working_hour = request.data.get('working_hour')
        paymanagement_id = self.context.get('paymanagement_id')
        object_payment = DoctorPerDayAmount.objects.filter(id=paymanagement_id).first()
        value_split = working_hour.split(":")
        if int(value_split[1]) < 30:
            value_split[1] = 0
        elif int(value_split[1]) <= 59:
            value_split[1] = 5
        value_decimal = int(value_split[0]) + (int(value_split[1]) / 10)  # 07:40:00 to 7.5 hour
        amount_perday = float(value_decimal) * float(object_payment.designation_amount.designation_amount)
        DoctorPerDayAmount.objects.filter(id=instance.id).update(workinghours=working_hour,
                                                                 amount_perday=amount_perday)
        return instance


class UserPerDayPaymentResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email', 'name')


class PerDayPaymentResponseSerializer(serializers.ModelSerializer):
    user = UserPerDayPaymentResponseSerializer(allow_null=True)

    class Meta:
        model = DoctorPerDayAmount
        fields = ('id', 'payment_perday_date', 'workinghours', 'amount_perday', 'user', 'is_paid')


class ContentTypeSerializer(serializers.ModelSerializer):
    """
    ContentType is the database created by itself containing all the models(tables) as objects
    """

    class Meta:
        model = ContentType
        fields = ('__all__')


class ListDoctorAssignUserNestedSerializer(serializers.ModelSerializer):
    profile_image = AllImageSerializer(allow_null=True)

    class Meta:
        model = User
        fields = ['id', 'name', 'profile_image']


class NearestHubGetterSerializer(DynamicFieldsModelSerializer):
    hub_documents = HubDocumentSerializer(many=True, fields=("document", "hub"))

    class Meta:
        model = Hub
        fields = ("id", "hub_documents", "hub_name", "is_deleted", "address", "lat", "lng", "cordinate", "amount")


class InsuranceVerifySerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = ('__all__')


class MedicalDisclosureSerializer(serializers.ModelSerializer):

    def update(self, instance, validated_data):
        Booking.objects.filter(id=instance.id).update(medical_disclosure=validated_data.get('medical_disclosure'))
        return validated_data

    class Meta:
        model = Booking
        fields = ("id", "medical_disclosure")


class CancelBookingSerializer(serializers.ModelSerializer):
    amnt_percent_deduct = serializers.FloatField(required=True)
    co_pay = serializers.FloatField(required=False)
    booking_cancel_charge = serializers.FloatField(required=False)

    def validate_amnt_percent_deduct(self, amnt_percent_deduct):
        if amnt_percent_deduct > 100:
            raise serializers.ValidationError("Please provide % between 0 and 100 ")

    def update(self, instance, validated_data):
        date_time = self.context.get('date_time')
        date_time = datetime.strptime(date_time, '%Y-%m-%d %H:%M:%S')
        booking_obj = Booking.objects.get(id=instance.id)
        booking_obj_return = cancelbooking(booking_obj, date_time)
        return booking_obj_return

    class Meta:
        model = Booking
        fields = ('__all__')


class CancelBookingResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = ('id', 'booking_cancel_charge', 'co_pay', 'state')


class RatingPatientVisitsSerializer(serializers.ModelSerializer):
    class Meta:
        model = RatingDocAndApp
        fields = ('__all__')


class PatientVisitsSerializer(serializers.ModelSerializer):
    patient = BookingListNestedSerializer(allow_null=True, many=False)
    doctor = BookingListNestedSerializer(allow_null=True, many=False)
    van = ListVanSerializer(allow_null=True, many=False)
    virtualroom = VirtualRoomResponseSerializer(allow_null=True, many=False)
    room = RoomSerializer(allow_null=True, many=False)
    ratingdoc = RatingPatientVisitsSerializer(allow_null=True, many=False)

    class Meta:
        model = Booking
        fields = (
            'id', 'patient', 'doctor', 'temp_doctor', 'van', 'room', 'virtualroom', 'created_at', 'updated_at', 'state',
            'booking_for',
            'visit_type', 'visit_now_later', 'source_address', 'source_cordinate',
            'destination_address', 'destination_cordinate', 'visit_start_time',
            'visit_end_time', 'total_distance', 'total_amount', 'co_pay',
            'meet_link', 'booking_cancel_charge', 'card_id', 'hub', 'familymember', 'ratingdoc',
            'medicalhistory', 'covid_related')


class PatientUpcomingVisitsCountSerializer(serializers.ModelSerializer):
    patient = BookingListNestedSerializer(allow_null=True, many=False)
    doctor = BookingListNestedSerializer(allow_null=True, many=False)
    van = ListVanSerializer(allow_null=True, many=False)
    virtualroom = VirtualRoomResponseSerializer(allow_null=True, many=False)
    room = RoomSerializer(allow_null=True, many=False)

    class Meta:
        model = Booking
        fields = ('__all__')


class DoctorBookingsNestedSerializer(serializers.ModelSerializer):
    class Meta:
        model = FamilyMember
        fields = ('__all__')


class DoctorHubVisitBookingsSerializer(serializers.ModelSerializer):
    doctor = BookingListNestedSerializer(allow_null=True, many=False)
    patient = BookingListNestedSerializer(allow_null=True, many=False)
    room = RoomSerializer(allow_null=True, many=False)
    familymember = DoctorBookingsNestedSerializer(allow_null=True)

    class Meta:
        model = Booking
        fields = ('id', 'doctor', 'temp_doctor', 'patient', 'familymember', 'state', 'booking_for', 'visit_type',
                  'visit_now_later',
                  'source_address', 'destination_address', 'visit_start_time', 'visit_end_time', 'total_amount',
                  'co_pay', 'medical_disclosure', 'amnt_percent_deduct', 'booking_cancel_charge', 'hub',
                  'room', 'covid_related')


class DoctorMobDocBookingsSerializer(serializers.ModelSerializer):
    doctor = BookingListNestedSerializer(allow_null=True, many=False)
    patient = BookingListNestedSerializer(allow_null=True, many=False)
    van = ListVanSerializer(allow_null=True, many=False)
    familymember = DoctorBookingsNestedSerializer(allow_null=True)

    class Meta:
        model = Booking
        fields = ('id', 'doctor', 'temp_doctor', 'patient', 'familymember', 'state', 'booking_for', 'visit_type',
                  'visit_now_later',
                  'source_address', 'destination_address', 'visit_start_time', 'visit_end_time', 'total_amount',
                  'co_pay', 'medical_disclosure', 'amnt_percent_deduct', 'booking_cancel_charge', 'hub',
                  'van', 'covid_related')


class DoctorVideoConBookingsSerializer(serializers.ModelSerializer):
    doctor = BookingListNestedSerializer(allow_null=True, many=False)
    patient = BookingListNestedSerializer(allow_null=True, many=False)
    virtualroom = VirtualRoomResponseSerializer(allow_null=True, many=False)
    familymember = DoctorBookingsNestedSerializer(allow_null=True)

    class Meta:
        model = Booking
        fields = ('id', 'doctor', 'temp_doctor', 'patient', 'familymember', 'state', 'booking_for', 'visit_type',
                  'visit_now_later',
                  'source_address', 'destination_address', 'visit_start_time', 'visit_end_time', 'total_amount',
                  'co_pay', 'medical_disclosure', 'amnt_percent_deduct', 'booking_cancel_charge', 'hub',
                  'virtualroom', 'covid_related')


class RetriveBookingSerializer(serializers.ModelSerializer):
    doctor = BookingListNestedSerializer(allow_null=True, many=False)
    patient = BookingListNestedSerializer(allow_null=True, many=False)
    familymember = FamilyResponseSerializer(allow_null=True, many=False)
    van = ListVanSerializer(allow_null=True, many=False)
    virtualroom = VirtualRoomResponseSerializer(allow_null=True, many=False)
    room = RoomSerializer(allow_null=True, many=False)
    source_lat = serializers.SerializerMethodField()
    source_lng = serializers.SerializerMethodField()
    destination_lat = serializers.SerializerMethodField()
    destination_lng = serializers.SerializerMethodField()

    @staticmethod
    def get_source_lat(obj):
        latitude = obj.source_cordinate.y
        return str(latitude)

    @staticmethod
    def get_source_lng(obj):
        longitude = obj.source_cordinate.x
        return str(longitude)

    @staticmethod
    def get_destination_lat(obj):
        latitude = obj.destination_cordinate.y
        return str(latitude)

    @staticmethod
    def get_destination_lng(obj):
        longitude = obj.destination_cordinate.x
        return str(longitude)

    class Meta:
        model = Booking
        fields = ('id', 'doctor', 'temp_doctor', 'patient', 'familymember', 'state', 'booking_for', 'visit_type',
                  'visit_now_later',
                  'source_lat', 'source_lng', 'source_cordinate',
                  'source_address', 'destination_lat', 'destination_lng', 'destination_cordinate',
                  'destination_address', 'visit_start_time', 'visit_end_time', 'total_amount',
                  'co_pay', 'medical_disclosure', 'amnt_percent_deduct', 'booking_cancel_charge', 'hub',
                  'virtualroom', 'van', 'room', 'payment_intent_id', 'has_medical_history', 'covid_related')


class RoleManagementSerializer(serializers.ModelSerializer):
    ONBOARDING = 1
    DASHBOARD = 2
    USERMANAGEMENT = 3
    STAFFUSER = 4
    VISIT = 5
    HUB = 6
    CONTENT = 7
    DOCUMENT = 8
    PAYMENT = 9
    TROUBLETICKETS = 10
    SHIFTMANAGE = 11
    MODULES = (
        (ONBOARDING, "onboarding"),
        (DASHBOARD, "dashboard"),
        (USERMANAGEMENT, "user management"),
        (STAFFUSER, "staff user management"),
        (VISIT, "visit management"),
        (HUB, "hub management"),
        (CONTENT, "content management"),
        (DOCUMENT, "document management"),
        (PAYMENT, "payment management"),
        (TROUBLETICKETS, "trouble tickets"),
        (SHIFTMANAGE, "shift management"),
    )
    modules_access = fields.MultipleChoiceField(choices=MODULES)

    def validate_user_role(self, user_role):
        if RolesManagement.objects.filter(user_role=user_role, is_deleted=False).exists():
            raise serializers.ValidationError("This role already exists.")
        return user_role

    def update(self, instance, validated_data):
        RolesManagement.objects.filter(id=instance.id).update(**validated_data)
        return validated_data

    class Meta:
        model = RolesManagement
        fields = ("__all__")


class RoleManagementResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = RolesManagement
        fields = ("__all__")


class SubAdminSignupSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True, min_length=3, max_length=70)
    password = serializers.CharField(required=False, write_only=True, min_length=8, max_length=15)
    phone_number = serializers.CharField(required=True, min_length=10, max_length=20)

    def validate_email(self, email):
        email = email.lower()
        if User.objects.filter(email=email, is_deleted=False).exists():
            raise serializers.ValidationError("This Email is already registered,Kindly register another email.")
        return email

    def validate_phone_number(self, phone_number):
        if User.objects.filter(phone_number=phone_number, is_deleted=False).exists():
            raise serializers.ValidationError("This Phone Number is already registered.")
        return phone_number

    class Meta:
        model = User
        fields = ("id", "name", "email", "password",
                  "phone_number", "is_email_verified", "role_management", "is_deleted", "user_role")

    def create(self, validated_data):
        user_obj = User.objects.create(**validated_data)
        user_obj.set_password(validated_data.get("password"))
        user_obj.is_active = False
        user_obj.save()
        # here the credentials(email and pass) are sent to the email id of the Staff member created by Admin
        try:
            password = validated_data.get("password")
            name = user_obj.name
            send_subadmin_cred_email(user_obj.email, password, name)
        except Exception:
            pass
        return user_obj


class SubAdminSignupNestedSerializer(serializers.ModelSerializer):
    class Meta:
        model = RolesManagement
        fields = ("id", "modules_access", "user_role")


class SubAdminSignupResponseSerializer(DynamicFieldsModelSerializer):
    auth_token = TokenSerializer()
    role_management = SubAdminSignupNestedSerializer()

    class Meta:
        model = User
        fields = ('id', 'auth_token', 'email', 'name', 'phone_number',
                  'is_active', "role_management", "is_deleted", "user_role")


class SubAdminActDeactAccSerializer(serializers.ModelSerializer):
    def update(self, instance, validated_data):
        obj = User.objects.filter(id=instance.id).first()
        # here User object is activated and deactivated and parameter is as is_email_verified
        obj.is_active = validated_data.get('is_active')
        obj.save()
        return obj

    class Meta:
        model = User
        fields = ('id', 'email', 'is_active',)


class AdminUpdateBookingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = (
            "state", "hub", "virtualroom", "van", "room", "visit_start_time", "doctor", "source_address",
            "destination_address",
            "meet_link", "booking_cancel_charge", 'covid_related')

    def validate(self, attrs):
        """The fields which has to be updated will only be sent as json """
        request = self.context.get('request')
        if attrs.get('source_address') and (not request.data.get('source_lat') or not request.data.get('source_lng')):
            raise serializers.ValidationError("Kindly provide source lat and lng of address to change the address")
        if attrs.get('destination_address') and (not request.data.get('destination_lat'
                                                                      ) or not request.data.get('destination_lng')):
            raise serializers.ValidationError("Kindly provide destination lat and lng of address to change the address")
        return attrs

    def update(self, instance, validated_data):
        request = self.context.get('request')
        date_time = request.data.get('current_datetime')
        booking_obj = Booking.objects.filter(id=instance.id).first()
        if request.data.get('state') == Booking.CANCEL:  # state is 2
            date_time_format = datetime.strptime(date_time, '%Y-%m-%d %H:%M:%S')
            booking_obj.state = Booking.CANCEL
            # creating the cancelled booking object
            cancelled_booking_obj = CancelledBookings.objects.create(visit_start_time=booking_obj.visit_start_time,
                                                                     visit_end_time=booking_obj.visit_end_time,
                                                                     doctor=booking_obj.doctor,
                                                                     hub=booking_obj.hub,
                                                                     van_id=booking_obj.van_id,
                                                                     virtualroom_id=booking_obj.virtualroom_id,
                                                                     room_id=booking_obj.room_id,
                                                                     booking_id=booking_obj.id
                                                                     )
            # here when the booking is cancelled then start,end time is None and doctor is set free from this visit
            booking_obj.visit_start_time = None
            booking_obj.visit_end_time = None
            booking_obj.doctor = None
            booking_obj.hub = None
            booking_obj.van_id = None
            booking_obj.virtualroom_id = None
            booking_obj.room_id = None
            booking_obj.save()
        else:
            # after thsis cancel payment API has to be hit by web
            if request.data.get('state') == Booking.COMPLETED:  # state is 4
                booking_obj.state = Booking.COMPLETED
                # after thsis confirm payment API has to be hit by web
            if request.data.get('source_address'):
                booking_obj = source_address(request, booking_obj)
            if request.data.get('destination_address'):
                booking_obj = destination_address(request, booking_obj)
            if request.data.get('hub_id') and request.data.get('visit_start_time') and request.data.get('doctor_id'):
                booking_obj = hub_change(request, booking_obj)
        booking_obj.save()
        # Booking.objects.filter(id=instance.id).update(**validated_data)
        # noti_obj = User.objects.filter(user_role=1).first()
        # filtered_obj = noti_obj.user_device.filter(is_active=True).all()
        # title = "Appointment Updated"
        # message = "Kindly check the updated details"
        # doc_obj = User.objects.filter(id=instance.doctor.id).first()
        # patient_obj = User.objects.filter(id=instance.patient.id).first()
        # send_notification(user_device_obj=filtered_obj,
        #                 title=title,
        #                 message=message,
        #                 data={"email":doc_obj.email})
        # send_notification(user_device_obj=filtered_obj,
        #                   title=title,
        #                   message=message,
        #                   data={"email": patient_obj.email})
        # UserActivity.objects.create(sender_id=doc_obj.id, receiver_id=noti_obj.id,
        #                             activity_type=3, title=title, message=message, payload=doc_obj
        #                             )
        # UserActivity.objects.create(sender_id=doc_obj.id, receiver_id=noti_obj.id,
        #                             activity_type=3, title=title, message=message, payload=patient_obj
        #                             )
        return validated_data


class GetCMBookingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContentManagement
        fields = ('cm_email', 'cm_phone_number',)


class PatientSymptomSerializer(serializers.ModelSerializer):
    item = serializers.SerializerMethodField()

    class Meta:
        model = Symptoms
        fields = ('id', 'additional_info', 'item')

    def get_item(self, obj):
        try:
            symptoms = obj.items.all().values_list('subcategory')
            symptoms_list = [item for sublist in symptoms for item in sublist]
        except Exception:
            symptoms_list = " "
        return symptoms_list


class FamilyMemberResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = FamilyMember
        fields = ("id", "name", "dob", "relation")


class RetrievePatientInfoSerializer(serializers.ModelSerializer):
    doctor = BookingListNestedSerializer(allow_null=True, many=False)
    patient = BookingListNestedSerializer(allow_null=True, many=False)
    symptoms = serializers.SerializerMethodField()
    medical_history = serializers.SerializerMethodField()
    familymember = FamilyMemberResponseSerializer(allow_null=True)
    ratingdoc = RatingPatientVisitsSerializer(allow_null=True, many=False)

    class Meta:
        model = Booking
        fields = ('doctor', 'temp_doctor', 'patient', 'symptoms', 'medical_history',
                  'visit_start_time', 'visit_end_time', 'visit_type', 'state',
                  'source_address', 'destination_address', 'total_amount', 'familymember', 'ratingdoc', 'co_pay'
                  , 'covid_related')

    def get_symptoms(self, obj):
        symptoms_obj = Symptoms.objects.get(booking_id=obj.id)
        try:
            symptoms = PatientSymptomSerializer(symptoms_obj).data
        except Exception:
            symptoms = " "
        return symptoms

    def get_medical_history(self, obj):
        try:
            if obj.booking_for == 1:
                med_obj = MedicalHistory.objects.filter(user=obj.patient, familymember__isnull=True).first()
            else:
                med_obj = MedicalHistory.objects.filter(user=obj.patient, familymember=obj.familymember).first()
            medical_history = MedicalResponseSerializer(med_obj).data
        except Exception:
            medical_history = " "
        return medical_history


class DesignationAmountSerializer(serializers.ModelSerializer):
    class Meta:
        """meta class"""
        model = Designation_Amount
        fields = ('__all__')

    def create(self, validated_data):
        """create hub"""
        physician = self.context.get('physician')
        PA = self.context.get('PA')
        NP = self.context.get('NP')
        if physician:
            Designation_Amount.objects.update_or_create(designation_type=physician['designation_type'])
            Designation_Amount.objects.filter(designation_type=physician['designation_type']).update(
                designation_amount=physician['designation_amount'])
        if PA:
            Designation_Amount.objects.update_or_create(designation_type=PA['designation_type'])
            Designation_Amount.objects.filter(designation_type=PA['designation_type']).update(
                designation_amount=PA['designation_amount'])
        if NP:
            Designation_Amount.objects.update_or_create(designation_type=NP['designation_type'])
            Designation_Amount.objects.filter(designation_type=NP['designation_type']).update(
                designation_amount=NP['designation_amount'])
        return validated_data


class DesignationAmountResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Designation_Amount
        fields = ('__all__')


class CheckIsPaidSerializer(serializers.ModelSerializer):
    user = UserPerDayPaymentResponseSerializer(allow_null=True)

    class Meta:
        model = DoctorPerDayAmount
        fields = ('is_paid')


class ShiftManagementSerializer(DynamicFieldsModelSerializer):
    class Meta:
        """meta class"""
        model = DynamicShiftManagement
        fields = ('__all__')

    def validate_shift_name(self, shift_name):
        shift_obj = DynamicShiftManagement.objects.filter(shift_name=shift_name, is_deleted=False).first()
        if shift_obj:
            raise serializers.ValidationError("This name alraedy exists")
        return shift_name

    def validate_start_time(self, start_time):
        shift_start_obj = DynamicShiftManagement.objects.filter(start_time__lte=start_time,
                                                                end_time__gt=start_time, is_deleted=False)
        if shift_start_obj:
            raise serializers.ValidationError("The start time is overlapping with other shift timing")
        return start_time

    def validate_end_time(self, end_time):
        shift_end_obj = DynamicShiftManagement.objects.filter(start_time__lt=end_time,
                                                              end_time__gte=end_time, is_deleted=False)
        if shift_end_obj:
            raise serializers.ValidationError("This end time is overlapping with other shift timing")
        return end_time

    def create(self, validated_data):
        """create shift time"""
        start_time = validated_data.get('start_time')
        end_time = validated_data.get('end_time')
        if start_time == end_time:
            raise serializers.ValidationError({
                "status": 400, "error": {
                    "location": "create shift", "message": "Start and End time cannot be the same."
                }})
        create_shift_validations(start_time, end_time)
        DynamicShiftManagement.objects.create(**validated_data)
        return validated_data


class UpdateShiftManagementSerializer(serializers.ModelSerializer):
    class Meta:
        """meta class"""
        model = DynamicShiftManagement
        fields = ('__all__')

    def update(self, instance, data):
        """update shift time"""
        shift_name = data.get("shift_name")
        start_time = data.get("start_time")
        end_time = data.get("end_time")
        if shift_name:
            shift_obj = DynamicShiftManagement.objects.filter(shift_name=shift_name, is_deleted=False).exclude(
                id=instance.id)
            if shift_obj:
                raise serializers.ValidationError({
                    "status": 400, "error": {
                        "location": "Update shift .", "message": "This shift name already exists"
                    }})
        if start_time:
            shift_start_obj = DynamicShiftManagement.objects.filter(start_time__lte=start_time, end_time__gt=start_time,
                                                                    is_deleted=False).exclude(id=instance.id)
            if shift_start_obj:
                raise serializers.ValidationError({
                    "status": 400, "error": {
                        "location": " Update shift. ",
                        "message": "This shift start time is overlapping with another shift time"
                    }})

        if end_time:
            shift_end_obj = DynamicShiftManagement.objects.filter(start_time__lt=end_time, end_time__gte=end_time,
                                                                  is_deleted=False).exclude(id=instance.id)
            if shift_end_obj:
                raise serializers.ValidationError({
                    "status": 400, "error": {
                        "location": " update shift",
                        "message": "This shift end time is overlapping with another shift time"
                    }})
        update_shift_validations(start_time, end_time, instance, data)
        return data


class UpdateInsuranceVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        """meta class"""
        model = InsuranceDetails
        fields = ('__all__')

    def update(self, instance, data):
        request = self.context.get('request')
        requested_state = request.data.get('state')
        date_time = request.data.get('datetime')
        """
        Converted he string-->to datetime format -->then to utc format-->
        """
        c_dt = datetime.strptime(date_time, "%Y-%m-%d %H:%M:%S")
        in_utc_datetime = datetime(c_dt.year, c_dt.month, c_dt.day, c_dt.hour, c_dt.minute, c_dt.second, tzinfo=utc)
        insurance_obj = InsuranceVerification.objects.filter(id=instance.id, is_deleted=False).first()
        state_in_db = insurance_obj.insurance_state
        if (state_in_db == 6 or state_in_db == 2) and requested_state == 3:
            insurance_obj.insurance_state = requested_state
            hold_time = in_utc_datetime - insurance_obj.verification_date
            insurance_obj.hold_time = hold_time
            insurance_obj.save()
        elif (state_in_db == 3 and requested_state == 4) or (state_in_db == 3 and requested_state == 5):
            booking_obj = Booking.objects.filter(id=insurance_obj.booking_id).first()
            booking_obj.co_pay = request.data.get('co_pay')
            booking_obj.save()
            insurance_obj.insurance_state = requested_state
            handled_time = in_utc_datetime - insurance_obj.verification_date
            insurance_obj.handled_time = handled_time
            insurance_obj.save()
        else:
            raise serializers.ValidationError({
                "status": 400, "error": {
                    "location": "Update insurance verification",
                    "message": "Cannot jump between the states of verification"
                }})
        return instance


class UserListInsuranceVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'name', 'phone_number')


class ListInsuranceVerificationSerializerFamilymember(serializers.ModelSerializer):
    class Meta:
        model = FamilyMember
        fields = ('id', 'name')


class ListInsuranceVerificationSerializerBooking(serializers.ModelSerializer):
    familymember = ListInsuranceVerificationSerializerFamilymember(allow_null=True)

    class Meta:
        model = Booking
        fields = ('id', 'familymember')


class ListInsuranceVerificationSerializer(serializers.ModelSerializer):
    patient = UserListInsuranceVerificationSerializer(allow_null=True)
    booking = ListInsuranceVerificationSerializerBooking(allow_null=True)

    class Meta:
        model = InsuranceVerification
        fields = ('id', 'insurance_state', 'verification_date', 'insurance_general', 'booking', 'hub_amount', 'patient')


class ListDoctorAccountVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'name', 'phone_number', 'email', 'status_doctor')


class DoctorPerDayPaymentListSerializer(serializers.ModelSerializer):
    class Meta:
        model = DoctorPerDayAmount
        fields = ('payment_perday_date', 'amount_perday')


class DocDailyAvailabiltySerializer(serializers.ModelSerializer):
    class Meta:
        """meta class"""
        model = DoctorDailyAvailability
        fields = ('date', 'is_available',)

    def create(self, validated_data):
        """create user availability"""
        request = self.context.get("request")
        user_id = request.user.id
        is_available = validated_data.get("is_available")
        date = validated_data.get("date")
        if DoctorAssignDaily.objects.filter(date=date, doctor_id=user_id).exists():
            raise serializers.ValidationError({
                "status": 400, "error": {
                    "location": "doctor availability",
                    "message": "You are assign to a shift please contact to admin for leave"
                }})
        obj, created = DoctorDailyAvailability.objects.update_or_create(doctor_id=user_id, date=date,
                                                                        defaults={"is_available": is_available})
        return obj


class ListBookingHubWiseSerializer(serializers.ModelSerializer):
    patient = BookingListNestedSerializer(allow_null=True, many=False)
    doctor = BookingListNestedSerializer(allow_null=True, many=False)
    van = ListVanSerializer(allow_null=True, many=False)
    virtualroom = VirtualRoomResponseSerializer(allow_null=True, many=False)
    room = RoomSerializer(allow_null=True, many=False)

    class Meta:
        model = Booking
        fields = ('__all__')


class ListDoctorAppParticularDayBookingsSerializer(DynamicFieldsModelSerializer):
    patient = BookingListNestedSerializer(allow_null=True, fields=("name", "profile_image"))
    doctor = BookingListNestedSerializer(allow_null=True, fields=("name", "profile_image"))

    class Meta:
        model = Booking
        fields = ('id', 'patient', 'doctor', 'visit_start_time', 'visit_end_time', 'state', 'visit_type')


class BookingDoctorDateWiseSerializer(serializers.ModelSerializer):
    doctor = BookingListNestedSerializer(allow_null=True, many=False)
    patient = BookingListNestedSerializer(allow_null=True, many=False)
    van = ListVanSerializer(allow_null=True, many=False)
    virtualroom = VirtualRoomResponseSerializer(allow_null=True, many=False)
    room = RoomSerializer(allow_null=True, many=False)

    class Meta:
        model = Booking
        fields = ('__all__')


class ListDoctorAvaialbilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = DoctorDailyAvailability
        fields = ('__all__')


class BookingExtendTimeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = ('__all__')

    def update(self, instance, validated_data):
        request = self.context.get('request')
        booking_id = request.data.get("booking_id")
        extend_time = request.data.get("time")
        reason = request.data.get("reason")
        booking_obj = Booking.objects.filter(id=booking_id).first()
        extend_time_in_time_format = datetime.strptime(str(extend_time), '%H:%M:%S').time()
        extend_time_timedelta = timedelta(hours=extend_time_in_time_format.hour,
                                          minutes=extend_time_in_time_format.minute)
        new_visit_endtime = booking_obj.visit_end_time + extend_time_timedelta
        if Booking.objects.filter(doctor_id=booking_obj.doctor_id,
                                  visit_start_time__lte=new_visit_endtime,
                                  visit_end_time__gte=new_visit_endtime).exclude(id=booking_obj.id):

            raise serializers.ValidationError({
                "status": 400,
                "error": {
                    "location": "extend booking time",
                    "message": "Booking with this doctor exists in the extended time."
                }})
        else:
            """
            here hours and payment(doctor ka) will increase if shift ki timing se zyada hua
            """
            # assigned doc is taken out in that shift , agar new end time is bigger then assigned shift kaay end_time
            # se then working hour increase and payment increase and visit_end_time update and reason also
            # else visit_end_time,reason update only
            assigned_doc_obj = DoctorAssignDaily.objects.filter(doctor_id=booking_obj.doctor_id,
                                                                shift_start_time__lte=booking_obj.visit_start_time,
                                                                shift_end_time__gte=booking_obj.visit_end_time).first()

            if new_visit_endtime > assigned_doc_obj.shift_end_time:
                doctor_payment_obj = DoctorPerDayAmount.objects.filter(payment_perday_date=assigned_doc_obj.date,
                                                                       user_id=booking_obj.doctor_id).first()
                # wrking hours increase
                x = doctor_payment_obj.workinghours
                workinghours_timedelta = timedelta(hours=x.hour, minutes=x.minute, seconds=x.second)
                y = workinghours_timedelta + extend_time_timedelta
                doctor_payment_obj.workinghours = (datetime.min + y).time()
                designation_obj = Designation_Amount.objects.filter(
                    designation_type=booking_obj.doctor.designation).first()
                # payment increase
                doctor_payment_obj.amount_perday = doctor_payment_obj.amount_perday + designation_obj.designation_amount
                doctor_payment_obj.save()
            Booking.objects.filter(id=booking_id).update(visit_end_time=new_visit_endtime, reason=reason)
        return validated_data


class DoctorAssignSerializerDS(serializers.ModelSerializer):
    # dynamic shift doctor assign daily DS = dynamic shift
    def validate_date(self, date):
        # date valiadation for the assigning doctor to hub
        if date < date.today() - timedelta(days=1):
            raise serializers.ValidationError("Kindly enter correct date")
        return date

    def validate(self, attrs):
        request = self.context.get("request")
        # van = ContentType.objects.get(model='van');van_id = van.id
        # room = ContentType.objects.get(model='room');room_id = room.id
        # virtualroom = ContentType.objects.get(model='virtualroom');virtualroom_id = virtualroom.id
        # doctor will not be assigned if these are the creteria below
        # this is for van booked ie. mobile doctor ie. visit_type=1
        # the  visit_type  and the shift timingsare the pivot for bifurcation
        # issse, van , vr or room tab hi assign hoga jab van,room,vr free ho, matlab book na hue ho
        shift = DynamicShiftManagement.objects.filter(id=request.data.get('dynamic_shift')).first()
        if request.data.get('visit_type') == 1:
            assign_van = Van.objects.get(id=request.data.get('visit_space'))
            validate_van(assign_van, request, shift)
        # doctor will not be assigned if these are the creteria below
        # this is for video conferencing ie. virtual room ie. visit_type=2
        # the shift timings and the visit_type are the pivot for bifurcation
        if request.data.get('visit_type') == 2:
            assign_virtualroom = VirtualRoom.objects.get(id=request.data.get('visit_space'))
            validate_virtual_room(assign_virtualroom, request, shift)
        # doctor will not be assigned if these are the creteria below
        # this is for hub visit ie. room ie. visit_type=3
        # the shift timings and the visit_type are the pivot for bifurcation
        if request.data.get('visit_type') == 3:
            assign_room = Room.objects.get(id=request.data.get('visit_space'))
            validate_room(assign_room, request, shift)

        return attrs

    # create the doctor assign daily
    def create(self, validated_data):
        request = self.context.get("request")
        doc_assign_obj = self.context.get('doc_assign_obj')
        # We are using visit_space i.e Generic foreign key usage, so regular create cannot be used
        # try block is used to give it a check that if Van is not present then except block throws validation error
        if validated_data.get('visit_type') == 1:
            assign_obj = create_doctorassign_van(request, doc_assign_obj)
        if validated_data.get('visit_type') == 2:
            assign_obj = create_doctorassign_virtualroom(request, doc_assign_obj)
        if validated_data.get('visit_type') == 3:
            assign_obj = create_doctorassign_room(request, doc_assign_obj)
        # calling the function for create and update same doctor payment
        working_hours_value_to_format, amount_perday, doctor_obj, designation_obj, working_hours = doctorpayment(
            validated_data, request, assign_obj)
        doc_pay_obj = DoctorPerDayAmount.objects.filter().all()
        if not doc_pay_obj.filter(payment_perday_date=assign_obj.date, user_id=doctor_obj.id).exists():
            DoctorPerDayAmount.objects.create(payment_perday_date=assign_obj.date,
                                              user_id=doctor_obj.id,
                                              workinghours=working_hours_value_to_format,
                                              designation_amount=designation_obj,
                                              amount_perday=amount_perday)
        else:
            adminpayment_obj = doc_pay_obj.filter(payment_perday_date=assign_obj.date,
                                                  user_id=doctor_obj.id).first()
            adminpayment_obj.amount_perday = adminpayment_obj.amount_perday + amount_perday
            # below 3 lines are for adding the datetime.time with datetime.time
            a_datetime = datetime.combine(date.today(), adminpayment_obj.workinghours)
            new_datetime = a_datetime + timedelta(hours=working_hours_value_to_format.hour)
            combined_workinghours = new_datetime.time()
            adminpayment_obj.workinghours = combined_workinghours
            # if the doctor works for 24 hours then 24:00:00 doesnt exist , hence we will show 23:59:59
            if str(adminpayment_obj.workinghours) == '00:00:00':
                adminpayment_obj.workinghours = time(23, 59, 59)
            adminpayment_obj.save()
        return assign_obj

    """
    we are updating the doctor which is assigned on daily basis
    """

    def update(self, instance, validated_data):
        request = self.context.get('request')
        doctorassigned_obj = self.context.get('doctorassigned_obj')
        obj = doctorassigned_obj
        if validated_data.get('visit_type') == 1:
            obj = update_doctorassign_van(request, obj)
        if validated_data.get('visit_type') == 2:
            obj = update_doctorassign_virtualroom(request, obj)
        if validated_data.get('visit_type') == 3:
            obj = update_doctorassign_room(request, obj)
        # calling the function
        working_hours_value_to_format, amount_perday, doctor_obj, designation_obj, working_hours = doctorpayment(
            validated_data, request, obj)
        """
        here if the doctor is updated then booking will change the doctor id and payment will deduct from old doctor
        new_doctor_obj = doctor_obj(from Users table)
        obj = this is old doctor object(doctor assign daily table) but new values are stored in it , 
        however it is not saved to db yet        
        """
        old_assigned_obj = DoctorAssignDaily.objects.get(id=instance.id)
        old_payment_obj = DoctorPerDayAmount.objects.filter(payment_perday_date=old_assigned_obj.date,
                                                            user_id=old_assigned_obj.doctor_id).first()
        payment_obj = payment_deduction_method(old_payment_obj, old_assigned_obj, designation_obj)
        new_payment = DoctorPerDayAmount.objects.get_or_create(payment_perday_date=validated_data.get('date'),
                                                               designation_amount=designation_obj,
                                                               user_id=doctor_obj.id)
        new_payment_obj = new_payment[0]
        new_payment_obj.amount_perday = new_payment_obj.amount_perday + amount_perday
        if new_payment_obj.workinghours != None:
            t1 = datetime.strptime(str(new_payment_obj.workinghours), '%H:%M:%S')
            t2 = datetime.strptime(str(working_hours_value_to_format), '%H:%M:%S')
            time_zero = datetime.strptime('00:00:00', '%H:%M:%S')
            new_payment_obj.workinghours = (t1 - time_zero + t2).time()
        else:
            new_payment_obj.workinghours = working_hours_value_to_format
        # if the doctor works for 24 hours then 24:00:00 doesnt exist , hence we will show 23:59:59

        if str(new_payment_obj.workinghours) == '00:00:00' and working_hours != time(0, 0, 0):
            new_payment_obj.workinghours = time(23, 59, 59)
        new_payment_obj.save()
        obj.save()
        return obj

    class Meta:
        model = DoctorAssignDaily
        fields = ('__all__')


class DoctorAssignResponseSerializer(DynamicFieldsModelSerializer):
    content_type = ContentTypeSerializer(many=False)
    dynamic_shift = ShiftManagementSerializer(allow_null=True, fields=('id', 'shift_name', 'start_time', 'end_time'))

    class Meta:
        model = DoctorAssignDaily
        fields = ('__all__')


class ListDoctorAssignResponseSerializer(DynamicFieldsModelSerializer):
    content_type = ContentTypeSerializer(many=False)
    doctor = ListDoctorAssignUserNestedSerializer(many=False)
    dynamic_shift = ShiftManagementSerializer(allow_null=True, fields=('id', 'shift_name', 'start_time', 'end_time'))

    class Meta:
        model = DoctorAssignDaily
        fields = ('__all__')


def roundtimeinhour(t):
    # if the start time has hour 2021-05-27 23:15:00 so it has to go to next date with 2021-05-28 00:00:00
    if t.hour == 23:
        return t.replace(second=0, microsecond=0, minute=0, hour=0, day=t.day + 1)
    if t.minute > 00 and t.minute <= 30:
        return t.replace(second=0, microsecond=0, minute=30, hour=t.hour)
    if t.minute > 30:
        return t.replace(second=0, microsecond=0, minute=0, hour=t.hour + 1)
    else:
        return t.replace(second=0, microsecond=0, minute=0, hour=t.hour)


def roundtimeinmin(dt, delta):
    return dt + (datetime.min - dt) % delta


class BookNowLaterVisitSerializerDS(serializers.ModelSerializer):
    def validate(self, attrs):
        if not attrs.get('visit_type'):
            raise serializers.ValidationError("Please provide visit_type")
        if not attrs.get('visit_now_later'):
            raise serializers.ValidationError("Kindly provide the visit_now_later")
        if not attrs.get('hub'):
            raise serializers.ValidationError("Please provide nearest hub ")
        return attrs

    def update(self, instance, validated_data):
        request = self.context.get('request')
        # here we are storing the visit type and visit now or later in the obj of booking
        # so that in coming lines we can use status=BOOKING_CREATED(same api mey kaam ho jaae)
        current_datetime_format = datetime.strptime(request.data.get("datetime"), date_time_string)
        Booking.objects.filter(id=instance.id).update(visit_type=validated_data.get('visit_type'),
                                                      visit_now_later=validated_data.get('visit_now_later'),
                                                      hub_id=validated_data.get('hub'),
                                                      total_amount=Hub.objects.get(
                                                          id=validated_data.get('hub').id).amount)
        # mapping the hub "amount" to the booking "total_amount"
        booking_obj = Booking.objects.get(id=instance.id)
        if booking_obj.visit_now_later == Booking.VISIT_NOW:
            shift_obj = get_dynamic_shift_id(request)
            if validated_data.get('visit_type') == Booking.MOBILE_DOCTOR:
                current_datetime_round_off = roundtimeinhour(current_datetime_format)
                doctor_id, return_avail_van_obj = booknow_mobiledoctor(request, instance, booking_obj,
                                                                       shift_obj, current_datetime_round_off)
                booking_obj.visit_start_time = current_datetime_round_off
                booking_obj.visit_end_time = current_datetime_round_off + timedelta(hours=1)
                booking_obj.temp_doctor_id = doctor_id
                booking_obj.van_id = return_avail_van_obj
                booking_obj.save()
            if validated_data.get('visit_type') == Booking.VIDEO_CONFERENCING:
                current_datetime_round_off = roundtimeinmin(current_datetime_format, timedelta(minutes=30))
                doctor_id, return_avail_vr_obj = booknow_videoconfer(request, instance, booking_obj, validated_data,
                                                                     shift_obj, current_datetime_round_off)
                booking_obj.visit_start_time = current_datetime_round_off
                booking_obj.visit_end_time = current_datetime_round_off + timedelta(minutes=30)
                booking_obj.temp_doctor_id = doctor_id
                booking_obj.virtualroom_id = return_avail_vr_obj
                booking_obj.save()
            if validated_data.get('visit_type') == Booking.HUB_VISIT:
                current_datetime_round_off = roundtimeinmin(current_datetime_format, timedelta(minutes=30))
                doctor_id, return_avail_room_obj = booknow_hubvisit(request, instance, booking_obj, validated_data,
                                                                    shift_obj, current_datetime_round_off)
                booking_obj.visit_start_time = current_datetime_round_off
                booking_obj.visit_end_time = current_datetime_round_off + timedelta(minutes=30)
                booking_obj.temp_doctor_id = doctor_id
                booking_obj.room_id = return_avail_room_obj
                booking_obj.save()
        # Booking later update
        if booking_obj.visit_now_later == Booking.VISIT_LATER:
            if not (validated_data.get('visit_start_time') or validated_data.get('visit_end_time')):
                raise serializers.ValidationError({
                    "status": 400,
                    "error": {
                        "location": "Update Booking, Time",
                        "message": "kindly provide both visit start and end time"
                    }})
            # When the request is as {"visit_type":2,"shift":2,"date":"2021-10-03","visit_space":21,"doctor":9}
            # and the same booking is updated at different date and rest are same then vr will also be same
            # so the vr_avail will be id_vr_booked <QuerySet [(21,)]> - id_doctor_assigned_vr <QuerySet [(21,)]> = 0
            # so below is updated
            Booking.objects.filter(id=instance.id).update(doctor_id=None, visit_type=None, co_pay=None,
                                                          van_id=None, virtualroom_id=None, room_id=None,
                                                          visit_start_time=validated_data.get(
                                                              'visit_start_time'),
                                                          visit_end_time=validated_data.get('visit_end_time')
                                                          )
            book_obj_now = Booking.objects.get(id=instance.id)
            # thie is for van booking
            if validated_data.get('visit_type') == Booking.MOBILE_DOCTOR:
                booklater_mobiledoctor(request, instance, book_obj_now)
            # for the booking later of the video conferencing
            if validated_data.get('visit_type') == Booking.VIDEO_CONFERENCING:
                booklater_videoconfer(request, instance, book_obj_now)
            # here book later for the hub visit
            if validated_data.get('visit_type') == Booking.HUB_VISIT:
                booklater_hubvisit(request, instance, book_obj_now)
        obj = Booking.objects.get(id=instance.id)
        point = Point(x=float(obj.hub.lng), y=float(obj.hub.lat), srid=4326)
        obj.destination_cordinate = point
        obj.destination_address = obj.hub.address
        obj.visit_type = validated_data.get('visit_type')
        obj.save()
        return obj

    class Meta:
        model = Booking
        fields = ('__all__')


class BookNowVisitlaterDSResponseSerializer(serializers.ModelSerializer):
    doctor = BookingListNestedSerializer(allow_null=True, many=False)

    class Meta:
        model = Booking
        fields = (
            'id', 'hub_id', 'temp_doctor', 'doctor', 'visit_type', 'van_id', 'virtualroom_id', 'room_id',
            'visit_now_later',
            'total_amount')


class TemporaryEditDoctorInfoSerializerDS(serializers.Serializer):
    # temporary table for adding in professional details of doctor
    tempdoctorinfo_documents = serializers.PrimaryKeyRelatedField(
        required=False, queryset=AllImage.objects.all(), many=True
    )
    experience = serializers.FloatField(required=False)

    def update(self, instance, validated_data):
        # saving to the temporary table
        doc_obj = self.context.get("doc_obj")
        details = self.context.get("details")
        request = self.context.get("request")
        med_obj = self.context.get("med_obj")
        # here the doctor status is updated because the admin has to list doctors with status in UI(kindly check User model)
        User.objects.filter(id=request.user.id).update(status_doctor=2)
        # deleting documents which are present from before
        try:
            TempDoctorMedicalDoc.objects.filter(tempdoctorinfo_id=med_obj.id).all().delete()
        except Exception:
            pass
        TempDoctorWorkInfo.objects.filter(user_id=instance.user_id).update(
            user_id=instance.user_id,
            designation=details.get('designation'),
            medical_practice_id=details.get('medical_practice_id'),
            speciality=details.get('speciality'),
            dynamicshift=details.get('dynamicshift'),
            experience=details.get('experience')
        )
        # update documents
        if details.get('tempdoctorinfo_documents'):
            tempdoctorinfo_documents = details.pop('tempdoctorinfo_documents')
        else:
            tempdoctorinfo_documents = None
        if tempdoctorinfo_documents:
            if len(tempdoctorinfo_documents) > 3:
                raise serializers.ValidationError({
                    "status": 400,
                    "error": {
                        "location": "documents update",
                        "message": "The documents have to less then or equal to 3"
                    }
                })
            else:
                for med_obj in tempdoctorinfo_documents:
                    TempDoctorMedicalDoc.objects.update_or_create(tempdoctorinfo=instance, document_id=med_obj)
        noti_obj = User.objects.filter(user_role=1).first()
        filtered_obj = noti_obj.user_device.filter(is_active=True).all()
        title = "Doctor Professional Information Notice"
        message = "Kindly check the doctor's professional information"
        data = {"email": doc_obj.email}
        # send_notification(user_device_obj=filtered_obj,
        #                 title="Doctor Professional Information Notice",
        #                 message="Kindly check the doctor's professional information",
        #                 data={"email":doc_obj.email})
        UserActivity.objects.create(sender_id=doc_obj.id, receiver_id=noti_obj.id,
                                    activity_type=1, title=title, message=message, payload=data
                                    )
        return instance

    # tempdoctorinfo_documents is used as nested serializer for document update
    class Meta:
        model = TempDoctorWorkInfo
        fields = ('id', 'designation', 'medical_practice_id', 'speciality', 'experience',
                  'dynamicshift', 'tempdoctorinfo_documents'
                  )


class TemporaryDocWorkInfoResponseSerializerDS(serializers.ModelSerializer):
    """
    professional details update response serializer
    """
    tempdoctorinfo_documents = TempDoctorDocumentSerializer(many=True)

    # professional details update
    class Meta:
        model = TempDoctorWorkInfo
        fields = ('id', 'designation', 'medical_practice_id', 'speciality', 'experience',
                  'dynamicshift', 'tempdoctorinfo_documents')


class VerifyDocWorkInfoSerializerDS(serializers.ModelSerializer):
    user_doctormedicaldoc = serializers.PrimaryKeyRelatedField(
        required=False, queryset=AllImage.objects.all(), many=True, allow_null=True
    )

    def update(self, instance, validated_data):
        user_id = self.context.get("user_id")
        request = self.context.get("request")
        doc_obj = User.objects.filter(id=user_id).prefetch_related('user_doctormedicaldoc')
        if request.data.get("is_profile_approved") == True:
            validated_data = verify_by_admin(validated_data, instance, user_id, doc_obj)
            doc_obj.update(is_profile_approved=request.data.get("is_profile_approved"))
        if request.data.get("is_profile_approved") == False:
            doc_obj.update(status_doctor=4)
        delete_from_temp_table_obj = TempDoctorWorkInfo.objects.filter(user_id=user_id).first()
        try:
            delete_from_temp_table_obj.delete()
        except Exception:
            pass
        return instance

    class Meta:
        model = User
        fields = (
            'designation',
            'medical_practice_id',
            'speciality',
            'experience',
            'dynamicshift',
            'user_doctormedicaldoc'
        )


class VerifyDocWorkInfoResponseSerializerDS(DynamicFieldsModelSerializer):
    """
    Serializer to serializer user fields.
    """
    user_doctormedicaldoc = DoctorDocumentSerializer(many=True)

    # user_doctormedicaldoc is used as nested serializer for document update
    class Meta:
        model = User
        fields = ('id', 'designation', 'medical_practice_id', 'speciality', 'experience', 'dynamicshift',
                  'is_profile_approved', 'admin_medical_practice_id', 'user_doctormedicaldoc'
                  )


class GetTempTableDoctorResponseSerializer(serializers.ModelSerializer):
    """serializer for getting temp doc information"""
    tempdoctorinfo_documents = TempDoctorDocumentSerializer(many=True)
    dynamicshift = RetriveShiftManagementSerializer(allow_null=True)

    class Meta:
        model = TempDoctorWorkInfo
        fields = ('id', 'designation', 'medical_practice_id', 'speciality', 'experience',
                  'shift', 'is_profile_approved', 'tempdoctorinfo_documents', 'dynamicshift')


class ListTempTableWorkInfoSerializer(serializers.ModelSerializer):
    dynamicshift = RetriveShiftManagementSerializer(allow_null=True)

    class Meta:
        model = TempDoctorWorkInfo
        fields = ('__all__')


class UserSerializer(DynamicFieldsModelSerializer):
    """
    Serializer to serializer user fields.
    """
    user_doctormedicaldoc = DoctorDocumentSerializer(many=True)
    profile_image = AllImageSerializer(allow_null=True)
    auth_token = TokenSerializer()
    role_management = RoleManagementLoginSerializer(allow_null=True)
    dynamicshift = RetriveShiftManagementSerializer(allow_null=True)

    class Meta:
        model = User
        fields = ('id', 'profile_image', 'auth_token', 'user_role', 'email', 'first_name', 'last_name', 'name',
                  'username', 'phone_number', 'dob', 'address', 'lat', 'lng', 'cordinate', 'city', 'state',
                  'zip_code', 'designation', 'medical_practice_id', 'speciality', 'experience', 'shift',
                  'is_profile_approved', 'is_email_verified', 'is_active', 'admin_medical_practice_id',
                  'user_doctormedicaldoc', 'created_at', 'updated_at', 'role_management',
                  'is_stripe_customer', 'dynamicshift')


class ListRatingsSerializer(serializers.ModelSerializer):
    patient = UserSerializer(allow_null=True, fields=('id', 'name'))
    doctor = UserSerializer(allow_null=True, fields=('id', 'name'))

    class Meta:
        model = RatingDocAndApp
        fields = ('id', 'doctor', 'patient', 'review', 'rating', 'comment_box')


class PatientDoctorAdminBookingSerializer(serializers.ModelSerializer):
    patient = UserSerializer(allow_null=True, fields=('id', 'name', 'email'))
    doctor = UserSerializer(allow_null=True, fields=('id', 'name', 'email'))

    class Meta:
        model = Booking
        fields = ('__all__')

class CancelledBookingsSerializer(DynamicFieldsModelSerializer):
    doctor = BookingListNestedSerializer(allow_null=True, many=False)
    class Meta:
        model = CancelledBookings
        fields = ('visit_start_time', 'visit_end_time', 'doctor')

class OverAllVisitsResponseSerializer(serializers.ModelSerializer):
    doctor = BookingListNestedSerializer(allow_null=True, many=False)
    patient = BookingListNestedSerializer(allow_null=True, many=False)
    van = ListVanSerializer(allow_null=True, many=False)
    virtualroom = VirtualRoomResponseSerializer(allow_null=True, many=False)
    room = RoomSerializer(allow_null=True, many=False)
    familymember = FamilyMemberResponseSerializer(allow_null=True)
    cancelledbooking = CancelledBookingsSerializer(allow_null=True, many=False)
    class Meta:
        model = Booking
        fields = ('id', 'doctor', 'patient', 'familymember', 'state', 'booking_for', 'visit_type',
                  'visit_now_later',
                  'source_address', 'destination_address', 'visit_start_time', 'visit_end_time', 'total_amount',
                  'co_pay', 'medical_disclosure', 'amnt_percent_deduct', 'booking_cancel_charge', 'hub',
                  'room', 'van', 'virtualroom', 'covid_related','cancelledbooking')


class AdminHubVisitBookingsSerializer(serializers.ModelSerializer):
    doctor = BookingListNestedSerializer(allow_null=True, many=False)
    patient = BookingListNestedSerializer(allow_null=True, many=False)
    room = RoomSerializer(allow_null=True, many=False)
    familymember = FamilyMemberResponseSerializer(allow_null=True)
    cancelledbooking = CancelledBookingsSerializer(allow_null=True, many=False)
    class Meta:
        model = Booking
        fields = ('id', 'doctor', 'temp_doctor', 'patient', 'familymember', 'state', 'booking_for', 'visit_type',
                  'visit_now_later',
                  'source_address', 'destination_address', 'visit_start_time', 'visit_end_time', 'total_amount',
                  'co_pay', 'medical_disclosure', 'amnt_percent_deduct', 'booking_cancel_charge', 'hub',
                  'room', 'covid_related','cancelledbooking')


class AdminMobDocBookingsSerializer(serializers.ModelSerializer):
    doctor = BookingListNestedSerializer(allow_null=True, many=False)
    patient = BookingListNestedSerializer(allow_null=True, many=False)
    van = ListVanSerializer(allow_null=True, many=False)
    familymember = FamilyMemberResponseSerializer(allow_null=True)
    cancelledbooking = CancelledBookingsSerializer(allow_null=True, many=False)
    class Meta:
        model = Booking
        fields = ('id', 'doctor', 'temp_doctor', 'patient', 'familymember', 'state', 'booking_for', 'visit_type',
                  'visit_now_later',
                  'source_address', 'destination_address', 'visit_start_time', 'visit_end_time', 'total_amount',
                  'co_pay', 'medical_disclosure', 'amnt_percent_deduct', 'booking_cancel_charge', 'hub',
                  'van', 'covid_related','cancelledbooking')


class AdminVideoConBookingsSerializer(serializers.ModelSerializer):
    doctor = BookingListNestedSerializer(allow_null=True, many=False)
    patient = BookingListNestedSerializer(allow_null=True, many=False)
    virtualroom = VirtualRoomResponseSerializer(allow_null=True, many=False)
    familymember = FamilyMemberResponseSerializer(allow_null=True)
    cancelledbooking = CancelledBookingsSerializer(allow_null=True, many=False)
    class Meta:
        model = Booking
        fields = ('id', 'doctor', 'temp_doctor', 'patient', 'familymember', 'state', 'booking_for', 'visit_type',
                  'visit_now_later',
                  'source_address', 'destination_address', 'visit_start_time', 'visit_end_time', 'total_amount',
                  'co_pay', 'medical_disclosure', 'amnt_percent_deduct', 'booking_cancel_charge', 'hub',
                  'virtualroom', 'covid_related','cancelledbooking')


class RetrievePatientInfoCancelSerializer(serializers.ModelSerializer):
    patient = BookingListNestedSerializer(allow_null=True, many=False)
    symptoms = serializers.SerializerMethodField()
    medical_history = serializers.SerializerMethodField()
    familymember = FamilyMemberResponseSerializer(allow_null=True)
    ratingdoc = RatingPatientVisitsSerializer(allow_null=True, many=False)
    cancelledbooking = CancelledBookingsSerializer(allow_null=True, many=False)

    def to_representation(self, instance):
        data = super(RetrievePatientInfoCancelSerializer, self).to_representation(instance)
        for each_data in data:
            if each_data == "cancelledbooking":
                for key,value in data['cancelledbooking'].items():
                    data[key] = value
        return data

    class Meta:
        model = Booking
        fields = ('patient', 'symptoms', 'medical_history',
                  'visit_type', 'state',
                  'source_address', 'destination_address', 'total_amount', 'familymember', 'ratingdoc', 'co_pay',
                  'covid_related', 'cancelledbooking')

    def get_symptoms(self, obj):
        symptoms_obj = Symptoms.objects.get(booking_id=obj.id)
        try:
            symptoms = PatientSymptomSerializer(symptoms_obj).data
        except Exception:
            symptoms = " "
        return symptoms

    def get_medical_history(self, obj):
        try:
            if obj.booking_for == 1:
                med_obj = MedicalHistory.objects.filter(user=obj.patient, familymember__isnull=True).first()
            else:
                med_obj = MedicalHistory.objects.filter(user=obj.patient, familymember=obj.familymember).first()
            medical_history = MedicalResponseSerializer(med_obj).data
        except Exception:
            medical_history = " "
        return medical_history