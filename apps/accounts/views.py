"""importing packages"""
from datetime import datetime, timedelta

import stripe
# this is imported for local time zone calculation
from django.contrib.gis.geos import Point
from django.db.models import Sum, Count, F, Avg, Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework import mixins, viewsets
from rest_framework import serializers
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView

from apps.accounts.dashboard_chart_function import dashboard_function_count, dashboard_function_aggregate_per_day
from apps.accounts.models import (DoctorAssignDaily, SymptomsItems, MedicalHistoryItems, Booking, State, City, User,
                                  OTP, UserActivity,
                                  Hub, HubDocs, Room, Van, FamilyMember, InsuranceDetails, EmergencyContacts, Ticket,
                                  VirtualRoom, MedicalHistory, DynamicShiftManagement,
                                  RatingDocAndApp, ContentManagement, DoctorMedicalDoc, DeviceManagement,
                                  TempDoctorWorkInfo, RolesManagement,
                                  Symptoms, Designation_Amount, DoctorPerDayAmount, InsuranceVerification,
                                  DoctorDailyAvailability,
                                  )
from apps.accounts.permissions import IsAdmin
from apps.accounts.serializers import (
    StateSerializer,
    CitySerializer,
    UserSerializer,
    LoginSerializer,
    SignupSerializer,
    ForgotPasswordSerializer,
    ResendOTPSerializer,
    VerifyOTPSerializer,
    ResetPasswordSerializer,
    ChangePasswordSerializer,
    HubResponseSerializer,
    HubSerializer,
    HubDocumentSerializer,
    ListHubSerializer,
    RoomSerializer,
    RoomResponseSerializer,
    ListRoomSerializer,
    VanSerializer,
    VanResponseSerializer,
    ListVanSerializer,
    EditPatientSerializer,
    FamilySerializer,
    InsuranceSerializer,
    InsuranceResponseSerializer,
    ListInsuranceSerializer,
    AdminListInsuranceSerializer,
    TicketResponseSerializer,
    TicketSerializer,
    VirtualRoomSerializer,
    VirtualRoomResponseSerializer,
    ListVirtualRoomSerializer,
    EditDoctorSerializer,
    MedicalSerializer,
    MedicalResponseSerializer,
    ListEmergencySerializer,
    ListMemberSerializer,
    EmergencySerializer,
    EmergencyResponseSerializer,
    RatingSerializer,
    RatingResponseSerializer,
    GetDocRatingInfoResponseSerializer,
    AdminUpdateSerializer,
    ContentManagementSerializer,
    ContentManagementResponseSerializer,
    EditDoctorPersonalInfoSerializer,
    DocEditDoctorResponseSerializer,
    VerifyDocWorkInfoSerializer,
    VerifyDocWorkInfoResponseSerializer,
    TemporaryEditDoctorInfoSerializer,
    GetTempTableDoctorResponseSerializer,
    SymptomSerializer,
    SymptomResponseSerializer,
    MedicalHistoryItemSerializer,
    RequestvisitResponseSerializer,
    RequestvisitSerializer,
    SymptomAllViewSerializer,
    DoctorAssignSerializer,
    DoctorAssignResponseSerializer,
    NearestHubGetterSerializer,
    InsuranceVerifySerializer,
    BookNowLaterVisitSerializer,
    BookNowVisitlaterResponseSerializer,
    BookNowStartEndTimeSerializer,
    BookNowStartEndTimeResponseSerializer,
    MedicalDisclosureSerializer,
    CancelBookingSerializer,
    CancelBookingResponseSerializer,
    PatientVisitsSerializer,
    AdminHubVisitBookingsSerializer,
    AdminMobDocBookingsSerializer,
    AdminVideoConBookingsSerializer,
    DoctorHubVisitBookingsSerializer,
    DoctorMobDocBookingsSerializer,
    DoctorVideoConBookingsSerializer,
    RetriveBookingSerializer,
    ListDoctorAssignResponseSerializer,
    SubAdminSignupResponseSerializer,
    SubAdminSignupSerializer,
    SubAdminActDeactAccSerializer,
    RoleManagementSerializer,
    RoleManagementResponseSerializer,
    AdminUpdateBookingSerializer,
    OverAllVisitsResponseSerializer,
    SymptomsItemsSerializer,
    GetCMBookingSerializer,
    ListRatingsSerializer,
    PatientDoctorAdminBookingSerializer,
    RetrievePatientInfoSerializer,
    DesignationAmountSerializer,
    DesignationAmountResponseSerializer,
    DoctorPerDayPaymentSerializer,
    PerDayPaymentResponseSerializer,
    ShiftManagementSerializer,
    RetriveShiftManagementSerializer,
    UpdateShiftManagementSerializer,
    UpdateInsuranceVerificationSerializer,
    ListInsuranceVerificationSerializer,
    ListDoctorAccountVerificationSerializer,
    DoctorPerDayPaymentListSerializer,
    DocDailyAvailabiltySerializer,
    ListTempTableWorkInfoSerializer,
    ListBookingHubWiseSerializer,
    ListDoctorAppParticularDayBookingsSerializer,
    BookingDoctorDateWiseSerializer,
    ListDoctorAvaialbilitySerializer,
    BookingExtendTimeSerializer,
    DoctorAssignSerializerDS,
    BookNowLaterVisitSerializerDS,
    BookNowVisitlaterDSResponseSerializer,
    TemporaryEditDoctorInfoSerializerDS,
    VerifyDocWorkInfoSerializerDS,
    RetrievePatientInfoCancelSerializer,
)
from apps.accounts.utils import generate_verify_admin_otp
from config.local import STRIPE_SECRET_KEY
from custom_exception.common_exception import (
    CustomApiException,
)
from pagination import Pagination
from permissions import ISPatient, IsAdminPatient
from response import CustomResponse
from utils import get_serialized_data
from utils import send_verify_admin_email

stripe.api_key = STRIPE_SECRET_KEY
from apps.payments.stripe_functions import Stripe
from apps.accounts.edit_doctor_profile_validations import (general_professional_validations, )
from apps.accounts.retrieve_medicalhistory import (user_in_auth_medicalhistory, user_in_params_medicalhistory, )

# global variables are as -
date_string = '%Y-%m-%d'
date_time_string = '%Y-%m-%d %H:%M:%S'


class States(viewsets.ReadOnlyModelViewSet):
    """
    THIS VIEW IS USED TO RETURN ALL States of particular Country
    """

    serializer_class = StateSerializer
    pagination_class = Pagination
    queryset = State.objects.filter().order_by("state_name")

    def get_queryset(self, *args, **kwargs):
        query = super(States, self).get_queryset()
        return query

    def list(self, request, *args, **kwargs):
        response = super().list(self, request, *args, **kwargs)
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.get_queryset(), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=self.serializer_class,
                fields=request.query_params.get("fields"),
                many=True,
            )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        return CustomResponse(response.data)


class Cities(viewsets.ReadOnlyModelViewSet):
    """
    THIS VIEW IS USED TO RETURN ALL Cities of particular State
    """

    serializer_class = CitySerializer
    pagination_class = Pagination
    queryset = City.objects.filter()

    def get_queryset(self, *args, **kwargs):
        query = super(Cities, self).get_queryset()
        state_id = self.kwargs.get("state_id")
        query = query.filter(state_id=state_id).order_by("city_name")
        return query

    def list(self, request, *args, **kwargs):
        response = super().list(self, request, *args, **kwargs)
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.get_queryset(), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=self.serializer_class,
                fields=request.query_params.get("fields"),
                many=True,
            )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        return CustomResponse(response.data)


class MedicalHistoryItemsView(viewsets.ReadOnlyModelViewSet):
    """
    THIS VIEW IS USED TO RETURN ALL medical history items
    """

    serializer_class = MedicalHistoryItemSerializer
    pagination_class = Pagination
    queryset = MedicalHistoryItems.objects.filter().order_by("id")

    def get_queryset(self, *args, **kwargs):
        query = super(MedicalHistoryItemsView, self).get_queryset()
        return query

    def list(self, request, *args, **kwargs):
        response = super().list(self, request, *args, **kwargs)
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.get_queryset(), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=self.serializer_class,
                fields=request.query_params.get("fields"),
                many=True,
            )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        return CustomResponse(response.data)


class SymptomAllView(viewsets.ReadOnlyModelViewSet):
    """
    THIS VIEW IS USED TO RETURN ALL medical history items
    """

    serializer_class = SymptomAllViewSerializer
    pagination_class = Pagination
    queryset = SymptomsItems.objects.filter().order_by("id")

    def get_queryset(self, *args, **kwargs):
        query = super(SymptomAllView, self).get_queryset()
        return query

    def list(self, request, *args, **kwargs):
        response = super().list(self, request, *args, **kwargs)
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.get_queryset(), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=self.serializer_class,
                fields=request.query_params.get("fields"),
                many=True,
            )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        return CustomResponse(response.data)


class SignUp(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """Signup view where user provides basic information and should be able to signup"""

    def create(self, request, *args, **kwargs):
        """method for user signup"""
        # RuntimeError: dictionary changed size during iteration for this error we have converted it to list
        # and then popped out the elements.
        for i in list(request.data):
            if not request.data[i]:
                request.data.pop(i)
        is_admin = request.query_params.get("is_admin")
        # for uuid and device registration id
        if not request.data.get("device_uuid") or not request.data.get("fcm_token"):
            raise CustomApiException(
                status_code=400, message="Kindly give fcm token and device uuid", location="signup create"
            )
        device_uuid = request.data.pop("device_uuid")
        serializer = SignupSerializer(data=request.data, context={"request": request, "is_admin": is_admin})
        serializer.is_valid(raise_exception=True)
        user_obj = serializer.save()
        # creating the obj of device from which it is logged in to send notification to admin
        DeviceManagement.objects.update_or_create(user=user_obj, device_uuid=device_uuid, defaults={
            "device_uuid": device_uuid,
            "fcm_token": request.data['fcm_token']})
        # temp code
        if request.data.get("is_email_verified"):
            user_obj.is_email_verified = request.data.get("is_email_verified")
            user_obj.save()
        token, created = Token.objects.get_or_create(user=user_obj)
        serializer = get_serialized_data(
            obj=user_obj,
            serializer=UserSerializer,
            fields=request.query_params.get("fields"),
        )

        data = serializer.data

        #######################################
        # Adding temporary piece of code for email url.
        email_url_obj = OTP.objects.filter(
            user=user_obj, otp_type=OTP.VERIFICATION_OTP
        ).first()
        data.update({"email_url_obj": email_url_obj.otp})
        # stripe customer create
        if request.data.get("user_role") == User.PATIENT:
            stripe = Stripe(user_obj.id)
            response = stripe.stripe_customer_create()
            User.objects.filter(id=user_obj.id).update(stripe_customer_id=response.id, is_stripe_customer=True)
            data.update({"stripe details": response})
        elif request.data.get("user_role") == User.ADMIN:
            stripe = Stripe(user_obj.id)
            response = stripe.create_admin_account()
            data.update({"stripe details": response})
            User.objects.filter(id=user_obj.id).update(stripe_customer_id=response.id, is_stripe_customer=True)
        return CustomResponse(data)


class Login(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """Login view to let user login into the App"""

    def create(self, request, *args, **kwargs):
        """method for user login"""
        device_uuid = request.data.pop('device_uuid')
        fcm_token = request.data['fcm_token']
        serializer = LoginSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        DeviceManagement.objects.update_or_create(user=serializer.validated_data.get('user'), device_uuid=device_uuid,
                                                  defaults={
                                                      "device_uuid": device_uuid,
                                                      "fcm_token": request.data['fcm_token']})
        # fetching OTP for temporary purpose
        user = serializer.validated_data.get("user")
        if user.user_role == User.DOCTOR and user.is_profile_approved != True:
            return CustomResponse(
                {
                    "message": "Your profile is not yet approved by admin. Kindly wait for approval!"
                }
            )
        if user.user_role == User.SUBADMIN and user.is_deleted == True:
            raise CustomApiException(
                status_code=400,
                message="Your profile is deleted,Kindly contact Admin!", location="login"
            )
        serializer = get_serialized_data(
            obj=serializer.validated_data.get("user"),
            serializer=UserSerializer,
            fields=request.query_params.get("fields"),
        )

        data = serializer.data
        if user.user_role not in [User.PATIENT, User.DOCTOR]:
            # add user in attrs
            otp = generate_verify_admin_otp(user)
            data.update({"otp": otp})
            try:
                send_verify_admin_email(user.email, otp)
            except Exception:
                pass
        data.update({"fcm_token": fcm_token})
        return CustomResponse(data)


class VerifyOTP(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """This View will help patient/doctor to verify their email via OTP"""

    def update(self, request):
        """method for verifying otp"""

        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        response = {"message": "OTP verified sucessfully."}
        return CustomResponse(response)


class MyProfile(mixins.ListModelMixin, viewsets.GenericViewSet):
    """View to return users profile"""

    permission_classes = (IsAuthenticated,)

    def list(self, request):
        """method for listing user data"""
        # if the query params has the patient id
        user_id = request.query_params.get("user_id")
        if user_id:
            # prefetch_related('user_doctormedicaldoc') is not used here because its one to one field
            user_obj = User.objects.filter(id=user_id).select_related('profile_image', 'auth_token',
                                                                      'role_management', 'dynamicshift').first()
            serializer = get_serialized_data(
                obj=user_obj,
                serializer=UserSerializer,
                fields=request.query_params.get("fields"),
            )
        else:
            serializer = get_serialized_data(
                obj=request.user,
                serializer=UserSerializer,
                fields=request.query_params.get("fields"),
            )
        return CustomResponse(serializer.data)


class EditPatientProfile(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = EditPatientSerializer

    def update(self, request, patient_id):
        patient_obj = User.objects.filter(id=patient_id).first()
        if not patient_obj:
            raise CustomApiException(
                status_code=400, message="Invalid Id!", location="update patient"
            )
        serializer = self.serializer_class(
            instance=patient_obj, data=request.data, partial=True, context={'patient_obj': patient_obj}
        )
        serializer.is_valid(raise_exception=True)
        user_obj = serializer.save()
        # return_obj is created because
        return_obj = User.objects.filter(id=patient_id).first()
        return_serializer = get_serialized_data(
            obj=return_obj,
            serializer=UserSerializer,
            fields=request.query_params.get("fields"),
        )

        data = return_serializer.data
        #######################################
        # Adding temporary piece of code for email url (this will return the OTP also along with other parameter).
        email_url_obj = OTP.objects.filter(
            user=user_obj, otp_type=OTP.VERIFICATION_OTP
        ).first()
        data.update({"email_url_obj": email_url_obj.otp})

        return CustomResponse(data)


class ForgotPassword(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """This API will send the OTP to user's  email to reset the password"""

    serializer_class = ForgotPasswordSerializer

    def create(self, request):
        """method for forgot password"""
        serializer = ForgotPasswordSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        data = {}
        data.update(
            {
                "message": "OTP sent successfully",
                "otp": serializer.validated_data.get("otp"),
            }
        )
        return CustomResponse(data)


class ResendOTP(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """If patient/doctor didn't got any OTP he can opt for resend option"""

    def create(self, request):
        """method for resend otp"""
        serializer = ResendOTPSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        response = {
            "message": "OTP sent successfully",
            "otp": serializer.validated_data.get("otp"),
        }
        return CustomResponse(response)


class ResetPassword(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """View to reset the password"""

    def create(self, request):
        """method for reset password"""

        # create password after emailverification url when admin creates doctor,patient,subadmins
        url_otp = self.request.query_params.get("url_otp")
        otp_type = self.request.query_params.get("otp_type")

        if url_otp:
            otp_obj = OTP.objects.filter(
                otp=url_otp, otp_type=int(otp_type), is_used=False
            ).first()

            if not otp_obj:
                raise CustomApiException(
                    status_code=400, message="Invalid otp", location="reset password"
                )

            user_obj = User.objects.filter(id=otp_obj.user.id).first()
            if not user_obj:
                raise serializers.ValidationError("No user found.")

            # updating verification status
            user_obj.is_email_verified = True
            user_obj.save()

            serializer = ResetPasswordSerializer(
                data=request.data, context={"user_obj": user_obj, "otp_obj": otp_obj}
            )

        else:
            # forgot password then reset password
            user_obj = User.objects.filter(email=request.data.get("email")).first()

            if not user_obj:
                raise CustomApiException(
                    status_code=400,
                    message="User does not exists",
                    location="reset password",
                )

            serializer = ResetPasswordSerializer(
                data=request.data, context={"user_obj": user_obj}
            )
        serializer.is_valid(raise_exception=True)
        return CustomResponse({"message": "Password reset successfully."})


class ChangePassword(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """View to update password"""

    permission_classes = (IsAuthenticated,)

    def update(self, request):
        """method for change password"""
        serializer = ChangePasswordSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        response = {
            "message": "Password changed successfully.",
            "token": serializer.validated_data.get("token"),
        }
        return CustomResponse(response)


class ListUsers(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
        API to list all users of our app : patient and doctors and search them by email and name
    """

    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    serializer_class = UserSerializer
    queryset = (
        User.objects.filter(user_role__in=[3, 4, 2]).all()
            .select_related('profile_image', 'auth_token', 'role_management')
            .order_by("-created_at")

    )
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ("email", "name")

    def list(self, request, *args, **kwargs):
        """method for listing users"""
        response = super().list(self, request, *args, **kwargs)
        return CustomResponse(response.data)


class ListPatients(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
        API to list all patients of our app and search them by email and name
    """

    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    serializer_class = UserSerializer
    queryset = (
        User.objects.filter(user_role=3).select_related('profile_image', 'auth_token', 'role_management')
            .order_by("-created_at")
            .all()
    )
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ("email", "name")

    def list(self, request, *args, **kwargs):
        """method for listing users"""
        response = super().list(self, request, *args, **kwargs)
        return CustomResponse(response.data)


class ListDoctors(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
        API to list all doctors of our app and search them by email and name
    """

    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    serializer_class = UserSerializer
    queryset = (
        User.objects.filter(user_role=4).select_related('profile_image', 'auth_token', 'role_management')
            .order_by("-created_at")
            .all()
    )
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ("email", "name")

    def list(self, request, *args, **kwargs):
        """method for listing users"""
        response = super().list(self, request, *args, **kwargs)
        return CustomResponse(response.data)


class ToggleStatus(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """This View will help users to toggle status:
        activate or deactivate user or multiple users(doctors/patients)
        by default : is_active is set to be true
    """
    permission_classes = (IsAdmin,)

    def update(self, request):
        """method for updating is_active status"""

        User.objects.filter(id__in=request.data.get("user_ids")).update(is_active=request.data.get("is_active"))

        return CustomResponse({"message": "Status updated successfully"})


class HubView(
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Hub view to create,edit,delete,list the hub.
    This View id used in Admin Panel"""
    # is authenticated iss liye kiya hai ki retrive time patient kaay liye bhi ho saakay
    permission_classes = (IsAdmin,)
    serializer_class = HubSerializer

    def create(self, request, *args, **kwargs):
        """method for creating hub"""

        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Hub added successfully"})

    def update(self, request, hub_id):
        """updating hub"""
        hub_obj = Hub.objects.filter(id=hub_id).first()
        if not hub_obj:
            raise CustomApiException(
                status_code=400, message="Invalid Id.", location="update hub"
            )
        serializer = self.serializer_class(
            instance=hub_obj, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Hub updated successfully"})


class HubRetriveView(mixins.RetrieveModelMixin,
                     viewsets.GenericViewSet, ):
    permission_classes = (IsAuthenticated,)
    serializer_class = HubSerializer
    response_serializer_class = HubResponseSerializer

    def retrieve(self, request, hub_id):
        """To retrieve details of particular hub"""
        hub_obj = Hub.objects.filter(id=hub_id, is_deleted=False).prefetch_related('hub_documents__document').first()
        if not hub_obj:
            raise CustomApiException(
                status_code=400, message="Invalid id", location="retrieve hub"
            )
        serializer = HubResponseSerializer(hub_obj)
        return CustomResponse(serializer.data)


class DeleteMultipleHubs(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """Class for deleting hubs"""

    # soft delete multiple hubs at a time
    permission_classes = (IsAdmin,)

    def update(self, request):
        """method for deleting hubs"""
        hub_ids = request.data.get("hub_ids")
        # soft deleting all flags at once
        Hub.objects.filter(id__in=hub_ids).update(is_deleted=True)
        Room.objects.filter(hub__in=hub_ids).update(is_deleted=True)
        Van.objects.filter(hub__in=hub_ids).update(is_deleted=True)
        VirtualRoom.objects.filter(hub__in=hub_ids).update(is_deleted=True)
        return CustomResponse({"message": "Hubs Deleted successfully"})


class ListHubs(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
        API to list all hubs 
    """

    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    serializer_class = ListHubSerializer
    queryset = Hub.objects.filter(is_deleted=False)
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ("hub_name",)

    def list(self, request, *args, **kwargs):
        """method for listing hubs"""
        response = super().list(self, request, *args, **kwargs)
        return CustomResponse(response.data)


class DeleteHubDocuments(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """soft delete multiple hub documents at a time"""

    permission_classes = (IsAdmin,)

    def update(self, request, hub_id):
        """method for deleting hub documents"""
        hub_documents = request.data.get("hub_documents")
        HubDocs.objects.filter(document__in=hub_documents, hub=hub_id).update(is_deleted=True)  # soft deleting objects
        return CustomResponse({"message": "Hub Documents deleted successfully"})


class ListHubDocuments(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """
        API to list all documents of a hub at hub detail api
    """

    permission_classes = (IsAdmin,)
    pagination_class = Pagination

    def retrieve(self, request, hub_id):
        """method for list hub documents at hub detail"""
        queryset = HubDocs.objects.filter(hub=hub_id, is_deleted=False).select_related('document').all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(queryset, request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=HubDocumentSerializer,
                fields=request.query_params.get("fields"),
                many=True,
            )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=queryset,
            serializer=HubDocumentSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class RoomView(
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Room view to create,edit,delete,list the rooms.
    This View id used in Admin Panel in hub management"""

    permission_classes = (IsAdmin,)
    serializer_class = RoomSerializer

    def create(self, request, *args, **kwargs):
        """method for creating rooms"""

        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Room added successfully"})

    def update(self, request, room_id):
        """updating room"""
        room_obj = Room.objects.filter(id=room_id).first()
        if not room_obj:
            raise CustomApiException(
                status_code=400, message="Invalid Room id", location="update room. "
            )
        if Room.objects.filter(room_number=request.data.get("room_number"), hub=request.data.get("hub"),
                               is_deleted=False).exists():
            raise CustomApiException(
                status_code=400, message="This room number is already present in the hub", location="update room ."
            )
        serializer = self.serializer_class(
            instance=room_obj, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Room updated successfully"})

    def retrieve(self, request, room_id):
        """To retrieve details of particular room"""
        room_obj = Room.objects.filter(id=room_id).first()
        if not room_obj:
            raise CustomApiException(
                status_code=400, message="Invalid RoomId", location="retrieve room"
            )
        serializer = RoomResponseSerializer(room_obj)
        return CustomResponse(serializer.data)


class DeleteMultipleRooms(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """Class for deleting rooms"""

    # soft delete multiple hubs at a time
    permission_classes = (IsAdmin,)

    def update(self, request, hub_id):
        """method for deleting rooms"""
        room_ids = request.data.get("room_ids")
        # soft deleting all flags at once
        Room.objects.filter(id__in=room_ids, hub=hub_id).update(is_deleted=True)
        return CustomResponse({"message": "Rooms Deleted successfully"})


class ListRooms(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """
        API to list all rooms 
    """

    permission_classes = (IsAdmin,)
    pagination_class = Pagination

    def retrieve(self, request, hub_id):
        """method for list rooms at hub detail"""
        if request.query_params.get('status'):
            queryset = Room.objects.filter(hub=hub_id, is_deleted=False, status=True).all()
        else:
            queryset = Room.objects.filter(hub=hub_id, is_deleted=False).all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(queryset, request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=ListRoomSerializer,
                fields=request.query_params.get("fields"),
                many=True,
            )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )

        serializer = get_serialized_data(
            obj=queryset,
            serializer=ListRoomSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class VanView(
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Van view to create,edit,delete,list the vans.
    This View id used in Admin Panel in hub management"""

    permission_classes = (IsAdmin,)
    serializer_class = VanSerializer

    def create(self, request, *args, **kwargs):
        """method for creating vans"""
        hub = request.data.get("hub")
        serializer = self.serializer_class(
            data=request.data, context={"request": request, "hub": hub}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Van added successfully"})

    def update(self, request, van_id):
        """updating van"""
        van_obj = Van.objects.filter(id=van_id, hub=request.data.get("hub")).first()
        if not van_obj:
            raise CustomApiException(
                status_code=400, message="Invalid Id or Van is not in this hub!!", location="update van"
            )
        serializer = self.serializer_class(
            instance=van_obj, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Van updated successfully"})

    def retrieve(self, request, van_id):
        """To retrieve details of particular van"""
        van_obj = Van.objects.filter(id=van_id).first()
        if not van_obj:
            raise CustomApiException(
                status_code=400, message="Invalid Van Id", location="retrieve van"
            )
        serializer = VanResponseSerializer(van_obj)
        return CustomResponse(serializer.data)


class DeleteMultipleVans(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """Class for deleting vans"""

    # soft delete multiple hubs at a time
    permission_classes = (IsAdmin,)

    def update(self, request, hub_id):
        """method for deleting vans"""
        van_ids = request.data.get("van_ids")
        obj = Van.objects.filter(hub=hub_id)
        if not obj:
            raise CustomApiException(
                status_code=400, message="The hub_id doesnt exist", location="delete van"
            )
            # soft deleting all flags at once
        Van.objects.filter(id__in=van_ids, hub=hub_id).update(is_deleted=True)
        return CustomResponse({"message": "Van Deleted successfully"})


class ListVans(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """
        API to list all vans 
    """

    permission_classes = (IsAdmin,)
    pagination_class = Pagination

    def retrieve(self, request, hub_id):
        """method for list vans at hub detail"""
        if request.query_params.get('status'):
            queryset = Van.objects.filter(hub=hub_id, is_deleted=False, status=True).all()
        else:
            queryset = Van.objects.filter(hub=hub_id, is_deleted=False).all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(queryset, request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=ListVanSerializer,
                fields=request.query_params.get("fields"),
                many=True,
            )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )

        serializer = get_serialized_data(
            obj=queryset,
            serializer=ListVanSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class AddMember(mixins.CreateModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = FamilySerializer

    def create(self, request, *args, **kwargs):
        """method for creating family members"""
        if not request.user.id == request.data.get("user"):
            raise CustomApiException(
                status_code=400, message="The patientId(user) and its auth doesnt match", location="add family member"
            )
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Family member added successfully"})

    def update(self, request, member_id):
        """updating family member"""
        if not request.user.id == request.data.get("user"):
            raise CustomApiException(
                status_code=400, message="The patientId(user) and its auth doesnt match.",
                location="update family member."
            )
        if not FamilyMember.objects.filter(id=member_id, user=request.user.id).exists():
            raise CustomApiException(
                status_code=400, message="The patientId(user) doesnt have the family member(id)!!",
                location="update family member . "
            )
        member_obj = FamilyMember.objects.filter(id=member_id).first()
        if not member_obj:
            raise CustomApiException(
                status_code=400, message="Invalid Family member id", location="family member update "
            )
        serializer = self.serializer_class(
            instance=member_obj, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "family member updated successfully"})


class DeleteAddMember(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """Class for deleting Family Members"""

    # soft delete multiple members at a time
    permission_classes = (IsAuthenticated,)

    def update(self, request, member_id):
        """method for deleting family members"""
        if not FamilyMember.objects.filter(id=member_id).exists():
            raise CustomApiException(
                status_code=400, message="Invalid family member Id!!", location="delete family member"
            )
        member_obj = FamilyMember.objects.get(id=member_id)
        if not request.user.id == member_obj.user.id:
            raise CustomApiException(
                status_code=400,
                message="The family member's patientId and the authenticated patient id doesnt match!!",
                location="update family member")

        # soft deleting all flags at once
        FamilyMember.objects.filter(id=member_id).update(is_deleted=True)
        return CustomResponse({"message": " Family Member Deleted successfully"})


class InsuranceView(
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Insurance details to add,update,retrieve"""

    permission_classes = (IsAuthenticated,)
    serializer_class = InsuranceSerializer
    response_serializer_class = InsuranceResponseSerializer

    def create(self, request, *args, **kwargs):
        """method for create insurance details"""
        if not request.user.id == request.data.get("user"):
            raise CustomApiException(
                status_code=400, message="The patientId(user) and its auth doesnt match . ",
                location="add_insurance_details"
            )
        familymember_id = request.query_params.get("familymember_id")
        if familymember_id and not FamilyMember.objects.filter(user=request.data.get('user'),
                                                               id=familymember_id).exists():
            raise CustomApiException(
                status_code=400, message="This user doesnt have this family member.",
                location="add_insurance_details"
            )
        serializer = self.serializer_class(
            data=request.data, context={"request": request, "familymember_id": familymember_id}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Your insurance contact has been added successfully"})

    def update(self, request, insurance_id):
        """updating insurance details"""
        if not request.user.id == request.data.get("user"):
            raise CustomApiException(
                status_code=400, message="The patientId (user) and its auth doesnt match!!",
                location="add_insurance_details"
            )

        insurance_obj = InsuranceDetails.objects.filter(id=insurance_id).select_related('user', 'familymember'
                                                                                        ).first()
        if not insurance_obj:
            raise CustomApiException(
                status_code=400, message="Invalid Insurance Id", location="update insurance details"
            )
        if not InsuranceDetails.objects.filter(id=insurance_id, user=request.user.id).exists():
            raise CustomApiException(
                status_code=400, message="The patientId(user) doesnt have this insurance(id)!!",
                location="update insurance details"
            )
        serializer = self.serializer_class(
            instance=insurance_obj, data=request.data, partial=True, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Your insurance contact has been updated successfully"})

    def retrieve(self, request, insurance_id):
        """To retrieve details of particular Insurance id"""

        insurance_obj = InsuranceDetails.objects.filter(id=insurance_id).first()
        if not insurance_obj:
            raise CustomApiException(
                status_code=400, message="Invalid insurance_id", location="retrieve insurance details"
            )
        serializer = InsuranceResponseSerializer(insurance_obj)
        return CustomResponse(serializer.data)


class DeleteInsuranceDetails(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """Class for deleting Insurance details"""

    # soft delete multiple details at a time
    permission_classes = (IsAuthenticated,)

    def update(self, request, insurance_id):
        """method for deleting Insurance details"""
        InsuranceDetails.objects.filter(id=insurance_id).update(is_deleted=True)
        return CustomResponse({"message": "Your insurance has been deleted successfully"})


class EmergencyView(
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Emergency contacts to add,update,retrieve"""

    permission_classes = (IsAuthenticated,)
    serializer_class = EmergencySerializer
    response_serializer_class = EmergencyResponseSerializer

    def create(self, request, *args, **kwargs):
        """method for create emergency contacts"""
        if not request.user.id == request.data.get("user"):
            raise CustomApiException(
                status_code=400, message="The patientId (user) and it's auth doesnt match!!",
                location="add_emergency_contacts")
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Your Emergency Contact added successfully"})

    def update(self, request, emergency_id):
        """updating emergency contacts"""
        if not request.user.id == request.data.get("user"):
            raise CustomApiException(
                status_code=400, message="The patientId(user) and its auth doesnt match!!",
                location="update emergency contacts . ")
        emergency_obj = EmergencyContacts.objects.filter(id=emergency_id).first()
        if not emergency_obj:
            raise CustomApiException(
                status_code=400, message="Invalid emergency_id", location="update emergency contacts."
            )
        if not EmergencyContacts.objects.filter(id=emergency_id, user=request.user.id).exists():
            raise CustomApiException(
                status_code=400, message="The patientId(user) doesnt have the emergency member(id)!!",
                location="emergency contacts update "
            )
        serializer = self.serializer_class(
            instance=emergency_obj, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Your Emergency Contact updated successfully"})

    def retrieve(self, request, emergency_id):
        """To retrieve details of particular Emergency id"""

        emergency_obj = EmergencyContacts.objects.filter(id=emergency_id).first()
        if not emergency_obj:
            raise CustomApiException(
                status_code=400, message="Invalid emergency id", location="retrieve emergency contacts"
            )
        serializer = EmergencyResponseSerializer(emergency_obj)
        return CustomResponse(serializer.data)


class DeleteEmergencyContact(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """Class for deleting emergency contacts"""

    # soft delete multiple emergency contacts at a time
    permission_classes = (IsAuthenticated,)

    def update(self, request, emergency_id):
        """method for deleting emergency contacts"""
        if not EmergencyContacts.objects.filter(id=emergency_id).exists():
            raise CustomApiException(
                status_code=400, message="Invalid emergency contact Id!!", location="delete emergency contact"
            )
        emergency_obj = EmergencyContacts.objects.get(id=emergency_id)
        if not request.user.id == emergency_obj.user.id:
            raise CustomApiException(
                status_code=400,
                message="The emergency contact's patientId and the authenticated patient id doesnt match!!",
                location="update emergency contact")
        EmergencyContacts.objects.filter(id=emergency_id).update(is_deleted=True)
        return CustomResponse({"message": "Your emergency contact has been deleted successfully"})


class TicketTable(mixins.CreateModelMixin,
                  mixins.RetrieveModelMixin,
                  mixins.UpdateModelMixin,
                  viewsets.GenericViewSet, ):
    """
        API to create update & ret retrieve tickets 
    """

    permission_classes = (IsAdmin,)
    serializer_class = TicketSerializer
    response_serializer_class = TicketResponseSerializer

    def create(self, request, *args, **kwargs):
        """method for creating ticket"""

        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Ticket added successfully"})

    def update(self, request, ticket_id):
        """method for updating ticket"""
        ticket_obj = Ticket.objects.filter(id=ticket_id).first()
        if not ticket_obj:
            raise CustomApiException(
                status_code=400, message="Invalid ticket_id", location="update ticket"
            )
        serializer = self.serializer_class(
            instance=ticket_obj, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Ticket  updated successfully"})

    def retrieve(self, request, ticket_id):
        """To retrieve details of particular ticket"""
        ticket_obj = Ticket.objects.filter(id=ticket_id).first()
        if not ticket_obj:
            raise CustomApiException(
                status_code=400, message="Invalid ticket id", location="retrieve ticket"
            )
        serializer = TicketResponseSerializer(ticket_obj)
        return CustomResponse(serializer.data)


class DeleteMultipleTickets(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """Class for deleting tickets"""

    # soft delete multiple ticket at a time
    permission_classes = (IsAdmin,)

    def update(self, request):
        """method for deleting ticket"""
        ticket_ids = request.data.get("ticket_ids")
        # soft deleting all flags at once
        Ticket.objects.filter(id__in=ticket_ids).update(is_deleted=True)

        return CustomResponse({"message": "Tickets Deleted successfully"})


class ListTickets(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
        API to list all ticket 
    """

    permission_classes = (IsAdmin,)
    pagination_class = Pagination

    def list(self, request):
        """method for list tickets"""
        is_resolved = request.query_params.get("is_resolved")
        if is_resolved == "True":
            queryset = Ticket.objects.filter(is_resolved=True, is_deleted=False).all()
        else:
            queryset = Ticket.objects.filter(is_resolved=False, is_deleted=False).all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(queryset, request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=TicketResponseSerializer,
                fields=request.query_params.get("fields"),
                many=True,
            )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )

        serializer = get_serialized_data(
            obj=queryset,
            serializer=TicketResponseSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class VirtualRoomView(mixins.CreateModelMixin,
                      mixins.RetrieveModelMixin,
                      mixins.UpdateModelMixin,
                      viewsets.GenericViewSet,
                      ):
    """ Virtual Room view to create,edit,delete,list the  virtual rooms.

    This View id used in Admin Panel in hub management"""

    permission_classes = (IsAuthenticated,)
    serializer_class = VirtualRoomSerializer
    response_serializer_class = VirtualRoomResponseSerializer

    def create(self, request, *args, **kwargs):
        """method for creating virtual rooms"""

        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Virtual Room added successfully"})

    def update(self, request, virtualroom_id):
        """updating  virtual room"""
        virtualroom_obj = VirtualRoom.objects.filter(id=virtualroom_id).first()
        if not virtualroom_obj:
            raise CustomApiException(
                status_code=400, message="Invalid virtualroom_id", location="update virtual room"
            )
        if VirtualRoom.objects.filter(room_number=request.data.get("room_number"), hub=request.data.get("hub"),
                                      is_deleted=False).exists():
            raise CustomApiException(
                status_code=400, message="This virtual room number is already present in the hub",
                location="update room"
            )
        serializer = self.serializer_class(
            instance=virtualroom_obj, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Virtual Room updated successfully"})

    def retrieve(self, request, virtualroom_id):
        """To retrieve details of particular virtual room"""

        virtualroom_obj = VirtualRoom.objects.filter(id=virtualroom_id).first()
        if not virtualroom_obj:
            raise CustomApiException(
                status_code=400, message="Invalid virtualroom id", location="retrieve virtual room"
            )
        serializer = VirtualRoomResponseSerializer(virtualroom_obj)
        return CustomResponse(serializer.data)


class DeleteMultipleVirtualRooms(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """Class for deleting  virtual rooms"""

    # soft delete multiple hubs at a time

    permission_classes = (IsAdmin,)

    def update(self, request, hub_id):
        """method for deleting  virtual rooms"""
        virtualroom_ids = request.data.get("virtualroom_ids")
        # soft deleting all flags at once
        VirtualRoom.objects.filter(id__in=virtualroom_ids, hub=hub_id).update(is_deleted=True)
        return CustomResponse({"message": " Virtual Rooms Deleted successfully"})


class ListVirtualRooms(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    #  API to list all  virtual rooms

    permission_classes = (IsAdmin,)
    pagination_class = Pagination

    def retrieve(self, request, hub_id):
        """method for list  virtual rooms at hub detail"""

        if request.query_params.get('status'):
            queryset = VirtualRoom.objects.filter(hub=hub_id, is_deleted=False, status=True).all()
        else:
            queryset = VirtualRoom.objects.filter(hub=hub_id, is_deleted=False).all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(queryset, request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=ListVirtualRoomSerializer,
                fields=request.query_params.get("fields"),
                many=True,
            )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )

        serializer = get_serialized_data(
            obj=queryset,
            serializer=ListVirtualRoomSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


# medical_history

class AddHistory(mixins.CreateModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """Medical History"""
    permission_classes = (IsAuthenticated,)
    serializer_class = MedicalSerializer
    response_serializer_class = MedicalResponseSerializer

    def create(self, request, *args, **kwargs):
        """method for creating medical history"""
        familymember_id = request.query_params.get('familymember', '')
        # Family member if given in query parameter
        if familymember_id:
            if not FamilyMember.objects.filter(user=request.user.id, id=familymember_id, is_deleted=False).exists():
                raise CustomApiException(
                    status_code=400, message="This user is not having this family member or family member is deleted",
                    location="update doctor profile . "
                )
            if MedicalHistory.objects.filter(familymember=familymember_id, is_deleted=False).exists():
                raise CustomApiException(
                    status_code=400, message="The medical history of the family member is present.",
                    location="update doctor profile."
                )
        # Family member if not given in query parameter
        if not familymember_id and MedicalHistory.objects.filter(user=request.user.id, familymember=None,
                                                                 is_deleted=False
                                                                 ).exists():
            raise CustomApiException(
                status_code=400, message="The medical history of the user is present.",
                location="doctor profile update "
            )
        serializer = self.serializer_class(
            data=request.data, context={"request": request, "familymember_id": familymember_id}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Medical History added successfully"})

    def update(self, request):
        """updating medical history"""
        familymember_id = request.query_params.get('familymember', '')
        # Family member if given in query parameter to update it
        if familymember_id:
            if not MedicalHistory.objects.filter(familymember=familymember_id, user=request.user.id,
                                                 is_deleted=False).exists():
                raise CustomApiException(
                    status_code=400, message="The patientId(user) doesnt have this family member!!",
                    location="update medical history")
            medical_obj = MedicalHistory.objects.filter(familymember=familymember_id).first()
            serializer = self.serializer_class(
                instance=medical_obj, data=request.data, partial=True,
                context={"request": request, "familymember_id": familymember_id}
            )
        if not familymember_id:
            # Family member if not given in query parameter to update it
            medical_obj = MedicalHistory.objects.filter(user=request.user.id, familymember=None,
                                                        is_deleted=False).first()

            serializer = self.serializer_class(
                instance=medical_obj, data=request.data, partial=True,
                context={"request": request}
            )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "medical history updated successfully"})


class EditDoctorProfile(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)
    serializer_class = EditDoctorSerializer

    def update(self, request, doctor_id):
        doctor_obj = User.objects.filter(id=doctor_id).first()
        if not doctor_obj:
            raise CustomApiException(
                status_code=400, message="Invalid doctor_id", location="doctor update profile"
            )
        serializer = self.serializer_class(
            instance=doctor_obj, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Doctor  data updated successfully"})


class Rating(
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet
):
    # rating the doctor and app
    permission_classes = (IsAuthenticated,)
    queryset = RatingDocAndApp.objects.all()

    serializer_class = RatingSerializer
    response_serializer_class = RatingResponseSerializer

    def update(self, request):
        """method for creating and updating rating"""
        if not request.data.get("rating_doc_or_app"):
            raise CustomApiException(
                status_code=400,
                message="Kindly provide choice for rating app or doc , rating_doc_or_app:1 for Rating doc and rating_doc_or_app:2 for Rating app",
                location="doc rating data "
            )
        # rating for the doctor by the patient is new everytime(hence create)
        if request.data.get("rating_doc_or_app") == RatingDocAndApp.RATING_DOC:
            serializer = self.serializer_class(
                data=request.data, context={"request": request}
            )
            serializer.is_valid(raise_exception=True)
            rating_obj = serializer.save()

        # rating for the app
        if (request.data.get("rating_doc_or_app") == RatingDocAndApp.RATING_APP):
            # if the app rating exists by the patient then(hence update)
            if RatingDocAndApp.objects.filter(patient=request.user.id, doctor__isnull=True).exists():
                rating_obj1 = RatingDocAndApp.objects.filter(patient=request.user.id).first()
                serializer = self.serializer_class(
                    instance=rating_obj1, data=request.data, context={"request": request}, partial=True
                )
                serializer.is_valid(raise_exception=True)
                rating_obj = serializer.save()
            else:
                # app rating creating for the patient for 1st time(hence create)
                serializer = self.serializer_class(
                    data=request.data, context={"request": request}
                )
                serializer.is_valid(raise_exception=True)
                rating_obj = serializer.save()

        serializer = get_serialized_data(
            obj=rating_obj,
            serializer=self.response_serializer_class,
            fields=request.query_params.get("fields"),
        )
        return CustomResponse(serializer.data)


class GetDocRatingInfo(
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    response_serializer_class = GetDocRatingInfoResponseSerializer
    permission_classes = (ISPatient,)

    def retrieve(self, request, doctor_id):
        """To retrieve details of doctor"""
        doc_obj = User.objects.filter(id=doctor_id, user_role=User.DOCTOR).select_related('profile_image').first()
        if not doc_obj:
            raise CustomApiException(
                status_code=400, message="Invalid doctor id or Its not a Doctor", location="retrieve doc"
            )

        serializer = GetDocRatingInfoResponseSerializer(doc_obj)
        return CustomResponse(serializer.data)


# 17th dec Admin Profile update
class AdminUpdate(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """
    Admin and subadmin both can use this api for editing there details
    """
    permission_classes = (IsAdmin,)
    serializer_class = AdminUpdateSerializer

    def update(self, request, admin_id):
        admin_obj = User.objects.filter(id=admin_id).exclude(user_role=User.DOCTOR).exclude(
            user_role=User.PATIENT).first()
        if not admin_obj:
            raise CustomApiException(
                status_code=400, message="Invalid admin id or Its not a Admin", location="update admin"
            )
        serializer = self.serializer_class(
            instance=admin_obj, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return CustomResponse({"message": "Admin updated successfully"})


# 23 dec
class ContentManagementCreateUpdate(mixins.CreateModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet, ):
    """ContentManagement to create,edit."""
    permission_classes = (IsAdmin,)
    serializer_class = ContentManagementSerializer
    response_serializer_class = ContentManagementResponseSerializer

    def create(self, request, *args, **kwargs):
        """method for creating Content Management"""
        if not request.user.id == request.data.get("user"):
            raise CustomApiException(
                status_code=400, message="The AdminID(user) and its auth doesnt match!!",
                location="add contentmanagement")
        if ContentManagement.objects.filter(user=request.user.id).exists():
            raise CustomApiException(
                status_code=400, message="The docs are already present", location="create cm"
            )
        serializer = self.serializer_class(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        cm_obj = serializer.save()
        serializer = get_serialized_data(
            obj=cm_obj,
            serializer=self.response_serializer_class,
            fields=request.query_params.get("fields"),
        )
        data = serializer.data
        return CustomResponse(data)

    def update(self, request):
        """method for updating content management"""
        if not request.user.id == request.data.get("user"):
            raise CustomApiException(
                status_code=400, message="The AdminID(user) and its auth doesnt match!!",
                location="update content management")
        user_obj = ContentManagement.objects.filter(user=request.user.id).first()

        serializer = self.serializer_class(
            instance=user_obj, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        cm_obj = serializer.save()
        serializer = get_serialized_data(
            obj=cm_obj,
            serializer=self.response_serializer_class,
            fields=request.query_params.get("fields"),
        )
        data1 = serializer.data
        return CustomResponse(data1)


# 28 dec
class GetCMInfo(
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    response_serializer_class = ContentManagementResponseSerializer
    permission_classes = (IsAdmin,)

    def retrieve(self, request, cm_id):
        """To retrieve details of CM"""
        cm_obj = ContentManagement.objects.filter(id=cm_id).select_related('cm_terms_condition_pdf',
                                                                           'cm_legal_terms_pdf').first()
        if not cm_obj:
            raise CustomApiException(
                status_code=400, message="Invalid ID", location="retrieve cm"
            )
        serializer = get_serialized_data(
            obj=cm_obj,
            serializer=self.response_serializer_class,
            fields=request.query_params.get("fields"),
        )
        return CustomResponse(serializer.data)


# 31 dec aagaay kaay 4 classes list kaay haai for patient module for admin access also
# familymember,emergency,insurance,medicalhistory 
class ListMember(mixins.ListModelMixin, viewsets.GenericViewSet):
    """ class for listing all members"""
    permission_classes = (IsAdminPatient,)
    pagination_class = Pagination
    serializer_class = ListMemberSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)

    def list(self, request, *args, **kwargs):
        user_id = request.query_params.get("user_id")
        # this if is used to authenticate the user_id passed in header , patient is authenticated
        # matlab query_params mey nothing is passed, patient khud ki family member dekh raaha hai
        if not user_id:
            queryset = FamilyMember.objects.filter(user=request.user.id,
                                                   is_deleted=False).prefetch_related('family_member_medical_history'
                                                                                      ).order_by('-created_at').all()
            pagination_class = self.pagination_class()
            page = pagination_class.paginate_queryset(queryset, request)
            if page is not None:
                serializer = get_serialized_data(
                    obj=page,
                    serializer=ListMemberSerializer,
                    fields=request.query_params.get("fields"),
                    many=True,
                )
                return CustomResponse(
                    pagination_class.get_paginated_response(serializer.data).data
                )
            serializer = get_serialized_data(
                obj=queryset,
                serializer=ListMemberSerializer,
                fields=request.query_params.get("fields"),
                many=True,
            )
        # here the admin authentication is given and query_params mey user_id
        # issme admin dekh paaega patient ki family member 
        if user_id:
            if request.user.user_role == User.PATIENT:
                raise CustomApiException(
                    status_code=400,
                    message="The auth is not of Admin or remove the query params to see the family mem of patient",
                    location="list family member")
            queryset_user_id_query_params = FamilyMember.objects.filter(user=user_id,
                                                                        is_deleted=False).prefetch_related(
                'family_member_medical_history'
            ).order_by('-created_at').all()
            pagination_class = self.pagination_class()
            page_user_id_query_params = pagination_class.paginate_queryset(queryset_user_id_query_params, request)
            if page_user_id_query_params is not None:
                serializer = get_serialized_data(
                    obj=page_user_id_query_params,
                    serializer=ListMemberSerializer,
                    fields=request.query_params.get("fields"),
                    many=True,
                )
                return CustomResponse(
                    pagination_class.get_paginated_response(serializer.data).data
                )
            serializer = get_serialized_data(
                obj=queryset_user_id_query_params,
                serializer=ListMemberSerializer,
                fields=request.query_params.get("fields"),
                many=True,
            )
        return CustomResponse(serializer.data)


class ListEmergencyContact(mixins.ListModelMixin, viewsets.GenericViewSet):
    """ class for listing all members"""
    permission_classes = (IsAdminPatient,)
    pagination_class = Pagination
    serializer_class = ListEmergencySerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)

    def list(self, request, *args, **kwargs):
        user_id = request.query_params.get("user_id")
        # this if is used to authenticate the user_id passed in header , patient is authenticated
        # matlab query_params mey nothing is passed, patient khud ki emergency contact dekh raaha hai
        if not user_id:
            queryset = EmergencyContacts.objects.filter(user=request.user.id, is_deleted=False).order_by(
                '-created_at').all()
            pagination_class = self.pagination_class()
            page = pagination_class.paginate_queryset(queryset, request)
            if page is not None:
                serializer = get_serialized_data(
                    obj=page,
                    serializer=ListEmergencySerializer,
                    fields=request.query_params.get("fields"),
                    many=True,
                )
                return CustomResponse(
                    pagination_class.get_paginated_response(serializer.data).data
                )
            serializer = get_serialized_data(
                obj=queryset,
                serializer=ListEmergencySerializer,
                fields=request.query_params.get("fields"),
                many=True,
            )
        # here the admin authentication is given and query_params mey user_id
        # issme admin dekh paaega patient ki emergency contact 
        if user_id:
            if request.user.user_role == User.PATIENT:
                raise CustomApiException(
                    status_code=400,
                    message="The auth is not of Admin or remove the query params to see the emergency contact of patient",
                    location="list emergency contacts")
            queryset_user_id_query_params = EmergencyContacts.objects.filter(user=user_id, is_deleted=False).order_by(
                '-created_at').all()
            pagination_class = self.pagination_class()
            page_user_id_query_params = pagination_class.paginate_queryset(queryset_user_id_query_params, request)
            if page_user_id_query_params is not None:
                serializer = get_serialized_data(
                    obj=page_user_id_query_params,
                    serializer=ListEmergencySerializer,
                    fields=request.query_params.get("fields"),
                    many=True,
                )
                return CustomResponse(
                    pagination_class.get_paginated_response(serializer.data).data
                )
            serializer = get_serialized_data(
                obj=queryset_user_id_query_params,
                serializer=ListEmergencySerializer,
                fields=request.query_params.get("fields"),
                many=True,
            )
        return CustomResponse(serializer.data)


class ListInsurance(mixins.ListModelMixin, viewsets.GenericViewSet):
    """ class for listing all members"""
    permission_classes = (IsAdminPatient,)
    pagination_class = Pagination
    serializer_class = ListInsuranceSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)

    def list(self, request, *args, **kwargs):
        user_id = request.query_params.get("user_id")
        # this if is used to authenticate the user_id passed in header , patient is authenticated
        # matlab query_params mey nothing is passed, patient khud ki insurance details dekh raaha hai
        """
        Many to many(profile image) is used so for admin all the insurance is shown and profile image
        is removed to save queries
        For specific user the no. of insurance list with will be max 5 so max 8 queries will hit.
        """
        if not user_id:
            queryset = InsuranceDetails.objects.filter(user=request.user.id,
                                                       is_deleted=False).select_related().order_by('-created_at').all()
            pagination_class = self.pagination_class()
            page = pagination_class.paginate_queryset(queryset, request)
            if page is not None:
                serializer = get_serialized_data(
                    obj=page,
                    serializer=ListInsuranceSerializer,
                    fields=request.query_params.get("fields"),
                    many=True,
                )
                return CustomResponse(
                    pagination_class.get_paginated_response(serializer.data).data
                )
            serializer = get_serialized_data(
                obj=queryset,
                serializer=ListInsuranceSerializer,
                fields=request.query_params.get("fields"),
                many=True,
            )
        # here the admin authentication is given and query_params mey user_id
        # issme admin dekh paaega patient ki insurance details
        if user_id:
            if request.user.user_role == User.PATIENT:
                raise CustomApiException(
                    status_code=400,
                    message="The auth is not of Admin or remove the query params to see the list insurance of patient",
                    location="list insurance")
            queryset_user_id_query_params = InsuranceDetails.objects.filter(user=user_id,
                                                                            is_deleted=False).select_related(
            ).order_by(
                '-created_at').all()
            pagination_class = self.pagination_class()
            page_user_id_query_params = pagination_class.paginate_queryset(queryset_user_id_query_params, request)
            if page_user_id_query_params is not None:
                serializer = get_serialized_data(
                    obj=page_user_id_query_params,
                    serializer=AdminListInsuranceSerializer,
                    fields=request.query_params.get("fields"),
                    many=True,
                )
                return CustomResponse(
                    pagination_class.get_paginated_response(serializer.data).data
                )
            serializer = get_serialized_data(
                obj=queryset_user_id_query_params,
                serializer=AdminListInsuranceSerializer,
                fields=request.query_params.get("fields"),
                many=True,
            )
        return CustomResponse(serializer.data)


class ListMedicalHistoryOfPatient(
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    """
    This API gives medical history of patient as well as family member medical history
    """
    response_serializer_class = MedicalResponseSerializer
    permission_classes = (IsAdminPatient,)

    def retrieve(self, request):
        """To retrieve details of patient"""
        user_id = request.query_params.get("user_id")
        family_mem_id = request.query_params.get("family_mem_id")
        if not user_id:
            result = user_in_auth_medicalhistory(family_mem_id, request)
            return CustomResponse(result)
        if user_id:
            result = user_in_params_medicalhistory(family_mem_id, user_id, request)
            return CustomResponse(result)
    # 4 Jan


'''API returning encrypted AWS keys'''


class GetAWSKey(mixins.CreateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)

    def create(self, request):
        import base64
        from config.local import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_STORAGE_BUCKET_NAME
        random_num = request.data.get('num')
        if random_num < 2:
            raise CustomApiException(
                status_code=400, message="Invalid Num",
                location="Post API keys")
        temp_dict = {
            'access_key': AWS_ACCESS_KEY_ID.encode('utf-8'),
            'secret_key': AWS_SECRET_ACCESS_KEY.encode('utf-8'),
            'bucket_name': AWS_STORAGE_BUCKET_NAME.encode('utf-8')
        }
        for _ in range(random_num):
            access_key = base64.encodebytes(temp_dict['access_key'])
            secret_key = base64.encodebytes(temp_dict['secret_key'])
            bucket_name = base64.encodebytes(temp_dict['bucket_name'])
            temp_dict['access_key'] = access_key
            temp_dict['secret_key'] = secret_key
            temp_dict['bucket_name'] = bucket_name

        response = {
            "access_key": base64.b64encode(temp_dict['access_key']),
            "secret_key": base64.b64encode(temp_dict['secret_key']),
            "bucket_name": base64.b64encode(temp_dict['bucket_name'])
        }
        return CustomResponse(response)


class EditDoctorInfo(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)

    def update(self, request):

        doc_obj = User.objects.filter(id=request.user.id).first()
        if not doc_obj:
            raise CustomApiException(
                status_code=400, message="Invalid doctor  id", location="update doctor"
            )
        # if the personal details are updated then it will be updated successfully
        # if email is updated then verification mail is sent to the email
        # serializers for personal details update is different and prosfessional details are differnt
        if request.data.get("personal"):
            # nested json hai toh details mey we can store the data and then update it.
            details = request.data.get("personal")
            serializer = EditDoctorPersonalInfoSerializer(
                instance=doc_obj, data=request.data, partial=True, context={"doc_obj": doc_obj, "details": details,
                                                                            "request": request}
            )
            serializer.is_valid(raise_exception=True)
            user_obj = serializer.save()
            if request.data.get("is_email_verified"):
                user_obj.is_email_verified = request.data.get("is_email_verified")
                user_obj.save()
            serializer = get_serialized_data(
                obj=user_obj,
                serializer=DocEditDoctorResponseSerializer,
                fields=request.query_params.get("fields"),
            )
            data = serializer.data
            ######################################
            # Adding temporary piece of code for email url (this will return the OTP also along with other parameter).
            email_url_obj = OTP.objects.filter(
                user=user_obj, otp_type=OTP.VERIFICATION_OTP
            ).first()
            data.update({"email_url_obj": email_url_obj.otp})
            return CustomResponse(data)
        # if the professional details are updated by the doctor then the serializers are diferent
        if request.data.get("professional"):
            details = request.data.get("professional")
            # if the professional details are updated by the doctor then the serializers are diferent

            """
            the validations are below
            """
            general_professional_validations(details, request)
            doctor_medical_doc = DoctorMedicalDoc.objects.filter(doctor_id=request.user.id).count()
            if details.get('tempdoctorinfo_documents'):
                tempdoctorinfo_documents = details.get('tempdoctorinfo_documents')
            if doctor_medical_doc + len(tempdoctorinfo_documents) > 3:
                raise CustomApiException(
                    status_code=400, message="There already exists 3 documents,kindly delete and upload again.",
                    location="update med doc"
                )
            if not TempDoctorWorkInfo.objects.filter(user_id=doc_obj.id).exists():
                TempDoctorWorkInfo.objects.update_or_create(user_id=request.user.id)
            med_obj = TempDoctorWorkInfo.objects.filter(user_id=request.user.id).first()
            serializer = TemporaryEditDoctorInfoSerializer(
                instance=med_obj, data=request.data, partial=True, context={"doc_obj": doc_obj, "details": details,
                                                                            "request": request, "med_obj": med_obj}
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return CustomResponse({"message": "The professional details are sent to Admin for verification"})


class GetTempTableDoctorInfo(
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    response_serializer_class = GetTempTableDoctorResponseSerializer
    permission_classes = (IsAdmin,)

    def retrieve(self, request, doctor_id):
        """To retrieve details of doctor"""
        doc_obj = TempDoctorWorkInfo.objects.filter(user_id=doctor_id).prefetch_related(
            'tempdoctorinfo_documents').select_related('dynamicshift').first()
        if not doc_obj:
            raise CustomApiException(
                status_code=400, message="Invalid doctor", location="retrieve temp doc"
            )
        serializer = GetTempTableDoctorResponseSerializer(doc_obj)
        return CustomResponse(serializer.data)


class VerifyDoctorDoc(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)

    def update(self, request, user_id):
        """method for verifying doctors work info"""
        if request.data.get("is_profile_approved") == False:
            try:
                delete_from_temp_table_obj = TempDoctorWorkInfo.objects.filter(user_id=user_id).first()
                delete_from_temp_table_obj.delete()
                raise CustomApiException(
                    status_code=400, message="Parameter not provided or not approved", location="verify_Doctor_Info"
                )
            except Exception:
                pass
        doc_obj = User.objects.filter(id=user_id).first()
        serializer = VerifyDocWorkInfoSerializer(
            instance=doc_obj,
            data=request.data,
            context={"request": request, "user_id": user_id}
        )
        serializer.is_valid(raise_exception=True)
        doc_obj = serializer.save()
        serializer = get_serialized_data(
            obj=doc_obj,
            serializer=VerifyDocWorkInfoResponseSerializer,
            fields=request.query_params.get("fields"),
        )
        response = {"message": "Information verified successfully"}
        return CustomResponse(response)


class DeleteDocMedicalDocuments(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """soft delete multiple medical documents of doctor in a list"""
    permission_classes = (IsAuthenticated,)

    def update(self, request):
        """method for deleting Doc medical documents"""
        medical_documents = request.data.get("medical_documents")
        DoctorMedicalDoc.objects.filter(document__in=medical_documents, doctor=request.user).update(
            is_deleted=True)  # soft deleting objects
        return CustomResponse({"message": "Medical Documents deleted successfully"})


# 20 Jan
class SymptomsBooking(
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    permission_classes = (IsAuthenticated,)
    serializer_class = SymptomSerializer
    response_serializer_class = SymptomResponseSerializer

    def retrieve(self, request):
        """To retrieve details of symptoms related to booking id"""
        user_id = request.user.id
        booking_id = request.query_params.get("booking_id")
        # here we are checking if the booking id entered , does it even exists or not
        if not Booking.objects.filter(id=booking_id).exists():
            raise CustomApiException(
                status_code=400, message="There is no booking is as such!!", location="retrieve symptoms"
            )
        # here symptom_obj is the objects of all bookings created by the patient, out of that we will retrive
        # the booking id mentioned in the url passed
        symptom_obj = Booking.objects.filter(patient_id=user_id).all()
        # if not symptom_obj:
        #     raise CustomApiException(
        #         status_code=400, message="The user_id has no booking!!", location="retrieve symptoms"
        #     )
        # symptom_obj.get(id=booking_id) if we get no attribute then it will throw error
        # hence try block is used to and error exception is suppressed by None
        try:
            user = symptom_obj.get(id=booking_id)
            if not Symptoms.objects.filter(booking_id_id=user.id).exists():
                raise CustomApiException(
                    status_code=400, message="Kindly add the symptoms first!!", location="retrieve symptoms"
                )
        except Booking.DoesNotExist:
            user = None
        symptom_obj = Symptoms.objects.filter(booking_id_id=booking_id).first()
        object_symp = SymptomsItems.objects.filter()
        """
        requirement is as 
        at present -- "items": [{"id": 1,"cat": "Gen","sub": "Fever"},{"id": 2,"cat": "Gen","sub": "BA"},],
        requirement hai -- [{General: {headache,1},{pain,2}},{Skin: {rash,3},{allergy,4}},]
        
        serializer ek baar mey ek hi object ko serialize karta hai, to_representation laaga kaay data aaya hai
        like -- [ {General:{headache,1} , {General:{pain,2} ]
        per hume chahiye [{General: {headache,1},{pain,2}}]
        so process followed is as-->
        """
        response_dic = {}
        serializer = SymptomsItemsSerializer(object_symp, many=True, context={"symptom_obj": symptom_obj})
        x = serializer.data
        for list_val in x:
            for k, v in list_val.items():
                if k in response_dic:
                    response_dic[k].extend(v)
                else:
                    response_dic[k] = v
        return CustomResponse({"id": symptom_obj.id, "items": dict(response_dic),
                               "additional_info": symptom_obj.additional_info})

    def update(self, request):
        booking_id = request.query_params.get("booking_id")
        user_id = request.user.id
        booking_obj = Booking.objects.filter(id=booking_id).first()
        if not booking_id:
            raise CustomApiException(
                status_code=400, message="Booking Id Invalid or not provided!!", location="update symptoms"
            )
        if not Booking.objects.filter(id=booking_id, patient_id=user_id).exists():
            raise CustomApiException(
                status_code=400, message="This patient doesnt has this booking id", location="update symptoms"
            )
        serializer = self.serializer_class(
            instance=booking_obj, data=request.data, partial=True, context={"request": request, "user_id": user_id,
                                                                            "booking_id": booking_id}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "The symptoms is updated successfully"})


# 25Jan
class Requestvisit(mixins.CreateModelMixin,
                   viewsets.GenericViewSet
                   ):
    permission_classes = (IsAuthenticated,)
    serializer_class = RequestvisitSerializer
    response_serializer_class = RequestvisitResponseSerializer

    def create(self, request, *args, **kwargs):
        """method for create booking visit"""
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        visit_obj = serializer.save()
        serializer = get_serialized_data(
            obj=visit_obj,
            serializer=self.response_serializer_class,
            fields=request.query_params.get("fields"),
        )
        return CustomResponse(serializer.data)

    def update(self, request, booking_id):
        booking_obj = Booking.objects.filter(id=booking_id).first()
        if not booking_obj:
            raise CustomApiException(
                status_code=400, message="Invalid booking_id", location="Update booking"
            )
        serializer = self.serializer_class(
            instance=booking_obj, data=request.data, partial=True, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        visit_obj = serializer.save()
        serializer = get_serialized_data(
            obj=visit_obj,
            serializer=self.response_serializer_class,
            fields=request.query_params.get("fields"),
        )
        return CustomResponse(serializer.data)


"""
There is seperate API for book the visit now or later
"""


class BookNowLaterVisit(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = BookNowLaterVisitSerializer
    response_serializer_class = BookNowVisitlaterResponseSerializer

    def update(self, request, booking_id):
        booking_obj = Booking.objects.filter(id=booking_id).first()
        if not booking_obj:
            raise CustomApiException(
                status_code=400, message="Invalid booking id", location="book now update"
            )

        serializer = self.serializer_class(
            instance=booking_obj, data=request.data, partial=True, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        visit_obj = serializer.save()
        serializer = get_serialized_data(
            obj=visit_obj,
            serializer=self.response_serializer_class,
            fields=request.query_params.get("fields"),
        )
        return CustomResponse(serializer.data)


# visit start and end time for the book now
class BookNowStartEndTime(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = BookNowStartEndTimeSerializer
    response_serializer_class = BookNowStartEndTimeResponseSerializer

    def update(self, request, booking_id):
        booking_obj = Booking.objects.filter(id=booking_id).first()
        if not booking_obj:
            raise CustomApiException(
                status_code=400, message="Invalid BookingId", location="book now start end time"
            )
        serializer = self.serializer_class(
            instance=booking_obj, data=request.data, partial=True, context={"request": request}
        )
        if not request.data.get('state') == 3:
            raise CustomApiException(
                status_code=400, message="kindly give state=3 for starting the visit timing",
                location="book now start end time"
            )
        serializer.is_valid(raise_exception=True)
        visit_obj = serializer.save()
        serializer = get_serialized_data(
            obj=visit_obj,
            serializer=self.response_serializer_class,
            fields=request.query_params.get("fields"),
        )
        return CustomResponse(serializer.data)


class AllVisits(mixins.ListModelMixin, viewsets.GenericViewSet):
    """ class for listing all upcoming visits"""
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination
    serializer_class = RequestvisitResponseSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter,)
    search_fields = ('patient__name', 'doctor__name', 'id', 'destination_address',)

    def list(self, request, *args, **kwargs):
        queryset = Booking.objects.filter(patient=request.user.id).exclude(state=2).exclude(
            state=2).select_related('doctor', 'doctor__profile_image').order_by('-created_at').all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=RequestvisitResponseSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=RequestvisitResponseSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class DoctorAssignDayWise(mixins.CreateModelMixin,
                          mixins.UpdateModelMixin,
                          viewsets.GenericViewSet
                          ):
    permission_classes = (IsAdmin,)
    serializer_class = DoctorAssignSerializer
    response_serializer_class = DoctorAssignResponseSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        if DoctorAssignDaily.objects.filter(doctor_id=request.data.get('doctor'),
                                            shift=request.data.get('shift'),
                                            date=request.data.get('date')).exists():
            raise CustomApiException(
                status_code=400, message="Doctor is assigned for today's shift!!",
                location="assign doctor"
            )
        serializer.is_valid(raise_exception=True)
        obj = serializer.save()
        serializer = get_serialized_data(
            obj=obj,
            serializer=self.response_serializer_class,
            fields=request.query_params.get("fields"),
        )
        return CustomResponse(serializer.data)

    def update(self, request, doctorassigned_id):
        location_error = "Update Assigned Doctor"
        doctorassigned_obj = DoctorAssignDaily.objects.filter(id=doctorassigned_id).first()
        if not doctorassigned_obj:
            raise CustomApiException(
                status_code=400, message="Invalid doctorassigned_id", location=location_error
            )
        if DoctorAssignDaily.objects.filter(doctor_id=request.data.get('doctor'),
                                            shift=request.data.get('shift'),
                                            date=request.data.get('date')).exists():
            raise CustomApiException(
                status_code=400, message="Doctor is assigned for today's shift!",
                location=location_error
            )
        serializer = self.serializer_class(
            instance=doctorassigned_obj, data=request.data, partial=True, context={"request": request,
                                                                                   "doctorassigned_id": doctorassigned_id}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Assigned Doctor updated successfully"})


class ListDoctorAssignDaily(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    serializer_class = ListDoctorAssignResponseSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('date', 'doctor__name',)

    def list(self, request, *args, **kwargs):
        hub = request.query_params.get('hub')
        visit_type = request.query_params.get('visit_type')
        visit_start_time = request.query_params.get('visit_start_time')
        if hub and visit_type and not visit_start_time:
            queryset = DoctorAssignDaily.objects.filter(date__gte=request.query_params.get(
                'startdate'), date__lte=request.query_params.get('enddate'), hub=hub, visit_type=visit_type
            ).select_related('doctor', 'doctor__profile_image', 'content_type').order_by('-date').all()
        elif hub and visit_type and visit_start_time:
            queryset = DoctorAssignDaily.objects.filter(shift_start_time__lte=request.query_params.get(
                'visit_start_time'), shift_end_time__gt=request.query_params.get('visit_start_time'),
                hub=hub, visit_type=visit_type
            ).select_related('doctor', 'doctor__profile_image', 'content_type').order_by('-date').all()
        else:
            queryset = DoctorAssignDaily.objects.filter(date__gte=request.query_params.get(
                'startdate'), date__lte=request.query_params.get('enddate')
            ).select_related('doctor', 'doctor__profile_image', 'content_type').order_by('-date').all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=ListDoctorAssignResponseSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=ListDoctorAssignResponseSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class NearestHubGetter(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """
    This will give the nearest hub and the hub docs for the medical disclosure screen in booking
    """
    serializer_class = NearestHubGetterSerializer
    permission_classes = (IsAuthenticated,)

    def retrieve(self, request):
        lat = request.query_params.get('lat')
        lng = request.query_params.get('lng')
        # is or == , both works
        if lat is None or lng == None:
            raise CustomApiException(
                status_code=400, message="Kindly provide both,lat and lng",
                location="nearest hub"
            )
        point = Point(x=float(lng), y=float(lat), srid=4326)
        distance_variable = 9999999
        """
        Here for loop is used,we need to calculate the nearest hub in the area
        Point is calculated for the lat and lng passed by the user
        In the loop , the len of hubs is calculated and iterated that many times
        We are taking each hub at a time and calculating its point.
        We are calculating the min_dis_between_pt(distance between the 2 points)
        Now we have taken a variable were min distance will be stored and if its 
        less then the  distance b/w 2 points calculated then 2337 is followed.
        Then we are string it as an queryset in saving_queryset so that it can
        be passed in the serializer
        """
        hub_obj = Hub.objects.filter(is_deleted=False)
        hub_obj_id_list = hub_obj.values_list('id', flat=True)
        for i in hub_obj_id_list:
            # Hub.objects.count() optimizes 60ms as compared to len(Hub.objects.all())
            particular_hub_object = hub_obj.filter(id=i).first()
            try:
                point_hub = Point(x=float(particular_hub_object.lng), y=float(particular_hub_object.lat), srid=4326)
                min_dis_between_pt = point.distance(point_hub)
                if min_dis_between_pt < distance_variable:
                    distance_variable = min_dis_between_pt
                    saving_queryset = Hub.objects.filter(id=i).first()
            except Exception:
                pass
        distance_variable = 9999999
        # print(saving_queryset,"saving_queryset is as -")
        serializer = get_serialized_data(
            obj=saving_queryset,
            serializer=self.serializer_class,
            fields=request.query_params.get("fields"),
        )
        return CustomResponse(serializer.data)


class InsuranceVerify(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = InsuranceVerifySerializer

    # patient will send the notification to admin for insurance verification
    def update(self, request, booking_id):
        booking_obj = Booking.objects.filter(id=booking_id).first()
        if not booking_obj:
            raise CustomApiException(
                status_code=400, message="Invalid booking", location="Verify Insurance."
            )
        if not request.data.get('insurance_id'):
            raise CustomApiException(
                status_code=400, message="Kindly give Insurance Id", location="Verify insurance"
            )
        insu_obj = InsuranceVerification.objects.filter(insurance_general_id=request.data.get('insurance_id'),
                                                        booking_id=booking_id).first()
        if insu_obj:
            insu_obj.delete()
        # insurance state is done from 1(create) to 2(new_request) when notfication is sent
        try:
            insurance_detail_send_obj = InsuranceDetails.objects.get(id=request.data.get('insurance_id'))
        except Exception:
            raise CustomApiException(
                status_code=400, message="Given insurance id is wrong.", location="verify insurance"
            )
        InsuranceVerification.objects.create(insurance_state=2, verification_date=datetime.utcnow(),
                                             booking=booking_obj, insurance_general=insurance_detail_send_obj,
                                             patient_id=booking_obj.patient_id, hub_amount=booking_obj.hub.amount)

        # noti_obj is to whom noti will go
        pat_obj = User.objects.filter(id=request.user.id, user_role=User.PATIENT).first()
        noti_obj = User.objects.filter(user_role=1).first()
        filtered_obj = noti_obj.user_device.filter(is_active=True).all()
        title = "Verification of Insurance Detail"
        message = "Kindly check the Patients insurance detail"
        data = {"groupid": insurance_detail_send_obj.groupid,
                "policyid": insurance_detail_send_obj.policyid,
                "securitynumber": insurance_detail_send_obj.securitynumber,
                }
        # send_notification(user_device_obj=filtered_obj,
        #                   title=title,
        #                   message=message,
        #                   data={"groupid": insurance_detail_send_obj.groupid,
        #                         "policyid": insurance_detail_send_obj.policyid,
        #                         "securitynumber": insurance_detail_send_obj.securitynumber,
        #                         })
        UserActivity.objects.create(sender_id=pat_obj.id, receiver_id=noti_obj.id,
                                    activity_type=1, title=title, message=message, payload=data)
        return CustomResponse({"message": "Insurance is sent to Admin for verification"})


class BookingMedicalDisclosure(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = MedicalDisclosureSerializer

    def update(self, request, booking_id):
        booking_obj = Booking.objects.filter(id=booking_id).first()
        if not booking_obj:
            raise CustomApiException(
                status_code=400, message="Invalid booking, pleease give correct Id", location="med disclosure."
            )
        if not request.data.get('medical_disclosure'):
            raise CustomApiException(
                status_code=400, message="Kindly give medical disclosure!!", location="Med Disclosure"
            )
        if not booking_obj.medical_disclosure is None:
            raise CustomApiException(
                status_code=400, message="Medical disclosure is alraedy saved", location="Med disclosure"
            )
        serializer = self.serializer_class(
            instance=booking_obj, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Documents with E-Signature has been saved successfully"})


class CancelBooking(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = CancelBookingSerializer
    response_serializer_class = CancelBookingResponseSerializer
    """
    Here the booking cancellation charges are decided.
    """

    def update(self, request, booking_id):
        booking_obj = Booking.objects.filter(id=booking_id).first()
        date_time = request.query_params.get('date_time')
        if not booking_obj:
            raise CustomApiException(
                status_code=400, message="Invalid BookingID", location="book deduct update"
            )
        if booking_obj.state == Booking.CANCEL or booking_obj.state == Booking.PAID:
            raise CustomApiException(status_code=400, message="Booking paid or cancelled already!!",
                                     location="book deduct update")
        serializer = self.serializer_class(
            instance=booking_obj, data=request.data, partial=True, context={"request": request, "date_time": date_time}
        )
        serializer.is_valid(raise_exception=True)
        visit_obj = serializer.save()
        serializer = get_serialized_data(
            obj=visit_obj,
            serializer=self.response_serializer_class,
            fields=request.query_params.get("fields"),
        )
        return CustomResponse(serializer.data)


# below are the 6 GET API's for the Booking module (till approx 2687)
class PatientVisits(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination
    serializer_class = PatientVisitsSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('doctor__name', 'id', 'familymember__name',)

    # On going meeting will be shown in past as state will be 3
    # bifurcation is done acc to state . state=3 is upcoming, state=4 is past
    def list(self, request, *args, **kwargs):
        if not (request.query_params.get('visit_type') or request.query_params.get('state')):
            raise CustomApiException(
                status_code=400, message="Kindly enter visit_type and state of booking", location="past visits")
        patient_id = request.user.id
        visit_type = request.query_params.get('visit_type')
        state = request.query_params.get('state')
        # this if is put because siorting is diffrent in both below queries
        if state == "3":
            queryset = Booking.objects.filter(patient_id=patient_id, visit_type=visit_type,
                                              state=state).order_by('visit_start_time').select_related('doctor',
                                                                                                       'doctor__profile_image',
                                                                                                       'patient',
                                                                                                       'patient__profile_image',
                                                                                                       'van', 'room',
                                                                                                       'virtualroom',
                                                                                                       'ratingdoc').all()
        elif state == "5":
            # here state 4 and 2 will be shown
            queryset = Booking.objects.filter(patient_id=patient_id, visit_type=visit_type,
                                              state__in=[2, 4]).order_by('-visit_start_time').select_related('doctor',
                                                                                                             'doctor__profile_image',
                                                                                                             'patient',
                                                                                                             'patient__profile_image',
                                                                                                             'van',
                                                                                                             'room',
                                                                                                             'virtualroom',
                                                                                                             'ratingdoc').all()
        queryset = self.filter_queryset(queryset)
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(queryset, request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=PatientVisitsSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=queryset,
            serializer=PatientVisitsSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class PatientUpcomingCountVisits(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('doctor__name', 'id', 'familymember__name',)

    def list(self, request, *args, **kwargs):
        video_query_count = Booking.objects.filter(patient_id=request.user.id, visit_type=Booking.VIDEO_CONFERENCING,
                                                   state=3).all().count()
        hub_query_count = Booking.objects.filter(patient_id=request.user.id, visit_type=Booking.HUB_VISIT,
                                                 state=3).all().count()
        mobile_query_count = Booking.objects.filter(patient_id=request.user.id, visit_type=Booking.MOBILE_DOCTOR,
                                                    state=3).all().count()
        return CustomResponse(
            {"video_count": video_query_count, "hub_count": hub_query_count, "mobile_count": mobile_query_count})


class AdminHubVisitBookings(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination
    serializer_class = AdminHubVisitBookingsSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('patient__name', 'doctor__name', 'id',)

    def list(self, request, *args, **kwargs):
        start_datetime = request.query_params.get('start_datetime')
        end_datetime = request.query_params.get('end_datetime')
        if not start_datetime or end_datetime:
            queryset = Booking.objects.filter().exclude(
                state=1).select_related('doctor',
                                        'doctor__profile_image',
                                        'patient',
                                        'patient__profile_image',
                                        'room',
                                        'familymember').prefetch_related('cancelledbooking').order_by(
                '-created_at').all()
        if start_datetime and end_datetime:
            queryset = Booking.objects.filter(visit_start_time__gte=start_datetime, visit_start_time__lte=end_datetime
                                              ).exclude(state=1).select_related('doctor',
                                                                                                           'doctor__profile_image',
                                                                                                           'patient',
                                                                                                           'patient__profile_image',
                                                                                                           'room',
                                                                                                           'familymember'
                                                                                                           ).prefetch_related(
                'cancelledbooking').order_by(
                '-created_at').all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=AdminHubVisitBookingsSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=AdminHubVisitBookingsSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class AdminMobDocBookings(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination
    serializer_class = AdminMobDocBookingsSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('patient__name', 'doctor__name', 'id',)

    def list(self, request, *args, **kwargs):
        start_datetime = request.query_params.get('start_datetime')
        end_datetime = request.query_params.get('end_datetime')
        if not start_datetime or end_datetime:
            queryset = Booking.objects.filter().exclude(state=1
                                                        ).prefetch_related('cancelledbooking'
                                                                          ).select_related('doctor',
                                                                                'doctor__profile_image', 'patient',
                                                                                'patient__profile_image',
                                                                                'van', 'familymember').order_by(
                '-created_at').all()
        if start_datetime and end_datetime:
            queryset = Booking.objects.filter(visit_start_time__gte=start_datetime, visit_start_time__lte=end_datetime,
                                              ).exclude(state=1
                                                                                   ).prefetch_related('cancelledbooking'
                                                                                                     ).select_related('doctor',
                                                                                                           'doctor__profile_image',
                                                                                                           'patient',
                                                                                                           'patient__profile_image',
                                                                                                           'van',
                                                                                                           'familymember').order_by(
                '-created_at').all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=AdminMobDocBookingsSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=AdminMobDocBookingsSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class AdminVideoConBookings(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination
    serializer_class = AdminVideoConBookingsSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('patient__name', 'doctor__name', 'id',)

    def list(self, request, *args, **kwargs):
        start_datetime = request.query_params.get('start_datetime')
        end_datetime = request.query_params.get('end_datetime')
        if not start_datetime or end_datetime:
            queryset = Booking.objects.filter().exclude(state=1).prefetch_related('cancelledbooking'
                                                                                 ).select_related('doctor',
                                                                                'doctor__profile_image', 'patient',
                                                                                'patient__profile_image',
                                                                                'virtualroom', 'familymember').order_by(
                '-created_at').all()
        if start_datetime and end_datetime:
            queryset = Booking.objects.filter(visit_start_time__gte=start_datetime, visit_start_time__lte=end_datetime
                                              ).exclude(state=1).prefetch_related('cancelledbooking'
                                                                                 ).select_related('doctor',
                                                                                'doctor__profile_image', 'patient',
                                                                                'patient__profile_image',
                                                                                'virtualroom', 'familymember').order_by(
                '-created_at').all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=AdminVideoConBookingsSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=AdminVideoConBookingsSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class DoctorHubVisitBookings(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination
    serializer_class = DoctorHubVisitBookingsSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('patient__name', 'id', 'doctor__name',)

    # on going meeting will be shown in past visits
    def list(self, request, *args, **kwargs):
        doctor_id = request.user.id
        if request.query_params.get("is_upcoming"):
            queryset = Booking.objects.filter(doctor=doctor_id, state=3, room_id__isnull=False).select_related('doctor',
                                                                                                               'doctor__profile_image',
                                                                                                               'patient',
                                                                                                               'patient__profile_image',
                                                                                                               'room',
                                                                                                               'familymember').order_by(
                'visit_start_time').all()
        else:
            queryset = Booking.objects.filter(doctor=doctor_id, state=4, room_id__isnull=False).select_related('doctor',
                                                                                                               'doctor__profile_image',
                                                                                                               'patient',
                                                                                                               'patient__profile_image',
                                                                                                               'room',
                                                                                                               'familymember').order_by(
                '-visit_start_time').all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=DoctorHubVisitBookingsSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=DoctorHubVisitBookingsSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class DoctorMobDocBookings(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination
    serializer_class = DoctorMobDocBookingsSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('patient__name', 'id', 'doctor__name',)

    def list(self, request, *args, **kwargs):
        doctor_id = request.user.id
        if request.query_params.get("is_upcoming"):
            queryset = Booking.objects.filter(doctor=doctor_id, state=3, van_id__isnull=False).select_related('doctor',
                                                                                                              'doctor__profile_image',
                                                                                                              'patient',
                                                                                                              'patient__profile_image',
                                                                                                              'van',
                                                                                                              'familymember').order_by(
                'visit_start_time').all()
        else:
            queryset = Booking.objects.filter(doctor=doctor_id, state=4, van_id__isnull=False).select_related('doctor',
                                                                                                              'doctor__profile_image',
                                                                                                              'patient',
                                                                                                              'patient__profile_image',
                                                                                                              'van',
                                                                                                              'familymember').order_by(
                '-visit_start_time').all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=DoctorMobDocBookingsSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=DoctorMobDocBookingsSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class DoctorVideoConBookings(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination
    serializer_class = DoctorVideoConBookingsSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('patient__name', 'id', 'doctor__name',)

    def list(self, request, *args, **kwargs):
        doctor_id = request.user.id
        if request.query_params.get("is_upcoming"):
            queryset = Booking.objects.filter(doctor=doctor_id, state=3, virtualroom_id__isnull=False).select_related(
                'doctor',
                'doctor__profile_image',
                'patient',
                'patient__profile_image',
                'virtualroom', 'familymember').order_by(
                'visit_start_time').all()
        else:
            queryset = Booking.objects.filter(doctor=doctor_id, state=4, virtualroom_id__isnull=False).select_related(
                'doctor',
                'doctor__profile_image',
                'patient',
                'patient__profile_image',
                'virtualroom', 'familymember'
            ).order_by('-visit_start_time').all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=DoctorVideoConBookingsSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=DoctorVideoConBookingsSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class RetriveBooking(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = RetriveBookingSerializer

    def retrieve(self, request):
        booking_id = request.query_params.get("booking_id")
        obj = Booking.objects.filter(id=booking_id).select_related('doctor',
                                                                   'doctor__profile_image', 'patient',
                                                                   'patient__profile_image',
                                                                   'van', 'room', 'virtualroom', 'familymember').first()
        if not obj:
            raise CustomApiException(
                status_code=400, message="There is no booking is as such !!", location="retrive boooking"
            )
        serializer = RetriveBookingSerializer(obj)
        return CustomResponse(serializer.data)


class RoleManagement(mixins.CreateModelMixin,
                     mixins.RetrieveModelMixin,
                     mixins.UpdateModelMixin,
                     viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)
    serializer_class = RoleManagementSerializer

    def create(self, request, *args, **kwargs):
        serializer = RoleManagementSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user_obj = serializer.save()
        serializer = get_serialized_data(
            obj=user_obj,
            serializer=RoleManagementResponseSerializer,
            fields=request.query_params.get("fields"), )
        data = serializer.data
        return CustomResponse(data)

    def update(self, request, role_id):
        role_obj = RolesManagement.objects.filter(id=role_id).first()
        if not role_obj:
            raise CustomApiException(
                status_code=400, message="Invalid role_id", location="update role"
            )
        serializer = self.serializer_class(
            instance=role_obj, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Role updated successfully"})

    def retrieve(self, request, role_id):
        """To retrieve details of particular room"""
        role_obj = RolesManagement.objects.filter(id=role_id).first()
        if not role_obj:
            raise CustomApiException(
                status_code=400, message="Invalid role id", location="retrieve role"
            )
        serializer = RoleManagementResponseSerializer(role_obj)
        return CustomResponse(serializer.data)


class DeleteRoleManagement(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)

    def update(self, request):
        role_ids = request.data.get("role_ids")
        RolesManagement.objects.filter(id__in=role_ids).delete()
        return CustomResponse({"message": "Roles Deleted successfully"})


class Deletestaff(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)

    def update(self, request):
        staff_ids = request.data.get("staff_ids")
        # is deleted ko isse kaay liye liya tha , but is creating issue ki deleted hai toh, another signin with
        # same email toh issue hai, iss liye delete hard doing
        User.objects.filter(id__in=staff_ids).delete()
        return CustomResponse({"message": "Staff Deleted successfully"})


class ListRoleManagement(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    serializer_class = RoleManagementResponseSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('user_role',)

    def list(self, request, *args, **kwargs):
        queryset = RolesManagement.objects.filter().exclude(is_deleted=True).order_by('-created_at').all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=RoleManagementResponseSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=RoleManagementResponseSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class SubAdminSignUp(mixins.CreateModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """
    this is the staff management signup
    """
    permission_classes = (IsAdmin,)

    def create(self, request, *args, **kwargs):
        device_uuid = request.data.pop("device_uuid")
        if request.data.get('user_role') != User.SUBADMIN:
            raise CustomApiException(
                status_code=400, message="The user role has to be 2 always for subadmin", location="create subadmin"
            )
        serializer = SubAdminSignupSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user_obj = serializer.save()
        # creating the obj of device from which it is logged in to send notification to admin
        DeviceManagement.objects.update_or_create(user=user_obj, device_uuid=device_uuid, defaults={
            "device_uuid": device_uuid,
            "fcm_token": request.data['fcm_token']})
        token, created = Token.objects.get_or_create(user=user_obj)
        serializer = get_serialized_data(
            obj=user_obj,
            serializer=SubAdminSignupResponseSerializer,
            fields=request.query_params.get("fields"), )
        data = serializer.data
        return CustomResponse(data)

    """
    This is used because the user role if updated then the users containing these roles will be     
    logged out and deactivated , when the admin activates the subadmins then the users will be 
    able to login 
    """

    def update(self, request):
        role_management_id = request.data.get('role_management_id')
        role_obj = User.objects.filter(role_management__in=role_management_id).all()
        if not role_management_id:
            raise CustomApiException(
                status_code=400, message="Invalid role_management_id", location="update subadmin role"
            )
        role_obj.update(is_active=False)
        return CustomResponse({"message": "The Users are deactivated for this roles"})

    def retrieve(self, request, subadmin_id):
        """To retrieve details of particular room"""
        staff_obj = User.objects.filter(id=subadmin_id).select_related('auth_token', 'role_management').first()
        if not staff_obj:
            raise CustomApiException(
                status_code=400, message="Invalid subadmin_id", location="retrieve staff"
            )
        serializer = SubAdminSignupResponseSerializer(staff_obj)
        return CustomResponse(serializer.data)


class SubAdminActDeactAcc(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    # This class is used to activate and deactivate the account of the subadmin
    # is_email_verified is used for True or False to act and deact respectively
    """
    this is the staff management activate and deactivate account
    """
    permission_classes = (IsAdmin,)
    serializer_class = SubAdminActDeactAccSerializer

    def update(self, request, subadmin_id):
        obj = User.objects.filter(id=subadmin_id).first()
        if not subadmin_id:
            raise CustomApiException(
                status_code=400, message="Invalid subadmin id", location="activate subadmin"
            )
        serializer = self.serializer_class(
            instance=obj, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse(serializer.data)


class ListSubAdmin(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    serializer_class = SubAdminSignupResponseSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('name', 'email', 'phone_number',)

    def list(self, request, *args, **kwargs):
        queryset = User.objects.filter(user_role=User.SUBADMIN).exclude(is_deleted=True).select_related(
            'role_management',
            'auth_token').order_by('-created_at').all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=SubAdminSignupResponseSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=SubAdminSignupResponseSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


def roundtimeinmin(dt, delta):
    return dt + (datetime.min - dt) % delta


class AvailableSlotsVideoHub(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination

    def retrieve(self, request):
        visit_type = request.query_params.get("visit_type")
        start_datetime = request.query_params.get("start_datetime")
        end_datetime = request.query_params.get("end_datetime")
        if (datetime.fromisoformat(end_datetime) - datetime.fromisoformat(start_datetime) <= timedelta(minutes=30)):
            slot_avail = []
            return CustomResponse({'AvailableSlots': slot_avail})
        # here the time will round off by minutes
        start_datetime = str(roundtimeinmin(datetime.fromisoformat(start_datetime), timedelta(minutes=30)))
        hub = request.query_params.get("hub")
        if int(visit_type) != 2 and int(visit_type) != 3:
            raise CustomApiException(
                status_code=400,
                message="Visit type is not correct",
                location="retrive slot")
        # yaha pe doctor 5 assigned hai , booking 4 hai same time pe , toh doctor_assigned count - booking agar
        # > 0 hai , then print the slot available
        doctor_asgd_count = DoctorAssignDaily.objects.filter(hub=hub, shift_start_time__lte=start_datetime,
                                                             shift_end_time__gte=end_datetime,
                                                             visit_type=visit_type).count()
        if request.version == 'v1.0':
            count = 0
            for i in range(1, 19):
                start_datetime = str(datetime.strptime(start_datetime, date_time_string) + timedelta(minutes=30))
                count = count + 1
                if start_datetime == end_datetime:
                    break
        # start_datetime loop kaay wajah se distort hua hai , toh phir se getting from query params
        start_datetime = request.query_params.get("start_datetime")
        start_datetime = str(roundtimeinmin(datetime.fromisoformat(start_datetime), timedelta(minutes=30)))
        # available slots ko return karengay toh ye store kiya hai
        slot_avail = []
        for i in range(1, count + 1):
            booking_count = Booking.objects.filter(hub=hub, visit_type=visit_type, visit_start_time__gte=start_datetime,
                                                   visit_end_time__lte=str(datetime.strptime(
                                                       start_datetime, date_time_string) + timedelta(
                                                       minutes=30)), doctor_id__isnull=False).count()
            if doctor_asgd_count - booking_count > 0:
                slot_avail.append(start_datetime)
            start_datetime = str(datetime.strptime(start_datetime, date_time_string) + timedelta(minutes=30))
        return CustomResponse({'AvailableSlots': slot_avail})


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


class AvailableSlotsMobDoc(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination

    def retrieve(self, request):
        visit_type = request.query_params.get("visit_type")
        start_datetime = request.query_params.get("start_datetime")
        end_datetime = request.query_params.get("end_datetime")
        """
        yaaha pe agar start end time 14:31:00 and 15:00:00 hai toh 15:00:00 se aagay ki timeslots aa raahay thay.
        toh to fix this this below if cond is given , ki slot available [] aa jaae
        """
        if (datetime.fromisoformat(end_datetime) - datetime.fromisoformat(start_datetime) <= timedelta(hours=1)):
            slot_avail = []
            return CustomResponse({'AvailableSlots': slot_avail})
        # here the time will round off by hour
        start_datetime = str(roundtimeinhour(datetime.fromisoformat(start_datetime)))

        hub = request.query_params.get("hub")
        if int(visit_type) != 1:
            raise CustomApiException(
                status_code=400,
                message="Kindly check the visit type , visit type is wrong",
                location="retrive slot")
        # yaha pe doctor 5 assigned hai , booking 4 hai same time pe , toh doctor_assigned count - booking agar
        # > 0 hai , then print the slot available
        doctor_asgd_count = DoctorAssignDaily.objects.filter(hub=hub, shift_start_time__lte=start_datetime,
                                                             shift_end_time__gte=end_datetime,
                                                             visit_type=visit_type).count()
        # max 1 shift mey 17 slots hai, aur start_datetime se aagay kaay timeslots(count) kaay liye
        # loop hai
        count = 0
        for i in range(1, 10):
            start_datetime = str(datetime.strptime(start_datetime, date_time_string) + timedelta(hours=1))
            count = count + 1
            if start_datetime == end_datetime:
                break
        # start_datetime loop kaay wajah se distort hua hai , toh phir se getting from query params
        start_datetime = request.query_params.get("start_datetime")
        start_datetime = str(roundtimeinhour(datetime.fromisoformat(start_datetime)))
        # available slots ko return karengay toh ye store kiya hai
        slot_avail = []
        for i in range(1, count + 1):
            booking_count = Booking.objects.filter(hub=hub, visit_type=visit_type, visit_start_time__gte=start_datetime,
                                                   visit_end_time__lte=str(datetime.strptime(
                                                       start_datetime, date_time_string) + timedelta(
                                                       hours=1)), doctor_id__isnull=False).count()
            if doctor_asgd_count - booking_count > 0:
                slot_avail.append(start_datetime)
            start_datetime = str(datetime.strptime(start_datetime, date_time_string) + timedelta(hours=1))
        return CustomResponse({'AvailableSlots': slot_avail})


class AdminUpdateBooking(mixins.UpdateModelMixin,
                         viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)
    serializer_class = AdminUpdateBookingSerializer

    def update(self, request, booking_id):
        book_obj = Booking.objects.filter(id=booking_id).first()
        if not book_obj or not request.data.get('current_datetime'):
            raise CustomApiException(
                status_code=400, message="Invalid Id . or current date time not provided",
                location="update booking admin"
            )
        serializer = self.serializer_class(
            instance=book_obj, data=request.data, partial=True, context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Booking updated successfully"})


class OverAllVisits(mixins.ListModelMixin, viewsets.GenericViewSet):
    """ class for listing all visits"""
    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    serializer_class = OverAllVisitsResponseSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter,)
    search_fields = ('patient__name', 'doctor__name', 'id', 'familymember__name')

    def list(self, request, *args, **kwargs):
        start_datetime = request.query_params.get('start_datetime')
        end_datetime = request.query_params.get('end_datetime')
        if not start_datetime or end_datetime:
            queryset = Booking.objects.filter().exclude(state=1).prefetch_related('cancelledbooking'
                                                                                  ).select_related('doctor',
                                                                                'doctor__profile_image', 'patient',
                                                                                'patient__profile_image',
                                                                                'van', 'room',
                                                                                'virtualroom',
                                                                                'familymember').order_by(
                '-created_at').all()
        if start_datetime and end_datetime:
            queryset = Booking.objects.filter(visit_start_time__gte=start_datetime, visit_start_time__lte=end_datetime
                                              ).exclude(state=1).prefetch_related('cancelledbooking'
                                                                                  ).select_related('doctor',
                                                                                'doctor__profile_image', 'patient',
                                                                                'patient__profile_image',
                                                                                'van', 'room', 'virtualroom').order_by(
                '-created_at').all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=OverAllVisitsResponseSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=OverAllVisitsResponseSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class GetCMInfoForBooking(
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    response_serializer_class = GetCMBookingSerializer
    permission_classes = (IsAuthenticated,)

    def retrieve(self, request):
        """To retrieve details of CM"""
        cm_obj = ContentManagement.objects.filter().first()
        if not cm_obj:
            raise CustomApiException(
                status_code=400, message="CM is not stored", location="retrieve cm"
            )
        serializer = get_serialized_data(
            obj=cm_obj,
            serializer=GetCMBookingSerializer,
            fields=request.query_params.get("fields"),
        )
        return CustomResponse(serializer.data)


class AdminListRatings(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
        API to list doctor or app ratings to the admin
    """
    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    serializer_class = ListRatingsSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter,)
    search_fields = ("doctor__name", "patient__name", "rating", "comment_box")

    def list(self, request, *args, **kwargs):
        doc_or_app = request.query_params.get('type')
        queryset = RatingDocAndApp.objects.filter(rating_doc_or_app=doc_or_app
                                                  ).exclude(is_deleted=True).select_related(
            'doctor', 'doctor__profile_image', 'patient', 'patient__profile_image').all().order_by(
            'rating')
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=ListRatingsSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )

        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=ListRatingsSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class DeleteMultipleReviews(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)

    def update(self, request):
        """method for deleting reviews"""
        review_ids = request.data.get("review_ids")
        # soft deleting all flags at once
        RatingDocAndApp.objects.filter(id__in=review_ids).update(is_deleted=True)
        return CustomResponse({"message": "Reviews Deleted successfully"})


class PatientDoctorAdminBooking(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
        API to list particular doctor or patient booking done
    """
    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    serializer_class = PatientDoctorAdminBookingSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter,)
    search_fields = ("id", "doctor__name", "patient__name", "destination_address", "source_address")

    def list(self, request, *args, **kwargs):
        patient_id = request.query_params.get('patient_id')
        doctor_id = request.query_params.get('doctor_id')
        if patient_id and doctor_id:
            raise CustomApiException(status_code=400, message="Select either patient or doctor",
                                     location="list pat doc booking")
        elif patient_id:
            queryset = Booking.objects.filter(patient=patient_id).exclude(doctor=None).select_related('doctor',
                                                                                                      'doctor__profile_image',
                                                                                                      'patient',
                                                                                                      'patient__profile_image').order_by(
                'id').all()
        elif doctor_id:
            queryset = Booking.objects.filter(doctor=doctor_id).select_related('doctor',
                                                                               'doctor__profile_image', 'patient',
                                                                               'patient__profile_image').order_by(
                'id').all()
        else:
            raise CustomApiException(status_code=400, message="Select atleast patient or doctor",
                                     location="list pat doc booking")
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=PatientDoctorAdminBookingSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )

        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=PatientDoctorAdminBookingSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class DashboardInfo(APIView):
    permission_classes = (IsAdmin,)

    def get(self, request, *args, **kwargs):
        """method for dashboard data"""
        data = request.GET
        datetime_format = "%Y-%m-%d"
        start_date = datetime.strptime(data['start_date'], datetime_format).date()
        end_date = datetime.strptime(data['end_date'], datetime_format).date()
        end_date = end_date + timedelta(days=1)
        all_user = User.objects.filter(created_at__gte=start_date, created_at__lte=end_date).values(
            'user_role').annotate(count=Count('id')).order_by('user_role')
        pait_count, doc_count = 0, 0
        for user in all_user:
            if user['user_role'] == 3:
                pait_count = user['count']
            elif user['user_role'] == 4:
                doc_count = user['count']
        hub_count = Hub.objects.filter(created_at__gte=start_date, created_at__lte=end_date, is_deleted=False).count()
        van_count = Van.objects.filter(created_at__gte=start_date, created_at__lte=end_date, is_deleted=False).count()
        room_count = Room.objects.filter(created_at__gte=start_date, created_at__lte=end_date, is_deleted=False).count()
        virtual_room_count = VirtualRoom.objects.filter(created_at__gte=start_date,
                                                        created_at__lte=end_date, is_deleted=False).count()
        visit_obj = Booking.objects.filter(created_at__gte=start_date, created_at__lte=end_date).exclude(doctor_id=None)
        total_earning = visit_obj.aggregate(amount=Sum('total_amount'))
        visit_cancelled = Booking.objects.filter(created_at__gte=start_date, created_at__lte=end_date, state=2).count()
        rating_app = Avg('rating', filter=Q(rating_doc_or_app=1))
        rating_doc = Avg('rating', filter=Q(rating_doc_or_app=2))
        avg_ratings = RatingDocAndApp.objects.filter(created_at__gte=start_date, created_at__lte=end_date)
        avg_rating_app = avg_ratings.aggregate(rating_app=rating_app)
        avg_rating_doc = avg_ratings.aggregate(rating_doc=rating_doc)
        book_obj = Booking.objects.filter(created_at__gte=start_date, created_at__lte=end_date).all()
        hold_booking = book_obj.filter(state=3).aggregate(Sum('co_pay'))
        paid_booking = book_obj.filter(state=4).aggregate(Sum('co_pay'))
        hub_obj = Hub.objects.filter().all()
        insurance = 0
        for i in visit_obj:
            co_pay = i.co_pay
            hub_id = i.hub_id
            try:
                hub_amount = float(hub_obj.get(id=hub_id).amount)
                insurance = insurance + (hub_amount - float(co_pay))
            except Exception:
                pass
        insurance_projection = insurance
        context = {'pait_count': pait_count, 'doc_count': doc_count, 'hub_count': hub_count, 'van_count': van_count,
                   'room_count': room_count, 'virtual_room_count': virtual_room_count,
                   'visit_cancelled': visit_cancelled, 'earnings': total_earning['amount'],
                   'avg_rating_app': avg_rating_app['rating_app'], 'avg_rating_doc': avg_rating_doc['rating_doc'],
                   'hold_booking': list(hold_booking.values())[0], 'paid_booking': list(paid_booking.values())[0],
                   'insurance_projection': insurance_projection
                   }
        return CustomResponse(context)


class DashboardCharts(APIView):
    permission_classes = (IsAdmin,)

    def get(self, request, *args, **kwargs):
        """method for dashboard chart"""
        data = request.GET
        datetime_format = "%Y-%m-%d"
        start_date = datetime.strptime(data['start_date'], datetime_format).date()
        end_date = datetime.strptime(data['end_date'], datetime_format).date()
        end_date = end_date + timedelta(days=1)
        ticket_obj = Ticket.objects.filter(created_at__gte=start_date, created_at__lte=end_date)
        all_tickets = ticket_obj.values('ticket_regard_type').annotate(count=Count('id')).order_by('ticket_regard_type')
        resolved_ticket = ticket_obj.filter(is_resolved=True).count()
        data_dict = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        doctor_amount = ''
        for ticket in all_tickets:
            data_dict[ticket['ticket_regard_type']] = ticket['count']
        tickets = list(data_dict.values())
        unresolved_ticket = sum(tickets) - resolved_ticket
        all_user = User.objects.filter(created_at__gte=start_date, created_at__lte=end_date)
        booking_obj = Booking.objects.filter(created_at__gte=start_date, created_at__lte=end_date).exclude(doctor=None)
        perdaydoc_pay_obj = DoctorPerDayAmount.objects.filter(
            payment_perday_date__gte=start_date, payment_perday_date__lte=request.query_params.get('end_date'))
        date_variable = "date(created_at)"
        """
        # this is the process for the video conferencing date wise count
        # dateList is the list of dates where count is not 0
        the below 3 bunch of coding is to get the list of video confere,hub ,mobile doc day wise count of booking 
        """
        video_confer = booking_obj.filter(visit_type=Booking.VIDEO_CONFERENCING).extra(
            {'created_at': date_variable}).values('created_at').annotate(count=Count('id')).order_by(
            'created_at')
        video_conf_list = dashboard_function_count(video_confer, start_date, end_date)

        """
        this is the process for the hub date wise count
        """
        hub = booking_obj.filter(visit_type=Booking.HUB_VISIT).extra(
            {'created_at': date_variable}).values('created_at').annotate(count=Count('id')).order_by('created_at')
        hub_list = dashboard_function_count(hub, start_date, end_date)
        """    
        This is for the mobile doc date wise count
        """
        mobile_doc = booking_obj.filter(visit_type=Booking.MOBILE_DOCTOR).extra(
            {'created_at': date_variable}).values('created_at').annotate(count=Count('id')).order_by('created_at')
        mobile_doc_list = dashboard_function_count(mobile_doc, start_date, end_date)
        """
        Now we have to get the patient and doctor count on daily basis so
        next 2 bunch of coding(patient and doctor) will give the patient and doctor day wise created count
        """
        patient = all_user.filter(user_role=3).extra({'created_at': date_variable}).values(
            'created_at').annotate(count=Count('id')).order_by('created_at')
        patient_list = dashboard_function_count(patient, start_date, end_date)
        doctor = all_user.filter(user_role=4).extra({'created_at': date_variable}).values(
            'created_at').annotate(count=Count('id')).order_by('created_at')
        doctor_list = dashboard_function_count(doctor, start_date, end_date)
        # doctor's per day payment sum
        doctor_pay_date_wise = perdaydoc_pay_obj.values('payment_perday_date').annotate(Sum('amount_perday'))
        doctor_pay_date_wise_list = dashboard_function_aggregate_per_day(doctor_pay_date_wise, start_date, end_date)
        context = {'doctors_payment': doctor_pay_date_wise_list,
                   'patient': patient_list,
                   'doctor': doctor_list, 'hub': hub_list, 'video_conference': video_conf_list,
                   'mobile_doctor': mobile_doc_list, 'tickets': tickets,
                   'resolved_ticket': resolved_ticket, 'unresolved_ticket': unresolved_ticket,
                   'doctor_amount': doctor_amount,
                   }
        return CustomResponse(context)


class RetrievePatientInfo(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = RetrievePatientInfoSerializer

    def retrieve(self, request):
        booking_id = request.query_params.get("booking_id")
        obj = Booking.objects.filter(id=booking_id).select_related('doctor', 'familymember'
                                                             , 'doctor__profile_image', 'patient',
                                                             'patient__profile_image', 'ratingdoc'
                                                                   ).prefetch_related('cancelledbooking'
                                                                                      ).first()
        if obj.state == Booking.COMPLETED or obj.state == Booking.BOOKING_CREATED:
            serializer = RetrievePatientInfoSerializer(obj)
            return CustomResponse(serializer.data)
        elif obj.state == Booking.CANCEL:
            serializer = RetrievePatientInfoCancelSerializer(obj)
            return CustomResponse(serializer.data)


class CoPayBooking(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    """
    this is used to update the co-pay of the booking as admin will also use and FE will also use to save the co_pay
    """

    def update(self, request, booking_id):
        book_obj = Booking.objects.filter(id=booking_id)
        if not book_obj:
            raise CustomApiException(
                status_code=400, message="Invalid Id !", location="update booking admin"
            )
        co_pay = request.data.get('co_pay')
        book_obj.update(co_pay=co_pay)
        return CustomResponse({"message": "Copay added successfully"})


class DoctorFinalApproveVisitBooking(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """
    Here the state=4 is put for the doctor so that visit is completed and this will confirm the payment API can be carried
    out.
    """
    permission_classes = (IsAuthenticated,)

    def update(self, request, booking_id):
        book_obj = Booking.objects.filter(id=booking_id)
        if not book_obj:
            raise CustomApiException(
                status_code=400, message="Invalid Booking  Id", location="update booking state 4"
            )
        state = request.data.get('state')
        if state != 4:
            raise CustomApiException(
                status_code=400, message="Kindly give state equals to 4 to approve the visit completion.!!",
                location="update booking state 4"
            )
        book_obj.update(state=state)
        return CustomResponse({"id": booking_id, "state": book_obj.get(id=booking_id).state})


class DesignationAmount(
    mixins.CreateModelMixin,
    viewsets.GenericViewSet,
):
    """
    Doctors have designation NP,PA,Pysician and for each type amount is created or updated.
    """
    permission_classes = (IsAdmin,)
    serializer_class = DesignationAmountSerializer

    def create(self, request, *args, **kwargs):
        physician = request.data.get('physician')
        PA = request.data.get('PA')
        NP = request.data.get('NP')
        if not physician or not PA or not NP:
            raise CustomApiException(
                status_code=400, message="Kindly give pysician , PA , NP ",
                location="create designation amount"
            )
        serializer = self.serializer_class(
            data=request.data, context={"physician": physician, "PA": PA, "NP": NP}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Designation amount added successfully"})


class DesignationAmountList(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)
    serializer_class = DesignationAmountResponseSerializer
    queryset = Designation_Amount.objects.filter().order_by("created_at").all()

    def list(self, request, *args, **kwargs):
        """method for listing designation amount"""
        response = super().list(self, request, *args, **kwargs)
        return CustomResponse(response.data)


class PerDayPaymentToDoctors(
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """
    Doctors are paid daily wage on the basis of working hours , so admin can update the working hours
    """
    permission_classes = (IsAdmin,)
    serializer_class = DoctorPerDayPaymentSerializer

    def update(self, request, paymanagement_id):
        paymanagement_obj = DoctorPerDayAmount.objects.filter(id=paymanagement_id).first()
        if not paymanagement_obj:
            raise CustomApiException(
                status_code=400, message="Invalid paymanagement_id", location="update payment management"
            )
        serializer = self.serializer_class(
            instance=paymanagement_obj, data=request.data, partial=True,
            context={"request": request, "paymanagement_id": paymanagement_id}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Working hours updated successfully"})


class PerDayPaymentList(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    serializer_class = PerDayPaymentResponseSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter,)
    search_fields = ('user__name', 'user__email', 'workinghours', 'amount_perday')

    def list(self, request, *args, **kwargs):
        date = request.query_params.get('date')
        queryset = DoctorPerDayAmount.objects.filter(payment_perday_date=date).select_related('user'
                                                                                              ).order_by(
            '-created_at').all()
        if not queryset:
            # requirement from FE for this response
            return CustomResponse(
                {
                    "count": 0,
                    "next": None,
                    "previous": None,
                    "results": []
                }
            )
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=PerDayPaymentResponseSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=PerDayPaymentResponseSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


import calendar


def get_previous_month(date_time_str):  # i/p is as 2017-10-10
    now = datetime.strptime(date_time_str, date_string)
    last_month = now.month - 1 if now.month > 1 else 12
    if last_month == 12:
        last_year = now.year - 1
    else:
        last_year = now.year
    last_day_of_month = calendar.monthrange(last_year, last_month)[1]
    start_date = datetime(last_year, last_month, 1, 00, 00, 00)
    end_date = datetime(last_year, last_month, last_day_of_month, 00, 00, 00)
    return start_date, end_date  # o/p is as 2017-09-01 and 2017-09-30


class AmountPaidToDoctorMonthly(mixins.RetrieveModelMixin,
                                viewsets.GenericViewSet, ):
    permission_classes = (IsAdmin,)

    def retrieve(self, request):
        date_request = request.query_params.get("current_date")
        start_date, end_date = get_previous_month(date_request)
        sum_of_amount = DoctorPerDayAmount.objects.filter(payment_perday_date__gte=start_date.date(),
                                                          payment_perday_date__lte=end_date.date()).aggregate(
            Sum('amount_perday'))
        # if the payment is done for last month(is_paid=true) or last month no doctors
        # were there(sum_of_amount['amount_perday__sum']==None)
        # then this month payment will be calculated upto current date and returned
        try:
            boolean_obj = DoctorPerDayAmount.objects.filter(payment_perday_date__gte=start_date.date(),
                                                            payment_perday_date__lte=end_date.date()).first().is_paid
        except Exception:
            boolean_obj = True
        if boolean_obj or sum_of_amount['amount_perday__sum'] == None:
            current_date = datetime.strptime(date_request, date_string)
            first_day_of_month = current_date.replace(day=1)
            sum_of_amount = DoctorPerDayAmount.objects.filter(payment_perday_date__gte=first_day_of_month.date(),
                                                              payment_perday_date__lte=current_date.date()).aggregate(
                Sum('amount_perday'))
            return CustomResponse({'monthly_amount': sum_of_amount['amount_perday__sum']})
        return CustomResponse({'monthly_amount': sum_of_amount['amount_perday__sum']})


class IsPaidPaymentToDoctors(
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """
    Here is_paid for all the due per payment of doctors in last month is is done True as per admin request.
    """
    permission_classes = (IsAdmin,)

    def update(self, request):
        current_date = request.data.get('current_date')
        start_date, end_date = get_previous_month(current_date)
        DoctorPerDayAmount.objects.filter(payment_perday_date__gte=start_date,
                                          payment_perday_date__lte=end_date).update(is_paid=True)
        return CustomResponse({"message": "Monthly Payment done successfully"})


class CheckIsPaidMontlyRetrieve(mixins.RetrieveModelMixin,
                                viewsets.GenericViewSet, ):
    permission_classes = (IsAdmin,)
    """
    We are checking that for the last month the payment was done or not from admin to doctors.By taking out one object and 
    checking its is_paid true or false
    """

    def retrieve(self, request):
        date_request = request.query_params.get("current_date")
        start_date, end_date = get_previous_month(date_request)
        is_paid_obj = DoctorPerDayAmount.objects.filter(payment_perday_date__gte=start_date,
                                                        payment_perday_date__lte=end_date).first()
        if not is_paid_obj:
            return CustomResponse(
                {
                    "is_paid": False
                }
            )
        return CustomResponse({"is_paid": is_paid_obj.is_paid})


class ShiftManagement(mixins.ListModelMixin, mixins.CreateModelMixin, mixins.UpdateModelMixin,
                      viewsets.GenericViewSet):
    """
    Create a new shift
    """
    permission_classes = (IsAdmin,)
    serializer_class = ShiftManagementSerializer
    update_serializer_class = UpdateShiftManagementSerializer

    def create(self, request, *args, **kwargs):
        if not request.data.get('start_time') or not request.data.get('end_time') or not request.data.get('shift_name'):
            raise CustomApiException(
                status_code=400, message="Kindly give start time type and end time and shift name",
                location="create Shift time"
            )
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Shift time added successfully"})

    def update(self, request):
        if not request.data.get('shift_id'):
            raise CustomApiException(
                status_code=400, message="Kindly give shift ID",
                location="Update Shift time"
            )
        shift_obj = DynamicShiftManagement.objects.filter(id=request.data.get('shift_id')).first()
        if not shift_obj:
            raise CustomApiException(
                status_code=400, message="Invalid shift_id", location="update shift"
            )
        serializer = self.update_serializer_class(
            instance=shift_obj, data=request.data
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "shift updated successfully"})


class ListShiftManagement(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
    List the shifts
    """
    permission_classes = (AllowAny,)
    pagination_class = Pagination
    filter_backends = (DjangoFilterBackend, filters.SearchFilter,)
    search_fields = ('shift_name',)

    def list(self, request, *args, **kwargs):
        queryset = DynamicShiftManagement.objects.filter(is_deleted=False).order_by('start_time').all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=RetriveShiftManagementSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=RetriveShiftManagementSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class DeleteShiftManagement(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)

    def update(self, request):
        shift_ids = request.data.get("shift_id")
        # soft delete shift time
        DynamicShiftManagement.objects.filter(id__in=shift_ids).update(is_deleted=True)
        return CustomResponse({"message": "Shift Deleted successfully"})


class BookingUpdateMedicalHistory(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)

    def update(self, request, booking_id):
        covid_related = request.data.get('covid_related')
        Booking.objects.filter(id=booking_id).update(covid_related=covid_related)
        book_obj = Booking.objects.filter(id=booking_id).first()

        if not booking_id:
            raise CustomApiException(
                status_code=400, message="Kindly give Booking ID",
                location="Update booking med history"
            )
        """
        has_medical_history is true when specialrequest or items are present in the object
        else it will show false, this is requirement from FE
        """
        try:
            # if the booking is for family member
            med_family_obj = MedicalHistory.objects.filter(user=request.user, familymember=book_obj.familymember,
                                                           is_deleted=False).first()
            med_family_items_obj = MedicalHistoryItems.objects.filter(medicalhistory=med_family_obj.id).first()
            # if the booking is for user himself
            med_obj = MedicalHistory.objects.filter(user=request.user, familymember__isnull=True,
                                                    is_deleted=False).first()
            med_items_obj = MedicalHistoryItems.objects.filter(medicalhistory=med_obj.id).first()
            if (book_obj.booking_for == 2 and med_family_obj and (med_family_items_obj or med_family_obj.specialrequest)
            ) or (book_obj.booking_for == 1 and med_obj and (med_items_obj or med_obj.specialrequest)):
                book_obj.has_medical_history = True
                book_obj.save()
            else:
                book_obj.has_medical_history = False
                book_obj.save()
        except Exception:
            pass
        return CustomResponse({"message": "Booking med history updated successfully"})


class UpdateInsuranceVerification(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)
    serializer_class = UpdateInsuranceVerificationSerializer

    def update(self, request, insurance_id):
        insurance_obj = InsuranceVerification.objects.filter(id=insurance_id, is_deleted=False).first()
        if not insurance_obj:
            raise CustomApiException(
                status_code=400, message="Invalid insurance_id", location="update insurance verification"
            )
        serializer = UpdateInsuranceVerificationSerializer(
            instance=insurance_obj, data=request.data, partial=True, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Insurance verification updated successfully"})


class ListInsuranceVerification(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    filter_backends = (DjangoFilterBackend, filters.SearchFilter,)
    search_fields = (
        "patient__name", "patient__email", "verification_date", "insurance_state", "booking__familymember__name")

    # on going meeting will be shown in past visits
    def list(self, request, *args, **kwargs):
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        queryset = InsuranceVerification.objects.filter(insurance_state__in=(2, 3, 4, 5),
                                                        verification_date__date__gte=start_date,
                                                        verification_date__date__lte=end_date,
                                                        is_deleted=False).all().order_by("-verification_date"
                                                                                         ).select_related(
            'patient', 'booking', 'booking__familymember')
        if not queryset:
            return CustomResponse({
                "count": 0,
                "next": None,
                "previous": None,
                "results": []
            })
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=ListInsuranceVerificationSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=ListInsuranceVerificationSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class AvgHoldHandledTimeInsuranceVerify(mixins.RetrieveModelMixin,
                                        viewsets.GenericViewSet, ):
    permission_classes = (IsAdmin,)

    def retrieve(self, request):
        # new_request i.e hold on state = 2
        insurance_obj = InsuranceVerification.objects.filter(is_deleted=False).all()
        verify_obj = insurance_obj.filter(insurance_state=3).all()
        new_to_verify_obj = insurance_obj.filter(insurance_state__in=(3, 4, 5)).all()
        approvedisapprove_obj = insurance_obj.filter(insurance_state__in=(4, 5)).all()
        # counting are as -
        new_count = insurance_obj.filter(insurance_state=2).count()
        verify_count = verify_obj.count()
        new_to_verify_count = insurance_obj.filter().exclude(hold_time="00:00:00").count()
        verify_approvedisapp_count = insurance_obj.filter().exclude(handled_time="00:00:00").count()
        approve_count = insurance_obj.filter(insurance_state=4).count()
        disapprove_count = insurance_obj.filter(insurance_state=5).count()
        # try block is put because if the count is 0 then error occurs
        try:
            new_to_verify_avg = (sum(new_to_verify_obj.values_list('hold_time', flat=True),
                                     timedelta())) / new_to_verify_count
        except Exception:
            new_to_verify_avg = "0.0"
        try:
            verify_approvedisapp_avg = (sum(approvedisapprove_obj.values_list(F('handled_time') - F('hold_time'),
                                                                              flat=True),
                                            timedelta())) / verify_approvedisapp_count
        except Exception:
            verify_approvedisapp_avg = "0.0"
        return CustomResponse({"new_reqest": new_count,
                               "verifying": verify_count,
                               "approved": approve_count,
                               "disapproved": disapprove_count,
                               "hold_time_average": new_to_verify_avg,
                               "handled_time_average": verify_approvedisapp_avg,
                               })


class ListDoctorAccountVerification(mixins.ListModelMixin, viewsets.GenericViewSet):
    # this is the get API for list of doctors for pending approval(notification sent to admin)
    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('name', 'phone_number', 'email', 'status_doctor',)

    def list(self, request, *args, **kwargs):
        queryset = User.objects.filter(user_role=4, status_doctor__in=(1, 2)).order_by("-updated_at").all()
        if not queryset:
            raise CustomApiException(
                status_code=400, message="Empty queryset !!", location="list doctor verification"
            )
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=ListDoctorAccountVerificationSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=ListDoctorAccountVerificationSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class DeleteDoctorAccountVerification(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)

    # for the delete option provided on admin panel for the notification sent to him for new ,update ,approve,disappr req
    # list doctors on admin panel
    def update(self, request):
        user_ids = request.data.get("user_ids")
        if not user_ids:
            raise CustomApiException(
                status_code=400, message="Empty queryset!!!", location="delete doctor verification"
            )
        User.objects.filter(id__in=user_ids).update(status_doctor=4)  # soft deleting objects
        return CustomResponse({"message": "The requests are deleted successfully"})


class DeleteInsuranceAdminVerification(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)

    # for the delete option provided on admin panel for the notification sent to him for insurance verification
    def update(self, request):
        insurance_ids = request.data.get("insurance_ids")
        if not insurance_ids:
            raise CustomApiException(
                status_code=400, message="Empty queryset.", location="delete insurance verification"
            )
        InsuranceVerification.objects.filter(id__in=insurance_ids).update(insurance_state=6, is_deleted=True)
        return CustomResponse({"message": "The requests are deleted successfully"})


def get_current_month(date_time_str):  # i/p is as 2017-10-10
    now = datetime.strptime(date_time_str, date_string)
    day_of_month = calendar.monthrange(now.year, now.month)[1]
    start_date = datetime(now.year, now.month, 1, 00, 00, 00)
    end_date = datetime(now.year, now.month, day_of_month, 00, 00, 00)
    return start_date, end_date


class DoctorAppPerDayPaymentList(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination
    serializer_class = DoctorPerDayPaymentListSerializer

    def list(self, request, *args, **kwargs):
        # date is taken if if previous month data is required
        date = request.query_params.get('date')
        # if current date is given then till today's date the payment will be reflected
        date_format = datetime.strptime(date, date_string)
        current_date = request.query_params.get('current_date')
        current_date_format = datetime.strptime(current_date, date_string)
        if date_format > current_date_format:
            return CustomResponse([])
        user_id = request.user.id
        # thid is done to get the start and end date of the month
        start_date, end_date = get_current_month(date)
        current_start_date, current_end_date = get_current_month(current_date)
        if current_date_format.month != start_date.month:
            try:
                queryset = DoctorPerDayAmount.objects.filter(user__id=user_id, payment_perday_date__gte=start_date,
                                                             payment_perday_date__lte=end_date).values(
                    'payment_perday_date'
                ).order_by(
                    'payment_perday_date').annotate(amount_perday=Sum(
                    'amount_perday')).all()
            except Exception:
                queryset = ''
        else:
            try:
                queryset = DoctorPerDayAmount.objects.filter(user__id=user_id,
                                                             payment_perday_date__gte=current_start_date,
                                                             payment_perday_date__lte=current_date_format - timedelta(
                                                                 hours=24)).values('payment_perday_date').order_by(
                    'payment_perday_date').annotate(amount_perday=Sum(
                    'amount_perday')).all()
            except Exception:
                queryset = ''
        if not queryset:
            # requirement from FE for this response
            return CustomResponse([])
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=DoctorPerDayPaymentListSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=DoctorPerDayPaymentListSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class DoctorAvailablability(
    mixins.CreateModelMixin,
    viewsets.GenericViewSet,
):
    """
        Doctors is available or not.
        """
    permission_classes = (IsAuthenticated,)
    serializer_class = DocDailyAvailabiltySerializer

    def create(self, request, *args, **kwargs):
        if not request.data.get('date'):
            raise CustomApiException(
                status_code=400, message="Kindly give date and availability status",
                location="create doctor availability"
            )
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Doctor Availability added successfully"})


class ListTempTableWorkInfo(mixins.ListModelMixin, viewsets.GenericViewSet):
    # this is the get API for list of doctors temporary table for pending approval(notification sent to admin)
    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('medical_practice_id', 'speciality', 'experience', 'user',)

    def list(self, request, *args, **kwargs):
        queryset = TempDoctorWorkInfo.objects.filter().select_related('dynamicshift').all()
        if not queryset:
            raise CustomApiException(
                status_code=400, message="Empty queryset!!", location="list doctor temp"
            )
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=ListTempTableWorkInfoSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=ListTempTableWorkInfoSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class GetInsuranceVerificationCount(
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    permission_classes = (IsAdmin,)

    def retrieve(self, request):
        """To retrieve new request count"""
        new_request_count = InsuranceVerification.objects.filter(insurance_state=2).all().count()
        if not new_request_count:
            return CustomResponse(
                {
                    "new_request_count": 0
                })
        else:
            return CustomResponse({"new_request_count": new_request_count})


class DeleteDoctorAssignDaily(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)

    def update(self, request):
        doctor_assign_ids = request.data.get("doctor_assign_ids")
        # soft delete shift time
        doctor_assign_obj = DoctorAssignDaily.objects.filter(id__in=doctor_assign_ids)
        for assign_obj in doctor_assign_obj:
            try:
                DoctorPerDayAmount.objects.filter(payment_perday_date=assign_obj.date,
                                                  user_id=assign_obj.doctor_id, is_paid=False).first().delete()
            except Exception:
                pass
        doctor_assign_obj.delete()
        return CustomResponse({"message": "Doctor Assigned to shift Deleted successfully , "
                                          "kindly remove the booking if exists for this doctor in this shift "})


class BookingRatingUpdate(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)

    def update(self, request, booking_id):
        doc_rating_id = request.data.get("doc_rating_id")
        if not doc_rating_id:
            raise CustomApiException(
                status_code=400, message="Kindly give id", location="booking rating update"
            )
        try:
            Booking.objects.filter(id=booking_id).update(ratingdoc_id=doc_rating_id)
        except Exception:
            return CustomResponse({"message": "Rating id doesnt exist"})
        return CustomResponse({"message": "Rating in the booking saved successfully"})


class ListBookingHubWise(mixins.ListModelMixin, viewsets.GenericViewSet):
    # For Admin
    # this is the get API for list of booking in that hub, in particular visit_type on that date
    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('doctor__name', 'doctor__email', 'patient__name', 'patient__email')

    def list(self, request, *args, **kwargs):
        hub_id = request.query_params.get('hub_id')
        visit_type = request.query_params.get('visit_type')
        date = request.query_params.get('date')
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        if date:
            queryset = Booking.objects.filter(hub_id=hub_id, visit_type=visit_type, visit_start_time__date=date, state=3
                                              ).order_by('visit_start_time').select_related('doctor',
                                                                                            'doctor__profile_image',
                                                                                            'patient',
                                                                                            'patient__profile_image',
                                                                                            'van', 'room',
                                                                                            'virtualroom').all()
        if start_date and end_date:
            queryset = Booking.objects.filter(hub_id=hub_id, visit_type=visit_type,
                                              visit_start_time__date__gte=start_date, state=3,
                                              visit_end_time__date__lte=end_date).order_by(
                'visit_start_time').select_related('doctor',
                                                   'doctor__profile_image',
                                                   'patient',
                                                   'patient__profile_image',
                                                   'van', 'room',
                                                   'virtualroom').all()
        if not queryset:
            return CustomResponse([])
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=ListBookingHubWiseSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=ListBookingHubWiseSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class ListDoctorAppParticularDayBookings(mixins.ListModelMixin, viewsets.GenericViewSet):
    # this is the get API for particular day list of booking in doctor's app for that doctor.
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ()

    def list(self, request, *args, **kwargs):
        request_date = request.query_params.get('date')
        user_obj = User.objects.filter(id=request.user.id).first()
        if user_obj.user_role == User.DOCTOR:
            queryset = Booking.objects.filter(doctor=request.user, visit_start_time__date=request_date,
                                              state=4).select_related(
                'patient',
                'patient__profile_image',
                'doctor',
                'doctor__profile_image'
            ).order_by(
                'visit_start_time').all()
        else:
            queryset = Booking.objects.filter(patient=request.user, visit_start_time__date=request_date,
                                              state=3).order_by(
                'visit_start_time').select_related(
                'patient',
                'patient__profile_image',
                'doctor',
                'doctor__profile_image').all()
        if not queryset:
            return CustomResponse([])
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=ListDoctorAppParticularDayBookingsSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=ListDoctorAppParticularDayBookingsSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class BookingDoctorDateWise(mixins.ListModelMixin, viewsets.GenericViewSet):
    # Admin will see the doctors booking according to the date wise
    permission_classes = (IsAdmin,)
    pagination_class = Pagination
    serializer_class = BookingDoctorDateWiseSerializer
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ('patient__name', 'doctor__name')

    def list(self, request, *args, **kwargs):
        date = request.query_params.get('date')
        queryset = Booking.objects.filter(visit_start_time__date=date).select_related('doctor',
                                                                                      'doctor__profile_image',
                                                                                      'patient',
                                                                                      'patient__profile_image',
                                                                                      'van', 'room',
                                                                                      'virtualroom').order_by(
            'visit_start_time').all()
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=BookingDoctorDateWiseSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=BookingDoctorDateWiseSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class RetrieveInsuranceVerification(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)

    def retrieve(self, request):
        """To retrieve insurnace verification for particular booking"""
        insurance_id = request.query_params.get('insurance_id')
        booking_id = request.query_params.get('booking_id')
        ins_obj = InsuranceVerification.objects.filter(insurance_general_id=insurance_id, booking_id=booking_id).first()
        if not ins_obj:
            raise CustomApiException(
                status_code=400, message="Invalid Id's!", location="retrieve insurance verification"
            )
        return CustomResponse({"insurance_state": ins_obj.insurance_state})


class ListDoctorAvaialbility(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = ListDoctorAvaialbilitySerializer

    def list(self, request, *args, **kwargs):
        month_date = request.query_params.get('month_date')
        date = request.query_params.get('date')
        user_id = request.user.id
        try:
            start_date, end_date = get_current_month(month_date)
        except Exception:
            pass
        if date:
            queryset = DoctorDailyAvailability.objects.filter(
                doctor=user_id, date=date, is_available=False).all()
        elif month_date:
            queryset = DoctorDailyAvailability.objects.filter(
                doctor=user_id, date__gte=start_date, date__lte=end_date, is_available=False).order_by(
                'date').all()
        if not queryset:
            return CustomResponse([])
        serializer = get_serialized_data(
            obj=queryset,
            serializer=ListDoctorAvaialbilitySerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class BookingExtendTime(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)

    def update(self, request):
        booking_id = request.data.get("booking_id")
        extend_time = request.data.get("time")
        if not booking_id or not extend_time:
            raise CustomApiException(
                status_code=400, message="Please give booking id and extend time.", location="extend booking time"
            )
        booking_obj = Booking.objects.filter(id=booking_id).first()
        serializer = BookingExtendTimeSerializer(
            instance=booking_obj,
            data=request.data,
            context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "The time for visit is extended"})


class DoctorAssignDayWiseDS(mixins.CreateModelMixin,
                            mixins.UpdateModelMixin,
                            viewsets.GenericViewSet
                            ):
    # DS is for dynamic shift
    permission_classes = (IsAdmin,)
    serializer_class = DoctorAssignSerializerDS
    response_serializer_class = DoctorAssignResponseSerializer

    def create(self, request, *args, **kwargs):
        doc_assign_obj = DoctorAssignDaily.objects.filter().all()
        serializer = self.serializer_class(
            data=request.data, context={"request": request, "doc_assign_obj": doc_assign_obj}
        )
        if doc_assign_obj.filter(doctor_id=request.data.get('doctor'),
                                 dynamic_shift=request.data.get('dynamic_shift'),
                                 date=request.data.get('date')).exists():
            raise CustomApiException(
                status_code=400, message="Doctor is assigned in today's shift !!",
                location="assign doctor"
            )
        serializer.is_valid(raise_exception=True)
        obj = serializer.save()
        serializer = get_serialized_data(
            obj=obj,
            serializer=self.response_serializer_class,
            fields=request.query_params.get("fields"),
        )
        return CustomResponse(serializer.data)

    def update(self, request, doctorassigned_id):
        location_error = "Update Assigned Doctor"
        doctorassigned_obj = DoctorAssignDaily.objects.filter(id=doctorassigned_id).first()
        if not doctorassigned_obj:
            raise CustomApiException(
                status_code=400, message="Invalid Id!!", location=location_error
            )
        if DoctorAssignDaily.objects.filter(doctor_id=request.data.get('doctor'),
                                            dynamic_shift=request.data.get('dynamic_shift'),
                                            date=request.data.get('date')).exclude(id=doctorassigned_obj.id).exists():
            raise CustomApiException(
                status_code=400, message=" Doctor is assigned for today's shift !!",
                location=location_error
            )
        serializer = self.serializer_class(
            instance=doctorassigned_obj, data=request.data, partial=True, context={"request": request,
                                                                                   "doctorassigned_id": doctorassigned_id,
                                                                                   "doctorassigned_obj": doctorassigned_obj}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return CustomResponse({"message": "Assigned Doctor updated successfully"})


class BookNowLaterVisitDS(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = BookNowLaterVisitSerializerDS
    response_serializer_class = BookNowVisitlaterDSResponseSerializer

    def update(self, request, booking_id):
        booking_obj = Booking.objects.filter(id=booking_id).first()
        if not booking_obj:
            raise CustomApiException(
                status_code=400, message="Invalid booking id", location="booking update"
            )

        serializer = self.serializer_class(
            instance=booking_obj, data=request.data, partial=True, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        visit_obj = serializer.save()
        serializer = get_serialized_data(
            obj=visit_obj,
            serializer=self.response_serializer_class,
            fields=request.query_params.get("fields"),
        )
        return CustomResponse(serializer.data)


def get_time_slot_count(start_time, end_time, time_interval):
    start_hour = start_time.hour
    start_min = start_time.minute
    end_hour = end_time.hour
    end_min = end_time.minute
    time_diff = (end_hour - start_hour) * 60 + (end_min - start_min)
    time_in_minute = time_diff + 1440 if time_diff < 0 else time_diff
    total_count = time_in_minute / time_interval
    return int(total_count)


class AvailableSlotsVideoHubDS(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    # DS is the dynamic shift
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination

    def retrieve(self, request):
        visit_type = request.query_params.get("visit_type")
        start_datetime = request.query_params.get("start_datetime")
        end_datetime = request.query_params.get("end_datetime")
        if (datetime.fromisoformat(end_datetime) - datetime.fromisoformat(start_datetime) <= timedelta(minutes=30)):
            slot_avail = []
            return CustomResponse({'AvailableSlots': slot_avail})
        # here the time will round off by minutes
        start_datetime = str(roundtimeinmin(datetime.fromisoformat(start_datetime), timedelta(minutes=30)))
        hub = request.query_params.get("hub")
        if int(visit_type) != 2 and int(visit_type) != 3:
            raise CustomApiException(
                status_code=400,
                message="Visit type is wrong",
                location="get slots")
        # yaha pe doctor 5 assigned hai , booking 4 hai same time pe , toh doctor_assigned count - booking agar
        # > 0 hai , then print the slot available
        doctor_asgd_count = DoctorAssignDaily.objects.filter(hub=hub, shift_start_time__lte=start_datetime,
                                                             shift_end_time__gte=end_datetime,
                                                             visit_type=visit_type).count()
        start_time = datetime.strptime(start_datetime, date_time_string).time()
        end_time = datetime.strptime(end_datetime, date_time_string).time()
        time_diff = 30
        count = get_time_slot_count(start_time, end_time, time_diff)
        # start_datetime loop kaay wajah se distort hua hai , toh phir se getting from query params
        start_datetime = request.query_params.get("start_datetime")
        start_datetime = str(roundtimeinmin(datetime.fromisoformat(start_datetime), timedelta(minutes=30)))
        # available slots ko return karengay toh ye store kiya hai
        slot_avail = []
        for i in range(1, count + 1):
            booking_count = Booking.objects.filter(hub=hub, visit_type=visit_type, visit_start_time__lte=start_datetime,
                                                   visit_end_time__gt=start_datetime, doctor_id__isnull=False).count()
            if doctor_asgd_count - booking_count > 0:
                slot_avail.append(start_datetime)
            start_datetime = str(datetime.strptime(start_datetime, date_time_string) + timedelta(minutes=30))
        return CustomResponse({'AvailableSlots': slot_avail})


class AvailableSlotsMobDocDS(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination

    # DS is the dynamic shift
    def retrieve(self, request):
        visit_type = request.query_params.get("visit_type")
        start_datetime = request.query_params.get("start_datetime")
        end_datetime = request.query_params.get("end_datetime")
        """
        yaaha pe agar start end time 14:31:00 and 15:00:00 hai toh 15:00:00 se aagay ki timeslots aa raahay thay.
        toh to fix this this below if cond is given , ki slot available [] aa jaae
        """
        # here the time will round off by hour
        # start_datetime is equal to str(roundtimeinhour(datetime.fromisoformat(start_datetime)))

        hub = request.query_params.get("hub")
        if int(visit_type) != 1:
            raise CustomApiException(
                status_code=400,
                message="Visit type is wrong ",
                location="get slots")
        # here doctor 5 assigned hai , booking 4 hai at same time , then doctor_assigned count - booking agar
        # > 0 hai , then print the slot available
        doctor_asgd_count = DoctorAssignDaily.objects.filter(hub=hub, shift_start_time__lte=start_datetime,
                                                             shift_end_time__gte=end_datetime,
                                                             visit_type=visit_type).count()

        start_time = datetime.strptime(start_datetime, date_time_string).time()
        end_time = datetime.strptime(end_datetime, date_time_string).time()
        time_diff = 60
        count = get_time_slot_count(start_time, end_time, time_diff)
        # start_datetime loop kaay wajah se distort hua hai , toh phir se getting from query params
        start_datetime = request.query_params.get("start_datetime")
        start_datetime = str(roundtimeinhour(datetime.fromisoformat(start_datetime)))
        # available slots ko return karengay toh ye store kiya hai
        slot_avail = []
        for i in range(1, count + 1):
            booking_count = Booking.objects.filter(hub=hub, visit_type=visit_type, visit_start_time__lte=start_datetime,
                                                   visit_end_time__gt=start_datetime, doctor_id__isnull=False).count()
            if doctor_asgd_count - booking_count > 0:
                slot_avail.append(start_datetime)
            start_datetime = str(datetime.strptime(start_datetime, date_time_string) + timedelta(hours=1))
        return CustomResponse({'AvailableSlots': slot_avail})


class EditDoctorInfoDS(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)

    # DS is the dynamic shift
    def update(self, request):

        doc_obj = User.objects.filter(id=request.user.id).first()
        if not doc_obj:
            raise CustomApiException(
                status_code=400, message="Invalid doctor  id", location="update doctor"
            )
        # if the personal details are updated then it will be updated successfully
        # if email is updated then verification mail is sent to the email
        # serializers for personal details update is different and prosfessional details are differnt
        if request.data.get("personal"):
            # nested json hai toh details mey we can store the data and then update it.
            details = request.data.get("personal")
            serializer = EditDoctorPersonalInfoSerializer(
                instance=doc_obj, data=request.data, partial=True, context={"doc_obj": doc_obj, "details": details,
                                                                            "request": request}
            )
            serializer.is_valid(raise_exception=True)
            user_obj = serializer.save()
            if request.data.get("is_email_verified"):
                user_obj.is_email_verified = request.data.get("is_email_verified")
                user_obj.save()
            serializer = get_serialized_data(
                obj=user_obj,
                serializer=DocEditDoctorResponseSerializer,
                fields=request.query_params.get("fields"),
            )
            data = serializer.data
            ######################################
            # Adding temporary piece of code for email url (this will return the OTP also along with other parameter).
            email_url_obj = OTP.objects.filter(
                user=user_obj, otp_type=OTP.VERIFICATION_OTP
            ).first()
            data.update({"email_url_obj": email_url_obj.otp})
            return CustomResponse(data)
        # if the professional details are updated by the doctor then the serializers are diferent
        if request.data.get("professional"):
            details = request.data.get("professional")
            # if the professional details are updated by the doctor then the serializers are diferent

            """
            the validations are below
            """
            doctor_medical_doc = DoctorMedicalDoc.objects.filter(doctor_id=request.user.id).count()
            if details.get('tempdoctorinfo_documents'):
                tempdoctorinfo_documents = details.get('tempdoctorinfo_documents')
            try:
                if doctor_medical_doc + len(tempdoctorinfo_documents) > 3:
                    raise CustomApiException(
                        status_code=400, message="There already exists 3 documents,kindly delete and upload again.",
                        location="update med doc"
                    )
            except Exception:
                pass
            general_professional_validations(details, request)
            if not TempDoctorWorkInfo.objects.filter(user_id=doc_obj.id).exists():
                TempDoctorWorkInfo.objects.update_or_create(user_id=request.user.id)
            med_obj = TempDoctorWorkInfo.objects.filter(user_id=request.user.id).first()
            serializer = TemporaryEditDoctorInfoSerializerDS(
                instance=med_obj, data=request.data, partial=True, context={"doc_obj": doc_obj, "details": details,
                                                                            "request": request, "med_obj": med_obj}
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return CustomResponse({"message": "The professional details are sent to Admin for verification"})


class VerifyDoctorDocDS(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)

    def update(self, request, user_id):
        """method for verifying doctors work info"""
        if request.data.get("is_profile_approved") == False:
            try:
                delete_from_temp_table_obj = TempDoctorWorkInfo.objects.filter(user_id=user_id).first()
                delete_from_temp_table_obj.delete()
                raise CustomApiException(
                    status_code=400, message="Parameter not provided or not approved", location="verify_Doctor_Info"
                )
            except Exception:
                pass
        doc_obj = User.objects.filter(id=user_id).first()
        serializer = VerifyDocWorkInfoSerializerDS(
            instance=doc_obj,
            data=request.data,
            context={"request": request, "user_id": user_id}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        response = {"message": "Information verified successfully"}
        return CustomResponse(response)


class RetrieveInsuranceFromBooking(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAdmin,)

    def retrieve(self, request):
        """To retrieve insurnace details from booking id for Admin"""
        booking_id = request.query_params.get('booking_id')
        ins_obj = InsuranceVerification.objects.filter(booking_id=booking_id).first()
        if not ins_obj:
            return CustomResponse()
        insurance_details_obj = InsuranceDetails.objects.filter(id=ins_obj.insurance_general_id
                                                                ).first()
        serializer = get_serialized_data(
            obj=insurance_details_obj,
            serializer=InsuranceResponseSerializer,
            fields=request.query_params.get("fields"),
        )
        return CustomResponse(serializer.data)


class DoctorCalenderUpcomingVisits(mixins.ListModelMixin, viewsets.GenericViewSet):
    # this is the get API for particular day list of booking in doctor's app for that doctor.
    permission_classes = (IsAuthenticated,)
    pagination_class = Pagination
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    search_fields = ()

    def list(self, request, *args, **kwargs):
        request_date = request.query_params.get('date')
        user_obj = User.objects.filter(id=request.user.id).first()
        queryset = Booking.objects.filter(doctor=request.user, visit_start_time__date=request_date,
                                          state=3).select_related(
            'patient',
            'patient__profile_image',
            'doctor',
            'doctor__profile_image'
        ).order_by(
            'visit_start_time').all()
        if not queryset:
            return CustomResponse([])
        pagination_class = self.pagination_class()
        page = pagination_class.paginate_queryset(self.filter_queryset(queryset), request)
        if page is not None:
            serializer = get_serialized_data(
                obj=page,
                serializer=ListDoctorAppParticularDayBookingsSerializer,
                fields=request.query_params.get("fields"),
                many=True, )
            return CustomResponse(
                pagination_class.get_paginated_response(serializer.data).data
            )
        serializer = get_serialized_data(
            obj=self.filter_queryset(queryset),
            serializer=ListDoctorAppParticularDayBookingsSerializer,
            fields=request.query_params.get("fields"),
            many=True,
        )
        return CustomResponse(serializer.data)


class TempDocToDoctorVisit(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)
    response_serializer_class = BookNowVisitlaterDSResponseSerializer

    def update(self, request, booking_id):
        obj = Booking.objects.filter(id=booking_id)
        booking_obj = obj.first()
        if not booking_obj:
            raise CustomApiException(
                status_code=400, message="Invalid booking id", location="booking update"
            )
        temp_doctor_id = booking_obj.temp_doctor_id
        obj.update(doctor_id=temp_doctor_id)
        serializer_obj = Booking.objects.filter(id=booking_id).first()
        serializer = get_serialized_data(
            obj=serializer_obj,
            serializer=self.response_serializer_class,
            fields=request.query_params.get("fields"),
        )
        return CustomResponse(serializer.data)
