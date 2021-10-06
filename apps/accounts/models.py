"""packages"""
from datetime import timedelta

from django.contrib.auth.models import AbstractUser
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.contrib.gis.db import models
from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.fields import JSONField
from multiselectfield import MultiSelectField

from apps.images.models import AllImage


class BaseModel(models.Model):
    """
    Core models to save the common properties such as:
        created_at,
        updated_at,
        last_modified_by
    """

    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created At")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Last Updated At")

    class Meta:
        """Meta class"""

        abstract = True
        verbose_name = "BaseModel"


class State(models.Model):
    """
    This model is used to store default states
    """

    state_name = models.CharField("state_name", max_length=50, null=True, blank=True)


class City(models.Model):
    """
    This model is used to store default cities
    """

    city_name = models.CharField("city_name", max_length=200, null=True, blank=True)
    state_id = models.ForeignKey(State, on_delete=models.CASCADE, related_name="state")


class RolesManagementManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)


class RolesManagement(BaseModel):
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
    modules_access = MultiSelectField("Modules assignment", choices=MODULES, null=True, blank=True)
    # this is the role(ex-HR) under which the admin will create the subadmins(hr1,hr2,hr3)
    user_role = models.CharField("User role", max_length=30, blank=True, null=True)
    is_deleted = models.BooleanField("is deleted", default=False)
    objects = RolesManagementManager()


class DynamicShiftManagement(BaseModel):
    """
    In this  the  shift time is stored
    """
    shift_name = models.CharField("shift_name", max_length=20, null=True, blank=True)
    start_time = models.TimeField(auto_now=False, auto_now_add=False, null=True, blank=True)
    end_time = models.TimeField(auto_now=False, auto_now_add=False, null=True, blank=True)
    is_deleted = models.BooleanField("is_deleted", default=False)


class User(AbstractUser, BaseModel):
    """
    User model used for the authentication process and it contains basic fields.
        Inherit : AbstractUser, CoreModels
    """
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

    MORNING = 1
    AFTERNOON = 2
    EVENING = 3

    SHIFT_TYPES = (
        (MORNING, "Morning"),
        (AFTERNOON, "Afternoon"),
        (EVENING, "Evening"),
    )

    PHYSICIAN = 1
    PA = 2
    NP = 3

    DESIGNATION_TYPE = (
        (PHYSICIAN, "Physician"),
        (PA, "PA"),
        (NP, "NP")
    )

    user_role = models.IntegerField("User role", choices=ROLE, default=PATIENT)

    # personal details
    email = models.EmailField("Email", max_length=70, unique=True, blank=False)
    first_name = models.CharField("First Name", max_length=50, blank=True, null=True)
    last_name = models.CharField("Last Name", max_length=50, blank=True, null=True)
    name = models.CharField("Full Name", max_length=120, blank=True, null=True)
    username = models.CharField("User Name", max_length=50, blank=True)
    phone_number = models.CharField(
        "PhoneNumber", max_length=25, unique=True, blank=True, null=True
    )
    dob = models.DateField(null=True, blank=True)
    profile_image = models.OneToOneField(
        AllImage, on_delete=models.SET_NULL, null=True, blank=True
    )

    # address details
    address = models.CharField("User address", max_length=600, null=True, blank=True)
    lat = models.DecimalField(max_digits=200, decimal_places=50, default=0.0)
    lng = models.DecimalField(max_digits=200, decimal_places=50, default=0.0)
    cordinate = models.PointField("User Cordinate", blank=True, null=True)
    city = models.CharField("city", max_length=100, null=True, blank=True)
    state = models.CharField("state", max_length=100, null=True, blank=True)
    zip_code = models.IntegerField("Zip Code", null=True, blank=True)

    # additional doctor details
    designation = models.IntegerField("Designation", choices=DESIGNATION_TYPE, default=PHYSICIAN)
    medical_practice_id = models.CharField(
        "Medical practice id", max_length=100, null=True, blank=True
    )
    speciality = models.CharField("speciality", max_length=100, null=True, blank=True)
    experience = models.FloatField("Experience", null=True, blank=True, default=0)
    shift = models.IntegerField("Shift", choices=SHIFT_TYPES, default=MORNING)
    is_profile_approved = models.BooleanField("Profile Verification", default=False)
    is_email_verified = models.BooleanField("Email Verified", default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField("Active", default=True)
    is_superuser = models.BooleanField("SuperUser", default=False)

    # Adding admin medical practice id array field
    admin_medical_practice_id = ArrayField(models.CharField(max_length=200), blank=True, null=True)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ("username",)
    # adding fields for rolestaff management
    role_management = models.ForeignKey(RolesManagement, blank=True, null=True, on_delete=models.CASCADE,
                                        related_name="role_man_user")
    is_deleted = models.BooleanField(default=False)
    # Stripe records
    stripe_customer_id = models.CharField("customer id", max_length=30, null=True, blank=True)
    is_stripe_customer = models.BooleanField("StripeCustomer", default=False)
    has_bank_account = models.BooleanField("Has bank account", default=False)
    # to show the list of doctor verification from admin side,ex- new request or update request is there
    NEW_DOCTOR = 1
    UPDATE_DOCTOR = 2
    APPROVE_DOCTOR = 3
    DISAPPROVE_DOCTOR = 4
    choices_doctor = (
        (NEW_DOCTOR, 'new'), (UPDATE_DOCTOR, 'update'), (APPROVE_DOCTOR, 'approve'), (DISAPPROVE_DOCTOR, 'disapprove'))
    status_doctor = models.IntegerField("state", choices=choices_doctor, default=NEW_DOCTOR)
    dynamicshift = models.ForeignKey(DynamicShiftManagement, on_delete=models.CASCADE, blank=True, null=True,
                                     related_name="shift_user")

    def __str__(self):
        """
        :return: email
        """
        return self.email

    class Meta:
        """Meta class for users and order them by id"""

        verbose_name = "Users"
        ordering = ["id"]


class OTP(BaseModel):
    """Model to save OTP sent to user"""

    VERIFICATION_OTP = 1
    FORGOT_PASSWORD_OTP = 2
    UPDATE_PROFILE = 3
    DOC_VERIFICATION = 4
    LOGIN_OTP = 5
    TYPES = (
        (VERIFICATION_OTP, "Email Verification"),
        (FORGOT_PASSWORD_OTP, "Forgot Password"),
        (UPDATE_PROFILE, "Update Profile"),
        (DOC_VERIFICATION, "Doc Verification"),
        (LOGIN_OTP, "Login Otp")
    )
    user = models.ForeignKey(
        User, blank=False, on_delete=models.CASCADE, related_name="otp_value"
    )
    otp = models.CharField(max_length=100, null=True, blank=True)
    otp_type = models.IntegerField(
        "OTP type", choices=TYPES, default=VERIFICATION_OTP
    )
    is_used = models.BooleanField(default=False)


class Hub(BaseModel):
    """
        Hub Model to map the hospitals/hubs in our app
    """
    hub_name = models.CharField('Hub Name', max_length=70, blank=False)
    lat = models.DecimalField(max_digits=15, decimal_places=10, default=0.0)
    lng = models.DecimalField(max_digits=15, decimal_places=10, default=0.0)
    cordinate = models.PointField('Cordinate', blank=True, null=True)
    address = models.TextField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False)
    amount = models.DecimalField(max_digits=15, decimal_places=10, null=True, blank=True)


class HubDocsManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)


class HubDocs(BaseModel):
    """Model to store hub documents"""

    hub = models.ForeignKey(Hub, on_delete=models.CASCADE, related_name="hub_documents")
    document = models.OneToOneField(
        AllImage, on_delete=models.CASCADE, null=True, blank=True
    )
    is_deleted = models.BooleanField(default=False)
    objects = HubDocsManager()


class Room(BaseModel):
    """
        Room Model to map the rooms of a hub in our app
    """
    hub = models.ForeignKey(Hub, on_delete=models.CASCADE, related_name="hub_rooms")
    room_number = models.IntegerField('Room Number', null=True, blank=True)
    status = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)


class Van(BaseModel):
    """
        Van Model to map the vans of a hub in our app
    """
    LEVEL1 = 1
    LEVEL2 = 2

    VAN_LEVEL_CHOICES = (
        (LEVEL1, "Level1"),
        (LEVEL2, "Level2")
    )
    hub = models.ForeignKey(Hub, on_delete=models.CASCADE, related_name="hub_vans")
    van_number = models.CharField('Van Number', max_length=70, null=True, blank=True)
    level_type = models.IntegerField(
        "Van level type", choices=VAN_LEVEL_CHOICES, default=LEVEL1
    )
    status = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)


class FamilyMember(BaseModel):
    """add family member model"""
    user = models.ForeignKey(User, blank=False, on_delete=models.CASCADE, related_name="user_family_member")
    name = models.CharField("Name", max_length=120, blank=False)
    dob = models.DateField(null=True, blank=True)
    relation = models.CharField("Relation", max_length=120, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)


class InsuranceDetails(BaseModel):
    """add insurance details"""
    user = models.ForeignKey(User, blank=False, on_delete=models.CASCADE, related_name="user_insurance")
    name = models.CharField("Name", max_length=120, blank=False)
    groupid = models.CharField("Group Id", max_length=50, blank=False)
    policyid = models.CharField("Policy Id", max_length=50, blank=False)
    profile_image = models.ManyToManyField(AllImage, blank=True)
    securitynumber = models.BigIntegerField("Social Security Number", blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    familymember = models.ForeignKey(FamilyMember, blank=True, null=True, on_delete=models.CASCADE,
                                     related_name="insurance_familymember")


class EmergencyContacts(BaseModel):
    """ add emergency contacts"""
    user = models.ForeignKey(User, blank=False, on_delete=models.CASCADE, related_name="user_emergency_contacts")
    name = models.CharField("Name", max_length=120, blank=False)
    phone_number = models.CharField("Phone_Number", max_length=25, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)


class Ticket(BaseModel):
    """
        Ticket Model to create the ticket 
    """
    ROOMNOTAVAILABLE = 1
    VANNOTAVAILABLE = 2
    CHANGETIME = 3
    CHANGEDATE = 4
    OTHERS = 5

    TICKET_REGARD_CHOICES = (
        (ROOMNOTAVAILABLE, "room not available"),
        (VANNOTAVAILABLE, "van not available"),
        (CHANGETIME, "change time"),
        (CHANGEDATE, "change date"),
        (OTHERS, "others"),
    )

    user = models.ForeignKey(User, blank=False, on_delete=models.CASCADE, related_name="tickets")
    tick_name = models.TextField(max_length=200)
    email_add = models.EmailField("Email Address", max_length=70, unique=False, blank=False)
    ticket_regard_type = models.IntegerField(
        "Ticet Regard type", choices=TICKET_REGARD_CHOICES, default=ROOMNOTAVAILABLE
    )
    add_note = models.TextField(max_length=200)
    is_resolved = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    new_text = models.CharField(max_length=255, blank=True)


class VirtualRoom(BaseModel):
    """
        virtual Room Model to map the virtualrooms of a hub in our app
    """
    hub = models.ForeignKey(Hub, on_delete=models.CASCADE, related_name="hub_virtualrooms")
    room_number = models.CharField('Room Number', max_length=70, unique=False, null=True, blank=True)
    status = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)


class MedicalHistoryManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)


class MedicalHistoryItems(models.Model):
    """
    This model is used to store items of medical history
    """
    medicalhistory_name = models.CharField("medicalhistory_name", max_length=50, null=True, blank=True)


class MedicalHistory(BaseModel):
    """ add medical history"""
    familymember = models.ForeignKey(FamilyMember, blank=True, null=True, on_delete=models.CASCADE,
                                     related_name="family_member_medical_history")
    user = models.ForeignKey(User, blank=False, on_delete=models.CASCADE, related_name="user_medical_history")
    specialrequest = models.CharField("Special Request", max_length=120, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    items = models.ManyToManyField(MedicalHistoryItems, blank=True)
    objects = MedicalHistoryManager()


class RatingDocAndApp(BaseModel):
    MOBILE_DOCTOR = 1
    VIDEO_CONSULT = 2
    HUB_VISIT = 3
    SUGGESTIONS = 4
    OVERALL = 5
    REVIEW_CHOICES = (
        (MOBILE_DOCTOR, "mobile_doctor"),
        (VIDEO_CONSULT, "video_consult"),
        (HUB_VISIT, "hub_visit"),
        (SUGGESTIONS, "suggestions"),
        (OVERALL, "Overall"),
    )
    RATING_DOC = 1
    RATING_APP = 2
    RATING_DOC_OR_APPS = (
        (RATING_DOC, "rating_doc"),
        (RATING_APP, "rating_app")
    )
    patient = models.ForeignKey(User, blank=True, null=True, on_delete=models.CASCADE, related_name="user_patient")
    doctor = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_doctor", blank=True, null=True)
    review = models.IntegerField("Review", blank=True, null=True, choices=REVIEW_CHOICES, default=OVERALL)
    rating = models.DecimalField(max_digits=5, decimal_places=1, null=True)
    comment_box = models.CharField("Comment", max_length=400, blank=True, null=True)
    rating_doc_or_app = models.IntegerField("rating_doc_or_app", null=False, choices=RATING_DOC_OR_APPS,
                                            default=RATING_DOC)
    is_completed = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)


class ContentManagement(BaseModel):
    user = models.ForeignKey(User, blank=False, on_delete=models.CASCADE, related_name="user_content_management")
    cm_email = models.EmailField("Email", max_length=70)
    cm_phone_number = models.CharField("Phone Number", max_length=19, blank=True, null=True)
    cm_terms_condition_pdf = models.OneToOneField(AllImage, on_delete=models.SET_NULL, null=True,
                                                  related_name="cm_terms_condition_pdf")
    cm_legal_terms_pdf = models.OneToOneField(AllImage, on_delete=models.SET_NULL, null=True,
                                              related_name="cm_legal_terms_pdf")
    is_deleted_terms_condition_pdf = models.BooleanField(default=False)
    is_deleted_legal_terms_pdf = models.BooleanField(default=False)


class Booking(BaseModel):
    # foreign keys are below
    patient = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True, related_name="booking_patient")
    doctor = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True, related_name="booking_doctor")
    temp_doctor = models.ForeignKey(User, on_delete=models.CASCADE, blank=True,
                                    null=True, related_name="booking_temp_doctor")
    hub = models.ForeignKey(Hub, on_delete=models.CASCADE, blank=True, null=True, related_name="booking_hub")
    familymember = models.ForeignKey(FamilyMember, blank=True, null=True, on_delete=models.CASCADE,
                                     related_name="booking_familymember")
    room = models.ForeignKey(Room, blank=True, null=True, on_delete=models.CASCADE, related_name="booking_room")
    van = models.ForeignKey(Van, blank=True, null=True, on_delete=models.CASCADE, related_name="booking_van")
    virtualroom = models.ForeignKey(VirtualRoom, blank=True, null=True, on_delete=models.CASCADE,
                                    related_name="booking_virtualroom")
    ratingdoc = models.ForeignKey(RatingDocAndApp, blank=True, null=True, on_delete=models.CASCADE,
                                  related_name="booking_ratingdoc")
    medicalhistory = models.ForeignKey(MedicalHistory, on_delete=models.CASCADE, blank=True, null=True,
                                       related_name="booking_medicalhistory")

    # choices are described below
    PATIENTSELF = 1
    FAMILYMEMBERS = 2
    BOOKINGS_FOR = (
        (PATIENTSELF, "patient"),
        (FAMILYMEMBERS, "familymember")
    )
    MOBILE_DOCTOR = 1
    VIDEO_CONFERENCING = 2
    HUB_VISIT = 3
    VISIT_TYPES = (
        (MOBILE_DOCTOR, "mobile_doc"),
        (VIDEO_CONFERENCING, "video_confer"),
        (HUB_VISIT, "hub_visit")
    )
    VISIT_NOW = 1
    VISIT_LATER = 2
    VISIT_TIME = (
        (VISIT_NOW, "visit_now"),
        (VISIT_LATER, "visit_later")
    )
    NEW = 1
    CANCEL = 2
    BOOKING_CREATED = 3  # when booking is created completly and paid, but amount is not deducted
    # (this is used for passing the start time of the patient)
    COMPLETED = 4  # when meeting or visit is completed and doctor marks this flag to confirm payment
    PAID = 5  # extra flag for doctor has received money or not
    STATES = (
        (NEW, "new"), (BOOKING_CREATED, "booking_created"), (CANCEL, "cancel"), (COMPLETED, "completed"), (PAID, "paid")
    )
    state = models.IntegerField("State", choices=STATES, default=NEW)
    booking_for = models.IntegerField("BookingFor", choices=BOOKINGS_FOR, null=True, blank=True)
    visit_type = models.IntegerField("Visit Type", choices=VISIT_TYPES, null=True, blank=True)
    visit_now_later = models.IntegerField("Visit Time", choices=VISIT_TIME, null=True, blank=True)
    # source address details
    source_address = models.CharField("Source Address", max_length=600, null=True, blank=True)
    source_cordinate = models.PointField("Source Cordinate", blank=True, null=True)
    # destination address details
    destination_address = models.CharField("Destination Address", max_length=600, null=True, blank=True)
    destination_cordinate = models.PointField("Destination Cordinate", blank=True, null=True)

    visit_start_time = models.DateTimeField(null=True, blank=True)
    visit_end_time = models.DateTimeField(null=True, blank=True)
    # has_medical_history is true when specialrequest or items are present in the object
    # else it will show false, this is requirement from FE
    has_medical_history = models.BooleanField("Has Medical History", default=False)
    total_distance = models.DecimalField(max_digits=200, decimal_places=50, default=0.0)
    total_amount = models.DecimalField(max_digits=20, decimal_places=10, default=0.0)
    # after insurance discount amount payable would be
    co_pay = models.FloatField("co pay", null=True, blank=True)
    medical_disclosure = JSONField(null=True, blank=True)
    meet_link = models.URLField(max_length=200, null=True, blank=True)
    # this is in percentage, this is the %of the amount to be deducted if the insurance is approved
    amnt_percent_deduct = models.DecimalField(max_digits=10, decimal_places=7, null=True, blank=True)
    booking_cancel_charge = models.DecimalField(max_digits=30, decimal_places=10, null=True, blank=True)
    card_id = models.CharField("card id", max_length=30, null=True, blank=True)
    payment_intent_id = models.CharField("card id", max_length=100, null=True, blank=True)
    # this is the reason for extending time of visit/booking
    reason = models.TextField(null=True, blank=True)
    covid_related = models.BooleanField("Covid related info", default=False)


class DoctorMedicalDocManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)


class DoctorMedicalDoc(BaseModel):
    doctor = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True,
                               related_name="user_doctormedicaldoc")
    document = models.OneToOneField(
        AllImage, on_delete=models.CASCADE, null=True, blank=True
    )
    is_deleted = models.BooleanField(default=False)
    objects = DoctorMedicalDocManager()


class DeviceManagement(BaseModel):
    """
        Model to map all the devices doctor logged in.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True, related_name='user_device')
    device_uuid = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    fcm_token = models.CharField(max_length=500, null=True, blank=True)


class TempDoctorWorkInfo(BaseModel):
    """
    This is the temporary table where in notification(when doc updates its professional details for admin to approve)
    will direct to the page showing the data updated by the doctor in the temp table(when doctor approves the details 
    then the temporary data from this tables will be deleted and data will be updated to new User and DoctorMedicalDoc 
    table.)  
    """
    MORNING = 1
    AFTERNOON = 2
    EVENING = 3
    SHIFT_TYPES = (
        (MORNING, "Morning"),
        (AFTERNOON, "Afternoon"),
        (EVENING, "Evening"),
    )
    PHYSICIAN = 1
    PA = 2
    NP = 3
    DESIGNATION_TYPE = (
        (PHYSICIAN, "Physician"),
        (PA, "PA"),
        (NP, "NP")
    )
    designation = models.IntegerField("Designation", choices=DESIGNATION_TYPE, null=True, blank=True)
    medical_practice_id = models.CharField("Medical practice id", max_length=100, null=True, blank=True)
    speciality = models.CharField("speciality", max_length=100, null=True, blank=True)
    experience = models.FloatField("Experience", null=True, blank=True)
    shift = models.IntegerField("Shift", choices=SHIFT_TYPES, null=True, blank=True)
    is_profile_approved = models.BooleanField("Profile Verification", default=False, null=True, blank=True)
    user = models.ForeignKey(User, blank=False, on_delete=models.CASCADE, related_name="user_tempdoctorworkinfo")
    dynamicshift = models.ForeignKey(DynamicShiftManagement, on_delete=models.CASCADE, blank=True, null=True,
                                     related_name="shift_tempdoctorworkinfo")


class TempDoctorMedicalDoc(BaseModel):
    """
    These are the medical doc updated by the doc and set  to the admin  for approval via notification
    when admin approves then ,from here it will be deleted and save to DoctorMedicalDoc table,
    if not approved then it will only be deleted from this model (no update to the DoctorMedicalDoc table)
    """
    tempdoctorinfo = models.ForeignKey(TempDoctorWorkInfo, on_delete=models.CASCADE,
                                       related_name="tempdoctorinfo_documents")
    document = models.OneToOneField(
        AllImage, on_delete=models.CASCADE, null=True, blank=True
    )
    is_deleted = models.BooleanField(default=False)


class UserActivity(BaseModel):
    """Model to store request send from one user to another"""
    """This is the notification table made for storing the notifications sent to the users from users"""
    # admin is sent notification is activity type 1
    ADMIN_SEND_YOU_A_NOTIFICATION = 1
    ADMIN_SEND_YOU_A_NOTI_INSURANCE = 2
    ADMIN_SEND_YOU_A_NOTI_BOOKING_UPDATE = 3
    ACTIVITY_TYPES = (
        (ADMIN_SEND_YOU_A_NOTIFICATION, "Admin sent you a notification"),
        (ADMIN_SEND_YOU_A_NOTI_INSURANCE, "Sent Admin noyi for insurance"),
    )
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notification_sender")
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notification_receiver")
    activity_type = models.IntegerField("Activity Type", choices=ACTIVITY_TYPES)
    title = models.CharField("title", max_length=100, null=True, blank=True)
    message = models.CharField("message", max_length=100, null=True, blank=True)
    payload = models.CharField("payload", max_length=600, null=True, blank=True)
    is_read = models.BooleanField("isread", default=False)


class SymptomsItems(models.Model):
    """
    This model is used to store items of symptoms
    """
    category = models.CharField("Category", max_length=50, null=True, blank=True)
    subcategory = models.CharField("SubCategory", max_length=50, null=True, blank=True)


class Symptoms(BaseModel):
    """
    every booking will have new symptoms .
    """
    booking_id = models.ForeignKey(Booking, on_delete=models.CASCADE, null=True, blank=True,
                                   related_name="symptoms_booking")
    items = models.ManyToManyField(SymptomsItems, blank=True)
    additional_info = models.CharField("additinal info", max_length=500, null=True, blank=True)


class DoctorAssignDaily(BaseModel):
    """
    the doctor will be assigned everyday with a van, virtualroom, or room according to the shift of doctor
    Here the GenericForeignKey and contenttype is used as in fk there can be van or virtualroom or room
    which can be assigned to the doctor.
    There is only one fk i.e visit_space that will be assigned any one of the fk's among van_id,vr_id or room_id
    """
    MOBILE_DOCTOR = 1
    VIDEO_CONFERENCING = 2
    HUB_VISIT = 3
    VISIT_TYPES = (
        (MOBILE_DOCTOR, "Mobile Doctor"),
        (VIDEO_CONFERENCING, "Video Conferencing"),
        (HUB_VISIT, "Hub Visit"),
    )
    MORNING = 1
    AFTERNOON = 2
    EVENING = 3
    SHIFT_TYPES = (
        (MORNING, "Morning"),
        (AFTERNOON, "Afternoon"),
        (EVENING, "Evening"),
    )
    visit_type = models.IntegerField("Visit Type", choices=VISIT_TYPES, null=True, blank=True)
    shift = models.IntegerField("Shift", choices=SHIFT_TYPES, null=True, blank=True)
    date = models.DateField(null=True, blank=True)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    visit_space = GenericForeignKey('content_type', 'object_id')
    doctor = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE, related_name="user_doctorassign")
    hub = models.ForeignKey(Hub, on_delete=models.CASCADE, blank=True, null=True, related_name="doctorassigndaily_hub")
    shift_start_time = models.DateTimeField(null=True, blank=True)
    shift_end_time = models.DateTimeField(null=True, blank=True)
    workinghours = models.TimeField(auto_now=False, auto_now_add=False, null=True, blank=True)
    dynamic_shift = models.ForeignKey(DynamicShiftManagement, on_delete=models.CASCADE, blank=True, null=True,
                                      related_name="shift_doctorassign")


class Designation_Amount(BaseModel):
    PHYSICIAN = 1
    PA = 2
    NP = 3

    DESIGNATION = (
        (PHYSICIAN, "Physician"),
        (PA, "PA"),
        (NP, "NP")
    )
    designation_type = models.IntegerField("Designation", choices=DESIGNATION, default=PHYSICIAN)
    designation_amount = models.FloatField("designation_amount", null=True, blank=True, default=0)


class DoctorPerDayAmount(BaseModel):
    """
    In DoctorAssignDaily the doctor's per day shift amount is stored . if multiple shift , then also it is stored
    """
    user = models.ForeignKey(User, blank=False, on_delete=models.CASCADE, related_name="user_payment_admin")
    payment_perday_date = models.DateField(null=True, blank=True)
    workinghours = models.TimeField(auto_now=False, auto_now_add=False, null=True, blank=True)
    designation_amount = models.ForeignKey(Designation_Amount, blank=False, on_delete=models.CASCADE,
                                           related_name="designation_amount_admin")
    amount_perday = models.FloatField("Amount perday", null=True, blank=True, default=0)
    is_paid = models.BooleanField("ispaid", default=False)


class DoctorDailyAvailability(BaseModel):
    """
    In this model where doctor when not available(for particular day) then the entry will be done here.
    """
    doctor = models.ForeignKey(User, blank=False, on_delete=models.CASCADE, related_name="doctor_availability")
    date = models.DateField(null=True, blank=True)
    is_available = models.BooleanField("isavailable", default=True)


class InsuranceVerification(BaseModel):
    """
    this is because the admin has to get the list of insurance for which he can approve/disapprove the insurance
    insuranceverify noti to admin --> (listinsuranceverification)listing the insurances -->
    (insuranceverification) state 2 to 3 --> retrive insurance and check --> (insuranceverification) state 3 to 4/5
    """
    insurance_general = models.ForeignKey(InsuranceDetails, blank=False, on_delete=models.CASCADE,
                                          related_name="verification_insurancedetails")
    patient = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True, related_name="insurance_patient")
    booking = models.ForeignKey(Booking, blank=False, on_delete=models.CASCADE,
                                related_name="Insurance_booking")
    # this is used or the admin verification of insurance at the time of booking
    CREATE_INSURANCE = 1
    NEW_REQUEST = 2
    VERIFYING = 3
    APPROVE = 4
    DISAPPROVE = 5
    # hide status is for the get list of insurance in which the admin deletes the insurance, if state=6 is done in delete
    # then average timings will be calculated, if is_deleted is also done then avg timing will also be calculated
    # removing the entries i.e row(depends on client whatever she wants)
    HIDE = 6
    STATES = (
        (CREATE_INSURANCE, "create insurance"), (NEW_REQUEST, "new"), (VERIFYING, "verifying"), (APPROVE, "approve"),
        (DISAPPROVE, "disapprove"), (HIDE, "hide")
    )
    insurance_state = models.IntegerField("Insurance State", choices=STATES, default=CREATE_INSURANCE)
    # this is the timing  when the notification is sent to the admin
    verification_date = models.DateTimeField(null=True, blank=True)
    # time from state=2 to state=3
    hold_time = models.DurationField(default=timedelta())
    # time from state=2 to state=4/5 as per db.(however handled time means from state=3 to 4/5 which
    # is calculated in views.py)
    handled_time = models.DurationField(default=timedelta())
    is_deleted = models.BooleanField(default=False)
    hub_amount = models.DecimalField(max_digits=15, decimal_places=10, null=True, blank=True)

class CancelledBookings(BaseModel):
    """
    Here the cancelled bookings details will be stored to show to the patients because in the booking the details would be removed.
    """
    booking = models.OneToOneField("accounts.Booking", null=True, blank=True, on_delete=models.CASCADE,
                                   related_name="cancelledbooking")
    doctor = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True, related_name="cancelledbooking_doctor")
    room = models.ForeignKey(Room, blank=True, null=True, on_delete=models.CASCADE, related_name="cancelledbooking_room")
    van = models.ForeignKey(Van, blank=True, null=True, on_delete=models.CASCADE, related_name="cancelledbooking_van")
    virtualroom = models.ForeignKey(VirtualRoom, blank=True, null=True, on_delete=models.CASCADE,
                                    related_name="cancelledbooking_virtualroom")
    hub = models.ForeignKey(Hub, on_delete=models.CASCADE, blank=True, null=True, related_name="cancelledbooking_hub")
    visit_start_time = models.DateTimeField(null=True, blank=True)
    visit_end_time = models.DateTimeField(null=True, blank=True)
