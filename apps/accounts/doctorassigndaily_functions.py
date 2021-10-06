from datetime import datetime, timedelta, date

from rest_framework import serializers

from apps.accounts.models import (DynamicShiftManagement, Booking, User, Designation_Amount,
                                  DoctorAssignDaily, Van, VirtualRoom, Room, ContentType)
from custom_exception.common_exception import (
    CustomApiException,
)

date_format = '%Y-%m-%d'
location_error = "assign doctor"


def validate_van(assign_van, request, shift):
    if shift.start_time < shift.end_time:
        if Booking.objects.filter(van_id=request.data.get('visit_space'),
                                  visit_start_time__date=request.data.get('date'),
                                  visit_start_time__time__gte=shift.start_time,
                                  visit_end_time__time__lte=shift.end_time,
                                  hub_id=assign_van.hub_id
                                  ).exclude(state=2):
            raise CustomApiException(
                status_code=400, message="Van is booked",
                location="validate van"
            )
        # here or is used to get the date as timing of shift 3 cross the date to another
    else:
        if (Booking.objects.filter(van_id=request.data.get('visit_space'),
                                   visit_start_time__date=request.data.get('date'),
                                   visit_start_time__time__gte=shift.start_time,
                                   hub_id=assign_van.hub_id
                                   ).exclude(state=2)
                or
                Booking.objects.filter(van_id=request.data.get('visit_space'),
                                       visit_end_time__date=datetime.strptime(request.data.get('date'), date_format
                                                                              ) + timedelta(days=1),
                                       visit_end_time__time__lte=shift.end_time,
                                       hub_id=assign_van.hub_id
                                       ).exclude(state=2)):
            raise CustomApiException(
                status_code=400, message="Van is booked",
                location="validate van"
            )


def validate_virtual_room(assign_virtualroom, request, shift):
    if shift.start_time < shift.end_time:
        if Booking.objects.filter(virtualroom_id=request.data.get('visit_space'),
                                  visit_start_time__date=request.data.get('date'),
                                  visit_start_time__time__gte=shift.start_time,
                                  visit_end_time__time__lte=shift.end_time,
                                  hub_id=assign_virtualroom.hub_id
                                  ).exclude(state=2):
            raise CustomApiException(
                status_code=400, message="Virtual room is booked",
                location="validate Virtual room"
            )
    else:
        # here or is used to get the date as timing of shift 3 cross the date to another
        if (Booking.objects.filter(virtualroom_id=request.data.get('visit_space'),
                                   visit_start_time__date=request.data.get('date'),
                                   visit_start_time__time__gte=shift.start_time,
                                   hub_id=assign_virtualroom.hub_id
                                   ).exclude(state=2)
                or
                Booking.objects.filter(virtualroom_id=request.data.get('visit_space'),
                                       visit_end_time__date=datetime.strptime(request.data.get('date'), date_format
                                                                              ) + timedelta(days=1),
                                       visit_end_time__time__lte=shift.end_time,
                                       hub_id=assign_virtualroom.hub_id
                                       ).exclude(state=2)):
            raise CustomApiException(
                status_code=400, message="Virtual room is booked",
                location="validate Virtual room"
            )


def validate_room(assign_room, request, shift):
    if shift.start_time < shift.end_time:
        if Booking.objects.filter(room_id=request.data.get('visit_space'),
                                  visit_start_time__date=request.data.get('date'),
                                  visit_start_time__time__gte=shift.start_time,
                                  visit_end_time__time__lte=shift.end_time,
                                  hub_id=assign_room.hub_id
                                  ).exclude(state=2):
            raise CustomApiException(
                status_code=400, message="Room is booked",
                location="validate Room"
            )

    else:
        # here or is used to get the date as timing of shift 3 cross the date to another
        if (Booking.objects.filter(room_id=request.data.get('visit_space'),
                                   visit_start_time__date=request.data.get('date'),
                                   visit_start_time__time__gte=shift.start_time,
                                   hub_id=assign_room.hub_id
                                   ).exclude(state=2)
                or
                Booking.objects.filter(room_id=request.data.get('visit_space'),
                                       visit_end_time__date=datetime.strptime(request.data.get('date'), date_format
                                                                              ) + timedelta(days=1),
                                       visit_end_time__time__lte=shift.end_time,
                                       hub_id=assign_room.hub_id
                                       ).exclude(state=2)):
            raise CustomApiException(
                status_code=400, message="Room is booked",
                location="validate Room"
            )


def create_doctorassign_van(request, doc_assign_obj):
    try:
        assign_van = Van.objects.get(id=request.data.get('visit_space'))
        """
        Here generic relation could be used to check for the ,van jo kissi aur doctor ko 
        same shift pe, same din pe assign toh nai hai!!! 
        """
        if doc_assign_obj.filter(object_id=assign_van.id,
                                 date=request.data.get('date'),
                                 dynamic_shift=request.data.get('dynamic_shift'),
                                 visit_type=request.data.get('visit_type')).exists():
            raise serializers.ValidationError({
                "status": 400,
                "error": {
                    "location": location_error,
                    "message": "The Van is assigned to the other doctor"
                }})
        assign_obj = DoctorAssignDaily.objects.create(visit_type=1, visit_space=assign_van,
                                                      hub_id=assign_van.hub_id)
    except Van.DoesNotExist:
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": location_error,
                "message": "Invalid visit_space i.e Van id !!"
            }})
    return assign_obj


def create_doctorassign_virtualroom(request, doc_assign_obj):
    try:
        assign_virtualroom = VirtualRoom.objects.get(id=request.data.get('visit_space'))
        if doc_assign_obj.filter(object_id=assign_virtualroom.id,
                                 date=request.data.get('date'),
                                 dynamic_shift=request.data.get('dynamic_shift'),
                                 visit_type=request.data.get('visit_type')).exists():
            raise serializers.ValidationError({
                "status": 400,
                "error": {
                    "location": location_error,
                    "message": "The Virtualroom is assigned to the other doctor"
                }})
        assign_obj = DoctorAssignDaily.objects.create(visit_type=2, visit_space=assign_virtualroom,
                                                      hub_id=assign_virtualroom.hub_id)
    except VirtualRoom.DoesNotExist:
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": location_error,
                "message": "Invalid visit_space i.e Virtual Room id !!"
            }})
    return assign_obj


def create_doctorassign_room(request, doc_assign_obj):
    try:
        assign_room = Room.objects.get(id=request.data.get('visit_space'))
        if doc_assign_obj.filter(object_id=assign_room.id,
                                 date=request.data.get('date'),
                                 dynamic_shift=request.data.get('dynamic_shift'),
                                 visit_type=request.data.get('visit_type')).exists():
            raise serializers.ValidationError({
                "status": 400,
                "error": {
                    "location": location_error,
                    "message": "The Room is assigned to the other doctor"
                }})
        assign_obj = DoctorAssignDaily.objects.create(visit_type=3, visit_space=assign_room,
                                                      hub_id=assign_room.hub_id)
    except Room.DoesNotExist:
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": location_error,
                "message": "Invalid visit_space i.e Room id !!"
            }})
    return assign_obj


def update_doctorassign_van(request, obj):
    try:
        # filtering and updating doesnt work for generic foreign key
        # the error will be as  Use a value compatible with GenericForeignKey.
        # We have to update it as an object
        # mobile doctor ka content_type_id=14(van) hai toh check lagaya hai
        assign_van = Van.objects.get(id=request.data.get('visit_space'))
        if DoctorAssignDaily.objects.filter(object_id=assign_van.id,
                                            date=request.data.get('date'),
                                            dynamic_shift=request.data.get('dynamic_shift'),
                                            content_type_id=ContentType.objects.get(model='van').id,
                                            hub_id=obj.hub_id).exclude(id=obj.id).exists():
            raise serializers.ValidationError({
                "status": 400,
                "error": {
                    "location": location_error,
                    "message": "The Van is assigned to the other doctor"
                }})
        obj.visit_type = 1
        obj.visit_space = assign_van
    except Van.DoesNotExist:
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": location_error,
                "message": "Invalid visit_space i.e Van id !!"
            }})
    return obj


def update_doctorassign_virtualroom(request, obj):
    try:
        assign_virtualroom = VirtualRoom.objects.get(id=request.data.get('visit_space'))
        if DoctorAssignDaily.objects.filter(object_id=assign_virtualroom.id,
                                            date=request.data.get('date'),
                                            dynamic_shift=request.data.get('dynamic_shift'),
                                            content_type_id=ContentType.objects.get(model='virtualroom').id,
                                            hub_id=obj.hub_id).exclude(id=obj.id).exists():
            raise serializers.ValidationError({
                "status": 400,
                "error": {
                    "location": location_error,
                    "message": "The Virtual Room is assigned to another doctor."
                }})
        obj.visit_type = 2
        obj.visit_space = assign_virtualroom
    except VirtualRoom.DoesNotExist:
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": location_error,
                "message": "Invalid visit_space i.e Virtual Room id !!"
            }})
    return obj


def update_doctorassign_room(request, obj):
    try:
        assign_room = Room.objects.get(id=request.data.get('visit_space'))
        if DoctorAssignDaily.objects.filter(object_id=assign_room.id,
                                            date=request.data.get('date'),
                                            dynamic_shift=request.data.get('dynamic_shift'),
                                            content_type_id=ContentType.objects.get(model='room').id,
                                            hub_id=obj.hub_id).exclude(id=obj.id).exists():
            raise serializers.ValidationError({
                "status": 400,
                "error": {
                    "location": location_error,
                    "message": "The Virtual Room is assigned to the other doctor"
                }})
        obj.visit_type = 3
        obj.visit_space = assign_room
    except Room.DoesNotExist:
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": location_error,
                "message": "Invalid visit_space i.e Room id !!"
            }})
    return obj


def doctorpayment(validated_data, request, assign_obj):
    """ naaya doctor(validated_data.get('doctor').id) pe saab calculate ho raaha hai"""
    assign_obj.date = validated_data.get('date')
    # validated_data.get('doctor') will give us object as doctor is the fk assigned in the model
    doctor_obj = User.objects.get(id=validated_data.get('doctor').id)
    assign_obj.doctor_id = doctor_obj.id
    assign_obj.date = request.data.get('date')
    assign_obj.dynamic_shift_id = request.data.get('dynamic_shift')
    shift = DynamicShiftManagement.objects.filter(id=request.data.get('dynamic_shift')).first()
    str_to_date_type = datetime.strptime(request.data.get('date'), date_format).date()
    start_date_time = datetime.combine(str_to_date_type, shift.start_time)
    if shift.start_time < shift.end_time:
        end_date_time = datetime.combine(str_to_date_type, shift.end_time)
    else:
        str_to_date_type = str_to_date_type + timedelta(days=1)
        end_date_time = datetime.combine(str_to_date_type, shift.end_time)
    assign_obj.shift_start_time = start_date_time
    assign_obj.shift_end_time = end_date_time
    working_hours = assign_obj.shift_end_time - assign_obj.shift_start_time
    working_hours_value_to_format = datetime.strptime(str(working_hours), '%H:%M:%S').time()
    assign_obj.workinghours = working_hours_value_to_format
    # create kaay time pe saving now , update kaay time pe save it later
    if request.method == 'POST':
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
    return working_hours_value_to_format, amount_perday, doctor_obj, designation_obj, working_hours


def payment_deduction_method(payment_obj, instance_obj, designation_obj):
    """when update is done then working hours change then payment also changes so , deduct from previous doctor"""
    """instance_obj.working_hours = Doctorassigndaily ka hai"""
    """payment_obj.working_hours = DoctorPaymentPerday ja hai"""

    """If the """
    if payment_obj.workinghours.second == 59 and payment_obj.workinghours.minute == 59 and payment_obj.workinghours.hour != 23:
        t = payment_obj.workinghours
        t = t.replace(second=0, microsecond=0, minute=0, hour=t.hour + 1)
    else:
        t = payment_obj.workinghours
    payment_obj.workinghours = datetime.combine(date.today(), t
                                                ) - datetime.combine(date.today(), instance_obj.workinghours)
    payment_obj.workinghours = (datetime.min + payment_obj.workinghours).time()
    str_value = str(instance_obj.workinghours)
    value_split = str_value.split(":")
    if int(value_split[1]) < 30:
        value_split[1] = 0
    elif int(value_split[1]) <= 59:
        value_split[1] = 5
    value_decimal = int(value_split[0]) + (int(value_split[1]) / 10)  # 07:40:00 to 7.5 hour
    amount_to_be_deducted = designation_obj.designation_amount * value_decimal
    payment_obj.amount_perday = payment_obj.amount_perday - amount_to_be_deducted
    if str(payment_obj.workinghours) == '0:00:00' or str(payment_obj.workinghours) == '00:00:00':
        payment_obj.delete()
    else:
        payment_obj.save()
    return payment_obj
