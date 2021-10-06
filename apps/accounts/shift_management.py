from django.db.models import F
from rest_framework import serializers

from apps.accounts.models import DynamicShiftManagement

location_error = "create shift"


def create_validation_one(start_time, end_time):
    shift_obj = DynamicShiftManagement.objects.filter(start_time__lte=start_time,
                                                      end_time__gte=end_time,
                                                      is_deleted=False)
    shift_obj1 = DynamicShiftManagement.objects.filter(start_time__gte=start_time,
                                                       end_time__lte=end_time,
                                                       is_deleted=False)
    if shift_obj or shift_obj1:
        raise serializers.ValidationError({
            "status": 400, "error": {
                "location": "create shift .", "message": "This shift time is overlapping with other shift timing."
            }})


def create_validation_two(start_time, end_time):
    shift_obj = DynamicShiftManagement.objects.filter(start_time__gte=start_time, is_deleted=False)
    if shift_obj:
        raise serializers.ValidationError({
            "status": 400, "error": {
                "location": "Create shift .", "message": "This  shift time is overlapping with other shift timing"
            }})


def create_validation_three(start_time, end_time, shift_next_day_obj):
    shift_obj = DynamicShiftManagement.objects.filter(start_time__gte=start_time,
                                                      end_time__lte=end_time,
                                                      is_deleted=False).exclude(id=shift_next_day_obj.id)
    # humne exclude kaara hai next day waala shift so end time compare toh kaarna padega na with end time
    shift_obj1 = True if shift_next_day_obj.start_time < end_time else False
    if shift_obj or shift_obj1:
        raise serializers.ValidationError({
            "status": 400, "error": {
                "location": "Create Shift.", "message": "This shift time is overlapping with other shift's timing"
            }})


def create_shift_validations(start_time, end_time):
    # yaha pe true for next day waali shift warna false will be stored in start_end_time from request body
    request_data_next_day = True if start_time > end_time else False
    # yaaha pe object nikla hai from databaseki next daya waala shift exists in db or not
    shift_next_day_obj = DynamicShiftManagement.objects.filter(start_time__gte=F('end_time'), is_deleted=False).first()
    # next day waali shift means ki 22:00 se 03:00 tak type
    # request mey next day waali shift means start time > end time like 23:00 se 03:00
    """ 4 cases will happen"""
    # jab DB mey next day waali shift na ho and request mey next day waali shift na ho
    # jab DB mey next day waali shift na ho and request mey next day waali shift ho
    # jab db mey next day waali shift ho and request mey next day waali shift na ho
    # jab db mey next day waali shift ho and request mey next day waali shift ho
    ##################################################################################
    # jab DB mey next day waali shift na ho and request mey next day waali shift na ho
    if not shift_next_day_obj and not request_data_next_day:
        create_validation_one(start_time, end_time)

    # jab DB mey next day waali shift na ho and request mey next day waali shift ho
    elif not shift_next_day_obj and request_data_next_day:
        create_validation_two(start_time, end_time)

    # jab db mey next day waali shift ho and request mey next day waali shift na ho
    elif shift_next_day_obj and not request_data_next_day:
        # excluding the next day shift object so that filter query runs accuratly
        create_validation_three(start_time, end_time, shift_next_day_obj)

    # jab db mey next day waali shift ho and request mey next day waali shift ho
    else:
        raise serializers.ValidationError({
            "status": 400, "error": {
                "location": location_error, "message": "There already exists a night shift."
            }})
    value = False
    try:
        if end_time <= shift_next_day_obj.end_time or start_time < shift_next_day_obj.end_time:
            value = True
    except Exception:
        value = False
    if value:
        raise serializers.ValidationError({
            "status": 400, "error": {
                "location": location_error, "message": "There already exists a night shift ."
            }})


def update_validation_one(start_time, end_time, instance):
    shift_obj = DynamicShiftManagement.objects.filter(start_time__lte=start_time,
                                                      end_time__gte=end_time,
                                                      is_deleted=False).exclude(id=instance.id).first()
    shift_obj1 = DynamicShiftManagement.objects.filter(start_time__gte=start_time,
                                                       end_time__lte=end_time,
                                                       is_deleted=False).exclude(id=instance.id).first()
    if shift_obj or shift_obj1:
        raise serializers.ValidationError({
            "status": 400, "error": {
                "location": "Update Shift", "message": "This shift time is overlapping with other shift timing."
            }})


def update_validation_two(start_time, end_time, instance):
    shift_obj = DynamicShiftManagement.objects.filter(start_time__gte=start_time,
                                                      is_deleted=False).exclude(id=instance.id)
    if shift_obj:
        raise serializers.ValidationError({
            "status": 400, "error": {
                "location": "update shift.", "message": "This  shift time is overlapping with other shift timing"
            }})


def update_validation_three(start_time, end_time, instance, shift_next_day_obj):
    shift_obj = DynamicShiftManagement.objects.filter(start_time__gte=start_time,
                                                      end_time__lte=end_time,
                                                      is_deleted=False).exclude(id=shift_next_day_obj.id).exclude(
        id=instance.id)
    shift_obj1 = True if shift_next_day_obj.start_time < end_time else False
    if shift_obj or shift_obj1:
        raise serializers.ValidationError({
            "status": 400, "error": {
                "location": "update shift . ", "message": "This shift time is overlapping with other shift's timing"
            }})


def update_shift_validations(start_time, end_time, instance, data):
    if start_time == end_time:
        raise serializers.ValidationError({
            "status": 400, "error": {
                "location": "Update shift", "message": "Start and End time cannot be the same."
            }})
    request_data_next_day = True if start_time > end_time else False
    shift_next_day_obj = DynamicShiftManagement.objects.filter(start_time__gte=F('end_time'),
                                                               is_deleted=False).exclude(id=instance.id).first()
    """ 4 cases will happen"""
    # jab DB mey next day waali shift na ho and request mey next day waali shift na ho
    # jab DB mey next day waali shift na ho and request mey next day waali shift ho
    # jab db mey next day waali shift ho and request mey next day waali shift na ho
    # jab db mey next day waali shift ho and request mey next day waali shift ho
    if not shift_next_day_obj and not request_data_next_day:
        update_validation_one(start_time, end_time, instance)

    elif not shift_next_day_obj and request_data_next_day:
        update_validation_two(start_time, end_time, instance)

    elif shift_next_day_obj and not request_data_next_day:
        update_validation_three(start_time, end_time, instance, shift_next_day_obj)

    else:
        raise serializers.ValidationError({
            "status": 400, "error": {
                "location": "update shift", "message": "There already exists a night shift."
            }})

    value = False
    try:
        if end_time <= shift_next_day_obj.end_time or start_time < shift_next_day_obj.end_time:
            value = True
    except Exception:
        value = False
    if value:
        raise serializers.ValidationError({
            "status": 400, "error": {
                "location": location_error, "message": "There already exists a night shift ."
            }})
    DynamicShiftManagement.objects.filter(id=instance.id).update(**data)
