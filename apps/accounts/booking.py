import random
from datetime import datetime

from django.db.models import F
from rest_framework import serializers

from apps.accounts.models import (DynamicShiftManagement, Booking, DoctorAssignDaily, Van, VirtualRoom, Room,
                                  ContentType)

date_time_string = '%Y-%m-%d %H:%M:%S'

doctor_not_avaialble = "Doctor is not available for this visit type."


def get_dynamic_shift_id(request):
    current_datetime = request.data.get("datetime")
    current_datetime_format = datetime.strptime(current_datetime, date_time_string)
    shift_obj = DynamicShiftManagement.objects.filter(is_deleted=False).all()
    """here there will be 2 conditions as night shift and day shift so shift is taken out accordingly"""
    for obj in shift_obj:
        if obj.start_time < obj.end_time:
            shift_obtained_obj = DynamicShiftManagement.objects.filter(start_time__lte=current_datetime_format.time(),
                                                                       end_time__gte=current_datetime_format.time(),
                                                                       is_deleted=False).first()
    if shift_obtained_obj is None:
        shift_obtained_obj = DynamicShiftManagement.objects.filter(start_time__gt=F('end_time'),
                                                                   is_deleted=False).first()
    return shift_obtained_obj


def booknow_mobiledoctor(request, instance, booking_obj, shift_obj, current_datetime_round_off):
    # here all the doctor for today who are assigned van in the hub are in obj
    doctor_assigned = DoctorAssignDaily.objects.filter(
        content_type_id=ContentType.objects.get(model='van').id,
        visit_type=1,
        hub_id=booking_obj.hub_id,
        dynamic_shift=shift_obj,
        # shift start time and end time is taken as booking can at 8:50 and at 9:00 the shift gets over
        shift_start_time__lte=current_datetime_round_off,
        shift_end_time__gte=current_datetime_round_off
    )
    # print(doctor_assigned,"doctor_assigned is as -")
    if not doctor_assigned:
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": "Update Booking, doctor unavailable",
                "message": doctor_not_avaialble
            }})
    # here the vans which are booked and not cancelled are stored in that hub
    vans_booked = Booking.objects.filter(visit_start_time__lte=current_datetime_round_off,
                                         visit_end_time__gt=current_datetime_round_off,
                                         hub_id=booking_obj.hub_id, doctor_id__isnull=False
                                         ).exclude(van_id=(None,)).exclude(
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
                "message": doctor_not_avaialble
            }})
    # 1
    return_avail_van_obj = Van.objects.get(id=remove_from_tuple)
    # print(return_avail_van_obj,"return_avail_van_obj is as -")
    # here the doctor_id is stored in the booking table
    doctor_id = DoctorAssignDaily.objects.get(object_id=remove_from_tuple,
                                              content_type_id=ContentType.objects.get(model='van').id,
                                              visit_type=1,
                                              hub_id=booking_obj.hub_id,
                                              dynamic_shift=shift_obj,
                                              shift_start_time__lte=current_datetime_round_off,
                                              shift_end_time__gte=current_datetime_round_off
                                              )
    return doctor_id.doctor_id, return_avail_van_obj


def booknow_videoconfer(request, instance, booking_obj, validated_data, shift_obj, current_datetime_round_off):
    # option is 2 for Booking.VIDEO_CONFERENCING
    doctor_assigned = DoctorAssignDaily.objects.filter(
        content_type_id=ContentType.objects.get(model='virtualroom').id,
        visit_type=2,
        hub_id=booking_obj.hub_id,
        dynamic_shift=shift_obj,
        shift_start_time__lte=current_datetime_round_off,
        shift_end_time__gte=current_datetime_round_off
    )
    if not doctor_assigned:
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": "Update Booking, unavailable doctor",
                "message": doctor_not_avaialble
            }})
    virtualroom_booked = Booking.objects.filter(visit_start_time__lte=current_datetime_round_off,
                                                visit_end_time__gt=current_datetime_round_off,
                                                hub_id=validated_data.get('hub'), doctor_id__isnull=False).exclude(
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
                "message": doctor_not_avaialble
            }})
    return_avail_vr_obj = VirtualRoom.objects.get(id=remove_from_tuple)
    doctor_id = DoctorAssignDaily.objects.get(object_id=remove_from_tuple,
                                              content_type_id=ContentType.objects.get(
                                                  model='virtualroom').id,
                                              visit_type=2,
                                              hub_id=booking_obj.hub_id,
                                              dynamic_shift=shift_obj,
                                              shift_start_time__lte=current_datetime_round_off,
                                              shift_end_time__gte=current_datetime_round_off
                                              )
    return doctor_id.doctor_id, return_avail_vr_obj


def booknow_hubvisit(request, instance, booking_obj, validated_data, shift_obj, current_datetime_round_off):
    # option is 3 for Booking.HUB_VISIT
    doctor_assigned = DoctorAssignDaily.objects.filter(
        content_type_id=ContentType.objects.get(model='room').id,
        visit_type=3,
        hub_id=booking_obj.hub_id,
        dynamic_shift=shift_obj,
        shift_start_time__lte=current_datetime_round_off,
        shift_end_time__gte=current_datetime_round_off
    )
    if not doctor_assigned:
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": "Doctor Unavailable",
                "message": doctor_not_avaialble
            }})
    room_booked = Booking.objects.filter(visit_start_time__lte=current_datetime_round_off,
                                         visit_end_time__gt=current_datetime_round_off,
                                         hub_id=validated_data.get('hub'), doctor_id__isnull=False).exclude(
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
                "message": doctor_not_avaialble
            }})
    return_avail_room_obj = Room.objects.get(id=remove_from_tuple)
    doctor_id = DoctorAssignDaily.objects.get(object_id=remove_from_tuple,
                                              content_type_id=ContentType.objects.get(model='room').id,
                                              visit_type=3,
                                              hub_id=booking_obj.hub_id,
                                              dynamic_shift=shift_obj,
                                              shift_start_time__lte=current_datetime_round_off,
                                              shift_end_time__gte=current_datetime_round_off
                                              )
    return doctor_id.doctor_id, return_avail_room_obj


def booklater_mobiledoctor(request, instance, book_obj_now):
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
                "message": doctor_not_avaialble
            }})
    vans_booked = Booking.objects.filter(visit_start_time__lte=book_obj_now.visit_start_time,
                                         visit_end_time__gt=book_obj_now.visit_end_time,
                                         hub_id=book_obj_now.hub_id, doctor_id__isnull=False).exclude(van_id=(None,)
                                                                                                      ).exclude(
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
                "message": doctor_not_avaialble
            }})
    return_avail_van_obj = Van.objects.get(id=remove_from_tuple)
    Booking.objects.filter(id=instance.id).update(van_id=return_avail_van_obj)
    doctor_id = DoctorAssignDaily.objects.get(object_id=remove_from_tuple,
                                              content_type_id=ContentType.objects.get(model='van').id,
                                              visit_type=1,
                                              hub_id=book_obj_now.hub_id,
                                              shift_start_time__lte=book_obj_now.visit_start_time,
                                              shift_end_time__gte=book_obj_now.visit_end_time)
    Booking.objects.filter(id=instance.id).update(temp_doctor_id=doctor_id.doctor_id)
    return instance


def booklater_videoconfer(request, instance, book_obj_now):
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
                "message": doctor_not_avaialble
            }})
    virtualroom_booked = Booking.objects.filter(visit_start_time__lte=book_obj_now.visit_start_time,
                                                visit_end_time__gt=book_obj_now.visit_end_time,
                                                hub_id=book_obj_now.hub_id, doctor_id__isnull=False).exclude(
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
                "message": doctor_not_avaialble
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
    Booking.objects.filter(id=instance.id).update(temp_doctor_id=doctor_id.doctor_id)
    return instance


def booklater_hubvisit(request, instance, book_obj_now):
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
                "message": doctor_not_avaialble
            }})
    rooms_booked = Booking.objects.filter(visit_start_time__lte=book_obj_now.visit_start_time,
                                          visit_end_time__gt=book_obj_now.visit_end_time,
                                          hub_id=book_obj_now.hub_id, doctor_id__isnull=False).exclude(room_id=(None,)
                                                                                                       ).exclude(
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
                "message": doctor_not_avaialble
            }})
    return_avail_room_obj = Room.objects.get(id=remove_from_tuple)
    Booking.objects.filter(id=instance.id).update(room_id=return_avail_room_obj)
    doctor_id = DoctorAssignDaily.objects.get(object_id=remove_from_tuple,
                                              content_type_id=ContentType.objects.get(model='room').id,
                                              visit_type=3,
                                              hub_id=book_obj_now.hub_id,
                                              shift_start_time__lte=book_obj_now.visit_start_time,
                                              shift_end_time__gte=book_obj_now.visit_end_time)
    Booking.objects.filter(id=instance.id).update(temp_doctor_id=doctor_id.doctor_id)
    return instance
