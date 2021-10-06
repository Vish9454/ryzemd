from datetime import timedelta, datetime

from django.contrib.gis.geos import Point
from rest_framework import serializers

from apps.accounts.models import Booking, DoctorAssignDaily, ContentType, CancelledBookings


def cancelbooking(booking_obj, date_time) -> object:
    if booking_obj.visit_start_time.replace(tzinfo=None) - date_time > timedelta(hours=24):
        booking_obj.booking_cancel_charge = 0
    else:
        """
        the hubvisit caherge=50$ ,video conf=30$, mob doc=60$ 
        """
        if booking_obj.visit_type == Booking.HUB_VISIT:
            booking_obj.booking_cancel_charge = 50
            booking_obj.co_pay = booking_obj.co_pay - 50
        if booking_obj.visit_type == Booking.VIDEO_CONFERENCING:
            booking_obj.booking_cancel_charge = 30
            booking_obj.co_pay = booking_obj.co_pay - 30
        if booking_obj.visit_type == Booking.MOBILE_DOCTOR:
            booking_obj.booking_cancel_charge = 60
            booking_obj.co_pay = booking_obj.co_pay - 60
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
    return booking_obj


def source_address(request, booking_obj):
    point = Point(x=float(request.data.get('source_lng')), y=float(request.data.get('source_lat')), srid=4326)
    booking_obj.source_cordinate = point
    booking_obj.source_address = request.data.get('source_address')
    booking_obj.save()
    return booking_obj


def destination_address(request, booking_obj):
    point = Point(x=float(request.data.get('destination_lng')), y=float(request.data.get('destination_lat')), srid=4326)
    booking_obj.destination_cordinate = point
    booking_obj.destination_address = request.data.get('destination_address')
    booking_obj.save()
    return booking_obj


def hub_change(request, booking_obj):
    doctor_id = request.data.get('doctor_id')
    hub_id = request.data.get('hub_id')
    visit_start_time = datetime.strptime(request.data.get('visit_start_time'), '%Y-%m-%d %H:%M:%S')
    visit_type = booking_obj.visit_type
    if booking_obj.visit_type == Booking.HUB_VISIT:
        booking_obj.visit_end_time = visit_start_time + timedelta(minutes=30)
        visit_end_time = booking_obj.visit_end_time
        assign_obj = DoctorAssignDaily.objects.filter(doctor_id=doctor_id,
                                                      content_type_id=ContentType.objects.get(model='room').id,
                                                      shift_start_time__lte=visit_start_time,
                                                      shift_end_time__gte=booking_obj.visit_end_time
                                                      ).first()
        booking_obj.room_id = assign_obj.object_id
    if booking_obj.visit_type == Booking.VIDEO_CONFERENCING:
        booking_obj.visit_end_time = visit_start_time + timedelta(minutes=30)
        visit_end_time = booking_obj.visit_end_time
        assign_obj = DoctorAssignDaily.objects.filter(doctor_id=doctor_id,
                                                      content_type_id=ContentType.objects.get(model='virtualroom').id,
                                                      shift_start_time__lte=visit_start_time,
                                                      shift_end_time__gte=booking_obj.visit_end_time
                                                      ).first()
        booking_obj.virtualroom_id = assign_obj.object_id
    if booking_obj.visit_type == Booking.MOBILE_DOCTOR:
        booking_obj.visit_end_time = visit_start_time + timedelta(minutes=60)
        visit_end_time = booking_obj.visit_end_time
        assign_obj = DoctorAssignDaily.objects.filter(doctor_id=doctor_id,
                                                      content_type_id=ContentType.objects.get(model='van').id,
                                                      shift_start_time__lte=visit_start_time,
                                                      shift_end_time__gte=booking_obj.visit_end_time
                                                      ).first()
        booking_obj.van_id = assign_obj.object_id
    if Booking.objects.filter(doctor_id=doctor_id, visit_type=visit_type,
                              hub_id=hub_id, visit_start_time__lte=visit_start_time,
                              visit_end_time__gte=visit_start_time).exclude(id=booking_obj.id).exists():
        raise serializers.ValidationError({
            "status": 400,
            "error": {
                "location": "admin update booking",
                "message": "Doctor is assigned , kindly choose another doctor."
            }})
    else:
        booking_obj.visit_start_time = visit_start_time
        booking_obj.visit_end_time = visit_end_time
        booking_obj.hub_id = hub_id
        booking_obj.doctor_id = doctor_id
        booking_obj.save()
    return booking_obj
