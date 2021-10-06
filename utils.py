"""importing packages for sending mails"""
import io
import os
import uuid
import urllib
import requests
import sendgrid
from django.core.files.storage import default_storage
from django.core.files.storage import default_storage
from django.contrib.gis.geos import GEOSGeometry
from django.contrib.gis.measure import D
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, Content, Attachment
from rest_framework import serializers
from rest_framework import serializers
from config.local import FROM_EMAIL
from config.local import FCM_SERVER_KEY
from pyfcm import FCMNotification


def send_notification(user_device_obj, title, message, data):
    push_service = FCMNotification(api_key=FCM_SERVER_KEY)
    fcm_token = []
    for token in user_device_obj:
        fcm_token.append(token.fcm_token)
    print(push_service.notify_multiple_devices(registration_ids=fcm_token, message_title=title,
                                               message_body=message, data_message=data))
    return push_service.notify_multiple_devices(registration_ids=fcm_token, message_title=title,
                                                message_body=message, data_message=data)


class DynamicFieldsModelSerializer(serializers.ModelSerializer):
    """
    A ModelSerializer that takes an additional `fields` argument that
    controls which fields should be displayed.
    """

    def __init__(self, *args, **kwargs):
        """init method"""
        fields = kwargs.pop("fields", None)
        super(DynamicFieldsModelSerializer, self).__init__(*args, **kwargs)
        if fields:
            allowed = set(fields)
            existing = set(self.fields.keys())
            for field_name in existing - allowed:
                self.fields.pop(field_name)


def get_serialized_data(obj, serializer, fields, many=False):
    if fields:
        return serializer(obj, fields=eval(fields), many=many)
    return serializer(obj, many=many)


def sendemail(subject, message, fro, to):
    """ method of sending email"""
    try:
        msg = EmailMessage(subject, message, fro, to)
        msg.content_subtype = "html"
        msg.send()


    except Exception:
        pass


def send_verification_email(email, code):
    """to send verification email"""
    try:
        ctx_dict = {"email": email, "verification_code": code}
        message = render_to_string("verification_email.html", ctx_dict)
        subject = "Email Verification "
        sendemail(subject, message, FROM_EMAIL, [email])
    except Exception:
        pass

def send_subadmin_cred_email(email,password,name):
    """to send verification email"""
    try:
        ctx_dict = {"email": email, "password": password, "name":name}
        message = render_to_string("send_subadmin_cred_email.html", ctx_dict)
        subject = "Email Verification. "
        sendemail(subject, message, FROM_EMAIL, [email])
    except Exception:
        pass

def send_forgot_password_email(email, code):
    """to send verification email"""
    try:
        ctx_dict = {"email": email, "verification_code": code}
        message = render_to_string("forgot_email.html", ctx_dict)
        subject = "Forgot Password"
        sendemail(subject, message, FROM_EMAIL, [email])
    except Exception:
        pass


def send_doc_verification_email(email, code):
    """to send push email"""
    try:

        ctx_dict = {"email": email, "docverification_url": code}
        message = render_to_string("docverification.html", ctx_dict)
        subject = "Document Verification"
        sendemail(subject, message, FROM_EMAIL, [email])
    except Exception:
        pass


def send_forget_password_otp(email, code):
    try:
        ctx_dict = {"email": email, "forget_password_code": code}
        message = render_to_string("forget_password_code.html", ctx_dict)
        subject = "Forgot Password"
        sendemail(subject, message, FROM_EMAIL, [email])
    except Exception:
        pass


def send_verify_admin_email(email, code):
    try:
        ctx_dict = {"email": email, "verification_code": code}
        message = render_to_string("admin_login_email.html", ctx_dict)
        subject = " Email Verification "
        sendemail(subject, message, FROM_EMAIL, [email])
    except Exception:
        pass
