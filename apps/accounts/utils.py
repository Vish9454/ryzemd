import random
import uuid

from apps.accounts.models import OTP


def generate_email_verification_url(user):
    """method to generate email verification url"""
    otp = uuid.uuid4().hex
    OTP.objects.update_or_create(
        user=user,
        otp_type=OTP.VERIFICATION_OTP,
        defaults={"otp": otp, "is_used": False},
    )

    return otp


def generate_forgot_password_url(user):
    """method to generate forgot password verification url for subadmin types and admin"""

    otp = uuid.uuid4().hex
    OTP.objects.update_or_create(
        user=user,
        otp_type=OTP.FORGOT_PASSWORD_OTP,
        defaults={"otp": otp, "is_used": False},
    )
    return otp


def generate_doc_verification_url(user):
    """method to generate doc verification url"""
    otp = uuid.uuid4().hex
    OTP.objects.update_or_create(
        user=user,
        otp_type=OTP.VERIFICATION_OTP,
        defaults={"otp": otp, "is_used": False},
    )
    return otp


def generate_forgot_password_otp(user):
    """method to generate forgot password otp"""
    otp = random.randint(1000, 9999)
    otp = str(otp)

    OTP.objects.update_or_create(
        user=user,
        otp_type=OTP.FORGOT_PASSWORD_OTP,
        defaults={"otp": otp, "is_used": False},
    )
    return otp


def generate_verify_admin_otp(user):
    """method to generate otp at admin and it's types"""
    otp = random.randint(1000, 9999)
    otp = str(otp)

    OTP.objects.update_or_create(
        user=user,
        otp_type=OTP.LOGIN_OTP,
        defaults={"otp": otp, "is_used": False},
    )
    return otp
