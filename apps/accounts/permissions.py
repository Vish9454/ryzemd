"""import base permissions and models"""
from rest_framework.permissions import BasePermission

from .models import User


class IsAdmin(BasePermission):
    """ permission class for user : admin and subadmin"""

    def has_permission(self, request, view):
        if not (request.user.user_role == User.ADMIN or request.user.user_role == User.SUBADMIN):
            return False
        return True


class IsAdminOnly(BasePermission):
    """ permission class for user : admin """
    """ this is only for admin update API as admin can update only his own profile """

    def has_permission(self, request, view):
        if not request.user.user_role == User.ADMIN:
            return False
        return True
