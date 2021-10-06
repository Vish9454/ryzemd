from rest_framework import permissions
from apps.accounts.models import User
class ISPatient(permissions.BasePermission):
    '''
        Custom isPatient to get the Patient Token Authenticated in APIs
    '''
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.user_role==User.PATIENT)

class IsAdminPatient(permissions.BasePermission):
    '''
        Custom permission for Admin accessing patients pofile also
        admin and patient common api
    '''
    def has_permission(self,request,view):
        return bool(request.user.is_authenticated and (request.user.user_role==User.PATIENT or request.user.user_role==User.ADMIN or
                                                       request.user.user_role==User.SUBADMIN))
