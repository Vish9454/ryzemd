from django.shortcuts import render
from django.contrib.auth.models import Permission
from django_filters.rest_framework import DjangoFilterBackend
from datetime import datetime, timedelta
from rest_framework import serializers
from rest_framework import mixins, viewsets
from rest_framework import filters
from rest_framework.permissions import IsAuthenticated
from apps.accounts.permissions import IsAdmin
from rest_framework.views import APIView
from apps.accounts.models import (Booking, User)
from apps.payments.models import CustomerCard
from custom_exception.common_exception import get_custom_error_message, CustomApiException
from response import CustomResponse
from pagination import Pagination
from utils import get_serialized_data
from utils import send_notification
from rest_framework.response import Response

from config.local import STRIPE_SECRET_KEY
from apps.payments.stripe_functions import Stripe
import stripe
from config.local import STRIPE_SECRET_KEY

stripe.api_key = STRIPE_SECRET_KEY


class CreateStripeCustomer(mixins.CreateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)

    def create(self, request):
        customer_obj = User.objects.filter(id=request.user.id, is_stripe_customer=True).first()
        if customer_obj:
            raise CustomApiException(status_code=400, message="The user_id has the stripe customer id",
                                     location="create stripe customer")
        # calling the stripe constructor
        # stripe is object of the class Stripe
        # reponse is the calling of method with the object
        try:
            stripe = Stripe(request.user.id)
            response = stripe.stripe_customer_create()
            return CustomResponse(response)
        except Exception:
            raise CustomApiException(status_code=400, message="Unable to create stripe customer,Kindly try later ",
                                     location="create stripe customer")


class Card(
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    """
    Add,list and delete customer card
    """
    permission_classes = (IsAuthenticated,)

    def create(self, request, *args, **kwargs):
        """adding customer stripe card"""
        card_token = request.query_params.get('card_token')
        try:
            stripe_obj = Stripe(request.user.id)
            stripe_card = stripe_obj.stripe_create_card(card_token)

            # to remove duplicacy of customer cards
            card_obj = CustomerCard.objects.filter(
                user=request.user, fingerprint=stripe_card.fingerprint).first()
            if card_obj:
                stripe.Customer.delete_source(
                    request.user.stripe_customer_id, stripe_card.id
                )
                return Response(
                    get_custom_error_message(
                        message="This card is already added",
                        error_location="Create Card",
                        status=400,
                    ),
                    status=400,
                )

            CustomerCard.objects.create(
                user=request.user,
                card_id=stripe_card.id,
                fingerprint=stripe_card.fingerprint,
                last4=stripe_card.last4, )
            return CustomResponse({"message": "Card added successfully"})
        except Exception:
            raise CustomApiException(
                status_code=400, message="Unable to add card try again later", location="create stripe cards", )

    def list(self, request, *args, **kwargs):
        try:
            stripe = Stripe(request.user.id)
            stripe_card = stripe.stripe_list_card()
            return CustomResponse(stripe_card)
        except Exception:
            raise CustomApiException(status_code=400, message="Unable to list,kindly try later",
                                     location="list stripe card ")

    def destroy(self, request, *args, **kwargs):
        card_id = request.query_params.get('card_id')
        if not card_id:
            raise CustomApiException(status_code=400, message="Kindly enter Card id",
                                     location="delete stripe card ")
        try:
            stripe = Stripe(request.user.id)
            stripe_obj = stripe.stripe_delete_card(card_id)
            if stripe_obj == True:
                CustomerCard.objects.filter(card_id=card_id).delete()
                return CustomResponse({"message": "Card deleted successfully"})
        except Exception:
            raise CustomApiException(status_code=400, message="Unable to delete,kindly try later",
                                     location="delete stripe card ")


class IntentPaymentOperations(mixins.CreateModelMixin,
                              mixins.ListModelMixin,
                              mixins.RetrieveModelMixin,
                              mixins.DestroyModelMixin,
                              viewsets.GenericViewSet,
                              mixins.UpdateModelMixin):
    permission_classes = (IsAuthenticated,)
    """
    here let us suppose the payment intent is created. 
    
    And patient cancels the booking , 
    2-If the booking is cancelled within 24 hrs of visit_start_time then --
    Firstly the amount and payment_intent_id is passed in the modify payment and amount is changed to 
    (deducting the cancellation charge) cancellation charge and then confirm payment API is hit to 
    pay the cancellation charge to the admin
    
    2- If the visit_start_time > 24 hrs then the cancellation charge is 0 then cancel_payment API is called.
    
    3- If the booking has state=4 then confirm_payment API is called 
    """

    def create(self, request, *args, **kwargs):
        # process to keep the co_pay on hold (amount will be deducted from patients acc, but not credited to Admin)
        booking_id = request.query_params.get("booking_id")
        currency = request.query_params.get("currency")
        amount = request.query_params.get("amount")
        card_id = request.query_params.get("card_id")
        if not booking_id or not currency or not card_id:
            raise CustomApiException(status_code=400, message="Kindly give both booking id, currency and card",
                                     location="create hold payment")
        if Booking.objects.filter(id=booking_id, payment_intent_id__isnull=False).exists():
            raise CustomApiException(status_code=400, message="Payment on hold is created, cannot create again",
                                     location="create hold payment")
        # calling constructor
        try:
            stripe_obj = Stripe(request.user.id)
            stripe_pay = stripe_obj.create_payment_intent(booking_id, currency, amount, card_id)
            Booking.objects.filter(id=booking_id).update(state=3, payment_intent_id=stripe_pay.id)
            return CustomResponse(stripe_pay)
        except Exception:
            raise CustomApiException(status_code=400, message="Unable to do payment,kindly try later",
                                     location="create hold payment ")

    def list(self, request, *args, **kwargs):
        try:
            stripe = Stripe(request.user.id)
            stripe_payment_list = stripe.list_payment_intent()
            return CustomResponse(stripe_payment_list)
        except Exception:
            raise CustomApiException(status_code=400, message="Unable to list,kindly try later",
                                     location="list payments ")

    def update(self, request):
        """
        This is the confirm payment when the booking is at state=4 and amount is in payment intent
        """
        booking_id = request.query_params.get("booking_id")
        payment_intent_id = Booking.objects.get(id=booking_id).payment_intent_id
        card_id = Booking.objects.get(id=booking_id).card_id
        if not payment_intent_id or not card_id:
            raise CustomApiException(status_code=400,
                                     message="Kindly give the payment Id or admin card_id doesnt exist.",
                                     location="confirm payment")
        try:
            stripe_obj = Stripe(request.user.id)
            stripe_payment_confirm = stripe_obj.confirm_payment_intent(payment_intent_id, card_id)
            Booking.objects.filter(id=booking_id).update(state=4)
            return CustomResponse(stripe_payment_confirm)
        except Exception:
            raise CustomApiException(status_code=400, message="Unable to confirm,kindly try later",
                                     location="confirm payment")

    def retrieve(self, request):
        payment_intent_id = request.query_params.get("payment_intent_id")
        if not payment_intent_id:
            raise CustomApiException(
                status_code=400, message="Kindly give payment intent id!!", location="retrieve payment info"
            )
        # calling constructor
        try:
            stripe_obj = Stripe(request.user.id)
            stripe_retrieve = stripe_obj.retrieve_payment_intent(payment_intent_id)
            return CustomResponse(stripe_retrieve)
        except Exception:
            raise CustomApiException(status_code=400, message="Unable to retrieve,kindly try later",
                                     location="retrieve payment info")


class ModifyPaymentIntent(viewsets.GenericViewSet, mixins.UpdateModelMixin):
    def update(self, request):
        """
        This is the update the amount of payment if the booking has to be cancelled
        In the amount the cancellation charge will come
        """
        payment_intent_id = request.query_params.get("payment_intent_id")
        amount = request.query_params.get("amount")
        amount = int(amount) * 100
        if not payment_intent_id or not amount:
            raise CustomApiException(status_code=400, message="Kindly give the payment Id and  amount both.",
                                     location="modify payment intent")
        try:
            stripe_obj = Stripe(request.user.id)
            stripe_payment_modify = stripe_obj.update_payment_intent(payment_intent_id, amount)
            return CustomResponse(stripe_payment_modify)
        except Exception:
            raise CustomApiException(status_code=400, message="Unable to modify payment,kindly try later",
                                     location="modify payment intent ")


class CancelPaymentIntent(mixins.CreateModelMixin, viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)

    def create(self, request, *args, **kwargs):
        payment_intent_id = request.query_params.get("payment_intent_id")
        if not payment_intent_id:
            raise CustomApiException(status_code=400,
                                     message="Kindly give the payment intent id for cancelling payment",
                                     location="create cancel payment")
        # calling constructor
        try:
            stripe_obj = Stripe(request.user.id)
            stripe_cancel = stripe_obj.cancel_payment_intent(payment_intent_id)
            return CustomResponse(stripe_cancel)
        except Exception:
            raise CustomApiException(status_code=400, message="Unable to cancel,kindly try later",
                                     location="create cancel payment")


class BankAccount(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """class used for adding bank account to a admin account created in stripe"""
    permission_classes = (IsAdmin,)

    def create(self, request, *args, **kwargs):
        """create customer cards"""
        data = request.data
        try:
            stripe_obj = Stripe(request.user.id)
            bank_account = stripe_obj.add_bankaccount(data)
            User.objects.filter(id=request.user.id).update(has_bank_account=True)
            return CustomResponse(bank_account)

        except Exception:
            raise CustomApiException(
                status_code=400,
                message="Unable to add bank account details, try again later",
                location="Add bank account",
            )

    def list(self, request):
        stripe_obj = Stripe(request.user.id)
        bank_account = stripe_obj.retrieve_bankaccount()
        return CustomResponse(bank_account)


class AdminAccount(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """
        Class which will handle admin account
    """
    permission_classes = (IsAdmin,)

    def create(self, request):
        admin_obj = User.objects.filter(
            id=request.user.id, is_stripe_customer=True
        ).first()

        if admin_obj:
            return Response(
                get_custom_error_message(
                    message="Admin account already exists",
                    error_location="Admin account create",
                    status=400,
                ),
                status=400,
            )

        try:
            # calling constructor
            stripe_obj = Stripe(request.user.id)
            response = stripe_obj.create_admin_account()
            admin_account = response.id
            # admin_account is stored in User -> stripe_customer_id
            User.objects.filter(id=request.user.id).update(
                stripe_customer_id=admin_account, is_stripe_customer=True
            )
            return CustomResponse(response)

        except Exception:
            raise CustomApiException(
                status_code=400,
                location="create admin account",
                message="Unable to create admin account, try again later.",
            )
