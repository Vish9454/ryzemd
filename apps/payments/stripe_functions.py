import stripe
from config.local import STRIPE_SECRET_KEY
from apps.accounts.models import Booking, User,City,State

stripe.api_key = STRIPE_SECRET_KEY
import time

class Stripe:

    def __init__(self, user_id):
        self.user_id = user_id

    def stripe_customer_create(self):
        user_obj = User.objects.get(id=self.user_id)
        stripe_customer = stripe.Customer.create(
            description="Creating stripe customer",
            email=user_obj.email,
            name=user_obj.name,
            phone=user_obj.phone_number,
        )
        User.objects.filter(id=self.user_id).update(stripe_customer_id=stripe_customer.id,
                                                                   is_stripe_customer=True)
        return stripe_customer

    def stripe_create_card(self,card_token):
        user_obj = User.objects.get(id=self.user_id)
        stripe_card = stripe.Customer.create_source(user_obj.stripe_customer_id,source=card_token,)
        return stripe_card

    def stripe_retrieve_card(self,card_token):
        user_obj = User.objects.get(id=self.user_id)
        stripe_card = stripe.Customer.retrieve_source(user_obj.stripe_customer_id,card_token,)
        return stripe_card

    def stripe_delete_card(self,card_id):
        user_obj = User.objects.get(id=self.user_id)
        stripe_card = stripe.Customer.delete_source(user_obj.stripe_customer_id,card_id,)
        return stripe_card["deleted"]

    def stripe_list_card(self):
        user_obj = User.objects.get(id=self.user_id)
        stripe_card = stripe.Customer.list_sources(user_obj.stripe_customer_id,object="card")
        return stripe_card

    def create_payment_intent(self, booking_id, currency, amount, card_id):
        user_obj = User.objects.get(id=self.user_id)
        customer = user_obj.stripe_customer_id
        admin_customer_id = User.objects.filter(user_role=User.ADMIN).first().stripe_customer_id
        Booking.objects.filter(id=booking_id).update(card_id=card_id)
        stripe_pay = stripe.PaymentIntent.create(
            amount=int(amount) * 100,
            currency=currency,
            customer=customer,
            description="Payment for Booking of Doctor.",
            receipt_email=user_obj.email,
            transfer_data={"destination": admin_customer_id, },
            payment_method=card_id,
        )
        return stripe_pay

    def confirm_payment_intent(self,payment_intent_id,card_id):
        stripe_pay = stripe.PaymentIntent.confirm(payment_intent_id,payment_method=card_id)
        return stripe_pay

    def list_payment_intent(self):
        stripe_pay = stripe.PaymentIntent.list()
        return stripe_pay

    def retrieve_payment_intent(self,payment_intent_id):
        stripe_pay = stripe.PaymentIntent.retrieve(payment_intent_id)
        return stripe_pay

    def cancel_payment_intent(self,payment_intent_id):
        stripe_pay = stripe.PaymentIntent.cancel(payment_intent_id)
        return stripe_pay

    def update_payment_intent(self,payment_intent_id,amount):
        payment_update = stripe.PaymentIntent.modify(payment_intent_id,amount=amount)
        return payment_update

    def create_admin_account(self):
        """
        for creating Admin account so that the external bank account can be created and money can be transfered to
        to the admin's bank account
        """
        user_obj = User.objects.get(id=self.user_id)
        stripe_admin_account = stripe.Account.create(
            type="custom",
            country="US",
            email=user_obj.email,
            capabilities={
                'card_payments': {
                    'requested': True,
                },
                'transfers': {
                    'requested': True,
                },
            },
        )
        # This is for accepting the terms and condition of the stripe account of Admin
        # stripe.Account.modify(stripe_admin_account.['data'][0]['account'],
        #                       tos_acceptance={'date': int(time.time()), 'ip': '8.8.8.8', })
        return stripe_admin_account

    def add_bankaccount(self, data):
        """for adding admin's bank account"""
        """checking if admin has bank account or not"""
        user_obj = User.objects.get(id=self.user_id)
        bank_token = data["bank_token"]
        if user_obj.has_bank_account:
            # retrieve bank account object
            response = stripe.Account.list_external_accounts(
                user_obj.stripe_customer_id,
                object="bank_account",
                limit=1,
            )
            # update bank account
            bank_account = stripe.Account.modify_external_account(
                user_obj.stripe_customer_id,
                response.data[0]["id"]
            )
        else:
            bank_account = stripe.Account.create_external_account(
                user_obj.stripe_customer_id, external_account=bank_token
            )
        return bank_account

    def retrieve_bankaccount(self):
        """listing owner bank accounts"""
        user_obj = User.objects.get(id=self.user_id)
        account_list = stripe.Account.list_external_accounts(
            user_obj.stripe_customer_id,
            object="bank_account",
            limit=3,
        )
        return account_list