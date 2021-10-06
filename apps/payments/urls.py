from django.contrib import admin
from django.urls import path
from . import views
urlpatterns = [
    path("createstripecustomer", views.CreateStripeCustomer.as_view({"post": "create"}), name="create stripe customer"),
    path("createliststripecard", views.Card.as_view({"post": "create","get":"list"}), name="create stripe card"),
    path("deletesrtipecard",views.Card.as_view({"delete":"destroy"}),name="delete stripe card"),
    path("createholdpayment", views.IntentPaymentOperations.as_view({"post": "create"}), name="create hold payment"),
    path("listpayments", views.IntentPaymentOperations.as_view({"get": "list"}), name="stripe_payment_list"),
    path("confirmpayment",views.IntentPaymentOperations.as_view({"put":"update"}),name="confirm payment"),
    path("cancelpayment", views.CancelPaymentIntent.as_view({"post": "create"}), name="create cancel payment"),
    path("retrievepayment", views.IntentPaymentOperations.as_view({"get": "retrieve"}),name="retrieve payment info"),
    path("modifypayment", views.ModifyPaymentIntent.as_view({"put": "update"}), name="modify payment intent"),
    # Admin
    path("adminaccount", views.AdminAccount.as_view({"post": "create"}), name="Admin account create"),
    path("bankaccount", views.BankAccount.as_view({"post": "create", "get":"list"}), name="add bank account"),
]