from apps.accounts.models import BaseModel
from django.db import models
from apps.accounts.models import Booking,User

class CustomerCard(BaseModel):
    user = models.ForeignKey(User,on_delete=models.CASCADE,related_name="customer_card")
    card_id = models.CharField(max_length=50)
    fingerprint = models.CharField(max_length=30)
    last4 = models.IntegerField(null=True, blank=True)

