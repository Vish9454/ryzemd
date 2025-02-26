# Generated by Django 2.1 on 2021-03-16 13:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0113_ratingdocandapp_is_deleted'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_stripe_customer',
            field=models.BooleanField(default=False, verbose_name='StripeCustomer'),
        ),
        migrations.AddField(
            model_name='user',
            name='stripe_customer_id',
            field=models.CharField(blank=True, max_length=30, null=True, verbose_name='customer id'),
        ),
    ]
