# Generated by Django 2.1 on 2021-02-11 21:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0097_booking_medical_disclosure'),
    ]

    operations = [
        migrations.AddField(
            model_name='booking',
            name='meet_link',
            field=models.URLField(blank=True, null=True),
        ),
    ]
