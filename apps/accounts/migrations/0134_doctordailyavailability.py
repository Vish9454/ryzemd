# Generated by Django 2.1 on 2021-04-20 11:25

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0133_booking_payment_intent_id'),
    ]

    operations = [
        migrations.CreateModel(
            name='DoctorDailyAvailability',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Last Updated At')),
                ('date', models.DateField(blank=True, null=True)),
                ('is_available', models.BooleanField(default=True, verbose_name='isavailable')),
                ('doctor', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='doctor_availability', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'BaseModel',
                'abstract': False,
            },
        ),
    ]
