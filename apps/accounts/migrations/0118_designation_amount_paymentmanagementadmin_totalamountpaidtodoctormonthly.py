# Generated by Django 2.1 on 2021-03-31 08:46

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion

created_at_variable = 'Created At'
updated_at_variable = 'Last Updated At'

class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0117_auto_20210326_0641'),
    ]

    operations = [
        migrations.CreateModel(
            name='Designation_Amount',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name=created_at_variable)),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name=updated_at_variable)),
                ('designation_type', models.IntegerField(choices=[(1, 'Physician'), (2, 'PA'), (3, 'NP')], default=1, verbose_name='Designation')),
                ('designation_amount', models.DecimalField(decimal_places=4, max_digits=10, null=True)),
            ],
            options={
                'verbose_name': 'BaseModel',
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='PaymentManagementAdmin',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name=created_at_variable)),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name=updated_at_variable)),
                ('payment_perday_date', models.DateField(blank=True, null=True)),
                ('working_hours', models.FloatField(blank=True, default=0, null=True, verbose_name='Working hours')),
                ('amount_perday', models.FloatField(blank=True, default=0, null=True, verbose_name='Amount perday')),
                ('designation_amount', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='designation_amount_admin', to='accounts.Designation_Amount')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_payment_admin', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'BaseModel',
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='TotalAmountPaidToDoctorMonthly',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name=created_at_variable)),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name=updated_at_variable)),
                ('total_amount_to_be_paid', models.FloatField(blank=True, null=True, verbose_name='Working hours')),
                ('is_paid', models.BooleanField(default=False, verbose_name='is deleted')),
                ('month', models.IntegerField(blank=True, null=True, verbose_name='Month')),
            ],
            options={
                'verbose_name': 'BaseModel',
                'abstract': False,
            },
        ),
    ]
