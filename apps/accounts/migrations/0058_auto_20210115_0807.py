# Generated by Django 2.1 on 2021-01-15 08:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0057_auto_20210115_0804'),
    ]

    operations = [
        migrations.AlterField(
            model_name='tempdoctorworkinfo',
            name='shift',
            field=models.IntegerField(blank=True, choices=[(1, 'Morning'), (2, 'Afternoon'), (3, 'Evening')], null=True, verbose_name='Shift'),
        ),
    ]
