# Generated by Django 2.1 on 2021-02-10 19:36

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0095_auto_20210210_0715'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='booking',
            name='medical_disclosure',
        ),
    ]
