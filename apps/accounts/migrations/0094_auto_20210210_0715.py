# Generated by Django 2.1 on 2021-02-10 07:15

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0093_auto_20210209_0845'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='doctorassigndaily',
            name='shift_end_time',
        ),
        migrations.RemoveField(
            model_name='doctorassigndaily',
            name='shift_start_time',
        ),
    ]
