# Generated by Django 2.1 on 2021-01-22 11:26

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0071_remove_medicalhistory_medicalhistory_item_ids'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='medicalhistory',
            name='medicalhistory_item_id',
        ),
    ]
