# Generated by Django 2.1 on 2021-01-21 14:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0065_auto_20210121_1126'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='medicalhistory',
            name='medicalhistory_items',
        ),
        migrations.RemoveField(
            model_name='symptoms',
            name='symptoms_items',
        ),
        migrations.AlterField(
            model_name='medicalhistoryitems',
            name='medicalhistory_name',
            field=models.CharField(blank=True, max_length=50, null=True, verbose_name='state_name'),
        ),
        migrations.AlterField(
            model_name='symptomsitems',
            name='symptoms_name',
            field=models.CharField(blank=True, max_length=50, null=True, verbose_name='state_name'),
        ),
    ]
