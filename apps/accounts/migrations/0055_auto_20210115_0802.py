# Generated by Django 2.1 on 2021-01-15 08:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0054_remove_tempdoctormedicaldoc_tempdoctor'),
    ]

    operations = [
        migrations.AlterField(
            model_name='tempdoctorworkinfo',
            name='designation',
            field=models.IntegerField(blank=True, choices=[(1, 'Physician'), (2, 'PA'), (3, 'NP')], null=True, verbose_name='Designation'),
        ),
    ]
