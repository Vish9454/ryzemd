# Generated by Django 2.1 on 2021-01-14 17:23

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0052_remove_tempdoctormedicaldoc_tempdoctorinfo'),
    ]

    operations = [
        migrations.AddField(
            model_name='tempdoctormedicaldoc',
            name='tempdoctorinfo',
            field=models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, related_name='tempdoctorinfo_documents', to='accounts.TempDoctorWorkInfo'),
            preserve_default=False,
        ),
    ]
