# Generated by Django 2.1 on 2021-01-14 15:08

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0045_auto_20210114_1450'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='tempdoctormedicaldoc',
            name='temp_doc_work',
        ),
        migrations.AddField(
            model_name='tempdoctormedicaldoc',
            name='doctor',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='user_tempdoctormedicaldoc', to=settings.AUTH_USER_MODEL),
        ),
    ]
