# Generated by Django 2.1 on 2021-01-14 14:50

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0044_auto_20210114_0818'),
    ]

    operations = [
        migrations.RenameField(
            model_name='tempdoctormedicaldoc',
            old_name='doctor',
            new_name='temp_doc_work',
        ),
    ]
