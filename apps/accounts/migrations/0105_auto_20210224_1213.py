# Generated by Django 2.1 on 2021-02-24 12:13

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0104_rolesmanagement'),
    ]

    operations = [
        migrations.RenameField(
            model_name='rolesmanagement',
            old_name='modules',
            new_name='modules_access',
        ),
    ]
