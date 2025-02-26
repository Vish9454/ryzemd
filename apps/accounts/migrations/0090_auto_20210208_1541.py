# Generated by Django 2.1 on 2021-02-08 15:41

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0089_auto_20210208_0419'),
    ]

    operations = [
        migrations.AddField(
            model_name='doctorassigndaily',
            name='hub',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='doctorassigndaily_hub', to='accounts.Hub'),
        ),
        migrations.AlterField(
            model_name='booking',
            name='state',
            field=models.IntegerField(choices=[(1, 'new'), (2, 'cancel'), (4, 'completed'), (5, 'paid')], default=1, verbose_name='State'),
        ),
    ]
