# Generated by Django 2.1 on 2020-12-15 18:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0020_auto_20201215_0905'),
    ]

    operations = [
        migrations.AddField(
            model_name='ratingdocandapp',
            name='comment_box',
            field=models.CharField(blank=True, max_length=400, null=True, verbose_name='Comment'),
        ),
        migrations.AlterField(
            model_name='ratingdocandapp',
            name='review',
            field=models.IntegerField(blank=True, choices=[(1, 'mobile_doctor'), (2, 'video_consult'), (3, 'hub_visit'), (4, 'suggestions'), (5, 'Overall')], default=5, null=True, verbose_name='Review'),
        ),
    ]
