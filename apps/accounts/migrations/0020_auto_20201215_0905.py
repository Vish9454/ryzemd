# Generated by Django 2.1 on 2020-12-15 09:05

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0019_auto_20201214_1239'),
    ]

    operations = [
        migrations.CreateModel(
            name='RatingDocAndApp',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Last Updated At')),
                ('review', models.CharField(blank=True, choices=[(1, 'mobile_doctor'), (2, 'video_consult'), (3, 'hub_visit'), (4, 'suggestions'), (5, 'Overall')], default=5, max_length=400, null=True, verbose_name='Review')),
                ('rating', models.DecimalField(decimal_places=1, default=0.0, max_digits=5)),
                ('is_completed', models.BooleanField(default=False)),
                ('doctor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='user_doctor', to=settings.AUTH_USER_MODEL)),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_patient', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'BaseModel',
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='ticket',
            name='new_text',
            field=models.CharField(blank=True, max_length=255),
        ),
    ]
