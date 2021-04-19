# Generated by Django 3.1.7 on 2021-04-19 08:12

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0002_auto_20210419_1512'),
        ('account', '0048_auto_20210308_1135'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='store',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='users', to='store.store'),
        ),
    ]
