# Generated by Django 3.1.7 on 2021-05-06 12:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0002_auto_20210419_1512'),
    ]

    operations = [
        migrations.AlterField(
            model_name='store',
            name='acreage',
            field=models.FloatField(blank=True, max_length=250, null=True),
        ),
        migrations.AlterField(
            model_name='store',
            name='background_image_alt',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
        migrations.AlterField(
            model_name='store',
            name='latlong',
            field=models.CharField(blank=True, max_length=250, null=True),
        ),
    ]