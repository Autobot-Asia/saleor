# Generated by Django 3.1.7 on 2021-05-29 04:01

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0002_auto_20210513_1002'),
        ('product', '0144_product_store'),
    ]

    operations = [
        migrations.AddField(
            model_name='category',
            name='store',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='categories', to='store.store'),
        ),
        migrations.AddField(
            model_name='collection',
            name='store',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='collections', to='store.store'),
        ),
        migrations.AddField(
            model_name='digitalcontent',
            name='store',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='digital_contents', to='store.store'),
        ),
        migrations.AddField(
            model_name='producttype',
            name='store',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='product_types', to='store.store'),
        ),
        migrations.AddField(
            model_name='productvariant',
            name='store',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='variants', to='store.store'),
        ),
    ]