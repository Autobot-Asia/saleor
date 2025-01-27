# Generated by Django 3.1.7 on 2021-05-10 07:38

import django.contrib.postgres.indexes
import django.contrib.postgres.search
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import saleor.core.db.fields
import saleor.core.utils.editorjs
import saleor.core.utils.json_serializer
import versatileimagefield.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('store', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Post',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('private_metadata', models.JSONField(blank=True, default=dict, encoder=saleor.core.utils.json_serializer.CustomJsonEncoder, null=True)),
                ('metadata', models.JSONField(blank=True, default=dict, encoder=saleor.core.utils.json_serializer.CustomJsonEncoder, null=True)),
                ('seo_title', models.CharField(blank=True, max_length=70, null=True, validators=[django.core.validators.MaxLengthValidator(70)])),
                ('seo_description', models.CharField(blank=True, max_length=300, null=True, validators=[django.core.validators.MaxLengthValidator(300)])),
                ('title', models.CharField(max_length=250)),
                ('content', saleor.core.db.fields.SanitizedJSONField(blank=True, null=True, sanitizer=saleor.core.utils.editorjs.clean_editor_js)),
                ('search_vector', django.contrib.postgres.search.SearchVectorField(blank=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('store', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='posts', to='store.store')),
            ],
            options={
                'ordering': ('pk',),
                'permissions': (('manage_posts', 'Manage store post.'),),
            },
        ),
        migrations.CreateModel(
            name='PostMedia',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sort_order', models.IntegerField(db_index=True, editable=False, null=True)),
                ('image', versatileimagefield.fields.VersatileImageField(blank=True, null=True, upload_to='post')),
                ('ppoi', versatileimagefield.fields.PPOIField(default='0.5x0.5', editable=False, max_length=20)),
                ('alt', models.CharField(blank=True, max_length=128)),
                ('type', models.CharField(choices=[('IMAGE', 'An uploaded image or an URL to an image'), ('VIDEO', 'A URL to an external video')], default='IMAGE', max_length=32)),
                ('post', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='media', to='post.post')),
            ],
            options={
                'ordering': ('sort_order', 'pk'),
            },
        ),
        migrations.CreateModel(
            name='PostTranslation',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('seo_title', models.CharField(blank=True, max_length=70, null=True, validators=[django.core.validators.MaxLengthValidator(70)])),
                ('seo_description', models.CharField(blank=True, max_length=300, null=True, validators=[django.core.validators.MaxLengthValidator(300)])),
                ('language_code', models.CharField(max_length=10)),
                ('name', models.CharField(max_length=250)),
                ('description', saleor.core.db.fields.SanitizedJSONField(blank=True, null=True, sanitizer=saleor.core.utils.editorjs.clean_editor_js)),
                ('post', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='translations', to='post.post')),
            ],
            options={
                'unique_together': {('language_code', 'post')},
            },
        ),
        migrations.AddIndex(
            model_name='post',
            index=django.contrib.postgres.indexes.GinIndex(fields=['search_vector'], name='post_post_search__afdb24_gin'),
        ),
        migrations.AddIndex(
            model_name='post',
            index=django.contrib.postgres.indexes.GinIndex(fields=['private_metadata'], name='post_p_meta_idx'),
        ),
        migrations.AddIndex(
            model_name='post',
            index=django.contrib.postgres.indexes.GinIndex(fields=['metadata'], name='post_meta_idx'),
        ),
    ]
