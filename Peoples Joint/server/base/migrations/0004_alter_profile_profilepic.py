# Generated by Django 4.0 on 2022-11-19 09:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0003_alter_blog_file'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='profilePic',
            field=models.ImageField(blank=True, default='profilePic/default.jpg', upload_to=''),
        ),
    ]
