# Generated by Django 4.0 on 2022-12-04 11:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0016_alter_profile_followers_alter_profile_following'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='interests',
            field=models.ManyToManyField(blank=True, related_name='interests', to='base.Interest'),
        ),
    ]