# Generated by Django 4.0 on 2022-11-28 13:56

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0010_rename_choice_interest_name'),
    ]

    operations = [
        migrations.RenameField(
            model_name='profile',
            old_name='iterests',
            new_name='interests',
        ),
    ]