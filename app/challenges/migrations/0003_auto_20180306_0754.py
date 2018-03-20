# Generated by Django 2.0.2 on 2018-03-06 07:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('challenges', '0002_challenge_is_ovh_chall'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='challenge',
            name='nb_points',
        ),
        migrations.AddField(
            model_name='challenge',
            name='difficulty',
            field=models.IntegerField(choices=[(0, 'Trivial'), (1, 'Easy'), (2, 'Medium'), (3, 'Hard'), (4, 'Genius Level')], default=2),
        ),
        migrations.AlterField(
            model_name='ctfsettings',
            name='state',
            field=models.CharField(choices=[('NST', 'Not started'), ('STA', 'Globally started'), ('OSE', 'On site end'), ('OLE', 'Online end')], default='NST', max_length=3),
        ),
    ]