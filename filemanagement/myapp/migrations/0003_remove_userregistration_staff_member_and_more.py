# Generated by Django 4.2.7 on 2023-11-05 09:40

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0002_userregistration_staff_member_file_company'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userregistration',
            name='staff_member',
        ),
        migrations.AlterField(
            model_name='userregistration',
            name='group',
            field=models.CharField(choices=[('owner', 'Owner'), ('staff', 'Staff')], max_length=10),
        ),
        migrations.CreateModel(
            name='Staff',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AlterField(
            model_name='company',
            name='staff_member',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='company', to='myapp.staff'),
        ),
        migrations.AlterField(
            model_name='file',
            name='file_owner',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='files', to='myapp.staff'),
        ),
    ]
