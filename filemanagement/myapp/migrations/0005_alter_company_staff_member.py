# Generated by Django 4.2.7 on 2023-11-05 11:25

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0004_file_company_staff_address_staff_phone_number'),
    ]

    operations = [
        migrations.AlterField(
            model_name='company',
            name='staff_member',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='company', to='myapp.staff'),
        ),
    ]
