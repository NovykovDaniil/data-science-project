# Generated by Django 4.2.1 on 2023-11-19 15:08

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("power_chat", "0005_alter_powerchatmessage_user"),
    ]

    operations = [
        migrations.AlterField(
            model_name="powerchatmessage",
            name="answer",
            field=models.CharField(null=True),
        ),
    ]