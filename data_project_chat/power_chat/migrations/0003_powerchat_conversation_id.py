# Generated by Django 4.2.1 on 2023-11-19 14:49

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        (
            "power_chat",
            "0002_remove_powerchat_answer_remove_powerchat_question_and_more",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="powerchat",
            name="conversation_id",
            field=models.CharField(max_length=512, null=True),
        ),
    ]
