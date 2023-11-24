from django.db import models

from chats.models import UserProfile


class PowerChatMessage(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='power_messages',
        null=True
    )
    question = models.CharField(max_length=512)
    answer = models.CharField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
