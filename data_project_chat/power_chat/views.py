from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect

from chats.models import UserProfile
from .models import PowerChatMessage
from .power_model import create_conversation, get_answer

@login_required
def power_chat(request):
    user = UserProfile.objects.filter(id = request.user.id).get()
    requests = [request_ for request_ in PowerChatMessage.objects.filter(user_id=user.id).all()]

    if request.method == "POST":
        question = request.POST["text"]
        answer = get_answer(create_conversation(), question)
        request_ = PowerChatMessage(user_id = user.id, question = question, answer = answer)
        requests.append(request_)
        request_.save()

    return render(request, 'power_chat/chat_interaction.html', {'requests': requests})