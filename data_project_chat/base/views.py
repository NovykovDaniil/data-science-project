import os
import logging

from pathlib import Path
from django import forms
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import HttpResponse
from django.contrib.auth import update_session_auth_hash

from .models import UserProfile
from .forms import UserProfileForm
from chats.models import Chat, File
from chats.data_extractor import read_file
from chats.qa_model import QAModel

logger = logging.getLogger(__name__)

@login_required(login_url="/")
def edit_profile(request):
    if request.method == "POST":
        form = UserProfileForm(request.POST, instance=request.user.userprofile)
        if form.is_valid():
            try:
                user_profile = form.save()

                update_session_auth_hash(request, request.user)

                request.user.username = user_profile.username
                request.user.save()

                return redirect("/")
            except Exception as e:
                logger.error(f"Error saving profile: {e}")
        else:
            logger.error(f"Form is invalid: {form.errors}")

    else:
        form = UserProfileForm(instance=request.user.userprofile)

    return render(request, "base/edit_profile.html", {"form": form})


@login_required(login_url='/')
def deactivate_account(request):
    if request.method == 'POST':
        request.user.delete()
        messages.success(request, 'Your account has been deactivated successfully.')
        return redirect('user_logout')

    return render(request, 'base/deactivate_account.html')



BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = Path('temp/')
file_list = []  

def main(request):
    if request.method == 'POST' and request.FILES.getlist('myfile'):
        files = request.FILES.getlist('myfile')
        user = UserProfile.objects.filter(id = request.user.id).get()
        chat = Chat(user=user)
        chat.save()
        text = ''
        for file in files:
            if file is not None:
                if file.content_type in ['application/pdf', 'application/msword',
                                         'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                                         'text/plain']:
                    text += read_file(file)
                    new_file = File(filename=file.name, chat=chat)
                    new_file.save()
        model = QAModel(chat.id, text)
        answer = model.get_answer('Що таке Київ?')
        return HttpResponse(answer, content_type='text/html')

    return render(request, 'base/index2.html', {})
    
@login_required
def user_logout(request):
    logout(request)
    return redirect('/')

class ExtendedUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True, help_text='Enter a valid email address.')

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        email = cleaned_data.get('email')

        if User.objects.filter(username=username).exists():
            raise forms.ValidationError('This username is already taken.')

        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('This email address is already in use.')

        return cleaned_data




def user_signup(request):
    if request.method == 'POST':
        form = ExtendedUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()

            UserProfile.objects.create(user=user, email=form.cleaned_data['email'])

            login(request, user)
            return redirect('/')
        else:
            return render(request, 'base/registration2.html', {'form': form, 'error': 'Make sure that your passwords match and the nickname is not occupied'})
    else:
        form = ExtendedUserCreationForm()

    return render(request, 'base/registration2.html', {'form': form})


def user_login(request):
    global image_list
    if request.method == 'GET':
        return render(request, 'base/login2.html', {'form': AuthenticationForm()})
    else:
        user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            return render(request, 'base/login2.html',
                          {'form': AuthenticationForm(), 'error': 'Username or password didn\'t match'})
        login(request, user)
        return redirect('/')


