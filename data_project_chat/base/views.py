import logging

from pathlib import Path
from django import forms
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash

from .models import UserProfile
from .forms import UserProfileForm

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
    return render(request, 'base/index.html', {})
    
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
            return render(request, 'base/registration.html', {'form': form, 'error': 'Make sure that your passwords match and the nickname is not occupied'})
    else:
        form = ExtendedUserCreationForm()

    return render(request, 'base/registration.html', {'form': form})


def user_login(request):
    global image_list
    if request.method == 'GET':
        return render(request, 'base/login.html', {'form': AuthenticationForm()})
    else:
        user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            return render(request, 'base/login.html',
                          {'form': AuthenticationForm(), 'error': 'Username or password didn\'t match'})
        login(request, user)
        return redirect('/')


