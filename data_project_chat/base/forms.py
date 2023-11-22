from django import forms
from django.contrib.auth.forms import UserChangeForm
from .models import UserProfile
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.forms import UserCreationForm



class ExtendedUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True, help_text="Enter a valid email address.")

    class Meta:
        model = User
        fields = ["username", "email", "password1", "password2"]

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("A user with this email already exists.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()

            UserProfile.objects.create(user=user, email=user.email)

        return user


class UserProfileForm(UserChangeForm):
    class Meta:
        model = UserProfile
        fields = ["email", "username", "first_name"]

    first_name = forms.CharField(required=False)


class EmailAuthenticationForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs['placeholder'] = 'Enter email'
        self.fields['username'].label = 'Email'

