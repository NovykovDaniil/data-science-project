from django.urls import path
from . import views

urlpatterns = [
    path('hug_chat/', views.power_chat, name='power_chat'),
]