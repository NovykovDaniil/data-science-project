from django.urls import path
from . import views
from .views import deactivate_account, edit_profile

urlpatterns = [
    path('', views.main, name='main'),
    path('signup/', views.user_signup, name='user_signup'),
    path('login/', views.user_login, name='user_login'),
    path('logout/', views.user_logout, name='user_logout'),
    path('deactivate_account/', deactivate_account, name='deactivate_account'),
    path('edit_profile/', edit_profile, name='edit_profile'),
]
