from django.urls import path

from . import views

urlpatterns = [
    path('create-user', views.create_user),
    path('login', views.login),
    path('logout', views.logout),
    path('get-refresh-token', views.get_refresh_token)
]
