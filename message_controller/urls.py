from django.urls import path

from . import views

urlpatterns = [
    path('get-snapshots', views.get_snapshots),
    path('get-client-snapshot/<str:mobile_number>', views.get_client_snapshot),
    path('post-snapshot', views.post_snapshot)
]
