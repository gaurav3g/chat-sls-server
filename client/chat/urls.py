from django.urls import path
from . import views

urlpatterns = [
    path('send/', views.send, name="send"),
    path('', views.index, name="index")
]