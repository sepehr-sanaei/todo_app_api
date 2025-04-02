"""
URL mappings for user APIs.
"""
from django.urls import path

from user import views


app_name = 'user'

urlpatterns = [
    path('create/', views.UserCreateAPIView.as_view(), name='create'),
    path('token/', views.AuthTokenAPIView.as_view(), name='token'),
    path('me/', views.ManageUserAPIView.as_view(), name='me'),
]