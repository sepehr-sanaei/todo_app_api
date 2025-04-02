"""
Views for user APIs.
"""
from rest_framework import generics
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_settings
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

from user.serializers import (
    UserSerializer,
    AuthTokenSerializer,
)


class UserCreateAPIView(generics.CreateAPIView):
    """View for creating a new user."""
    serializer_class = UserSerializer


class AuthTokenAPIView(ObtainAuthToken):
    """View for creating authtoken for a user."""
    serializer_class = AuthTokenSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES


class ManageUserAPIView(generics.RetrieveUpdateAPIView):
    """Manage authenticated user."""
    serializer_class = UserSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self):
        """Retrieve and return authenticated user."""
        return self.request.user
