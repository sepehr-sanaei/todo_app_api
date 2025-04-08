"""
Views for Task APIs.
"""

from rest_framework import viewsets
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

from core.models import Task

from task.serializers import (
    TaskSerializer,
    TaskDetailSerializer
)


class TaskViewSet(viewsets.ModelViewSet):
    """Views for managing task APIs."""
    serializer_class = TaskDetailSerializer
    queryset = Task.objects.all()
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = self.queryset
        return queryset.filter(
            user=self.request.user
        ).order_by('-id').distinct()

    def get_serializer_class(self):
        if self.action == 'list':
            return TaskSerializer
        return self.serializer_class
