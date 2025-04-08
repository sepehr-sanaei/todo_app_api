"""
Serializers for Task APIs.
"""
from rest_framework import serializers

from core.models import Task


class TaskSerializer(serializers.ModelSerializer):
    """Serializer for Task model."""

    class Meta:
        model = Task
        fields = ['id', 'title', 'is_completed']
        read_only_fields = ['id']

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return Task.objects.create(**validated_data)


class TaskDetailSerializer(TaskSerializer):
    """Serializer for task's detail."""

    class Meta(TaskSerializer.Meta):
        fields = TaskSerializer.Meta.fields + ['description']
