"""
Tests for task APIs.
"""
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from core.models import Task

from task.serializers import (
    TaskSerializer,
    TaskDetailSerializer
)


TASK_URL = reverse('task:task-list')


def detail_url(task_id):
    """Generate and return task detail url."""
    return reverse('task:task-detail', args=[task_id])


def create_task(user, **params):
    """Create, save and return a new task."""
    default = {
        'title': 'Sample Title',
        'description': 'Sample Task Description'
    }
    default.update(params)

    task = Task.objects.create(user=user, **default)
    return task


def create_user(**params):
    """Create and return a new user."""
    return get_user_model().objects.create_user(**params)


class PublicTaskApiTests(TestCase):
    """Test Public Features of Task API."""
    def setUp(self):
        self.client = APIClient()

    def test_retrieve_tasks(self):
        """Test retrieve tasks for unauthenticated users."""
        res = self.client.get(TASK_URL)

        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


class PrivateTaskApiTests(TestCase):
    """Test Private Features of Task API."""
    def setUp(self):
        self.client = APIClient()
        self.user = create_user(
            email='test@example.com',
            password='testpass123',
            name='Test Name'
        )
        self.client.force_authenticate(user=self.user)

    def test_retrieve_tasks(self):
        """Test retrieving tasks for authenticated user."""
        create_task(user=self.user)
        create_task(user=self.user)
        res = self.client.get(TASK_URL)

        tasks = Task.objects.all().order_by('-id')
        serializer = TaskSerializer(tasks, many=True)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data, serializer.data)

    def test_retrieve_task_limited_to_user(self):
        """Test the retrieved data is limited to user."""
        new_user = create_user(
            email='newuser@example.com',
            password='testpass123',
            name='New User'
        )
        create_task(user=self.user)
        create_task(user=new_user)

        res = self.client.get(TASK_URL)

        tasks = Task.objects.filter(user=self.user)
        serializer = TaskSerializer(tasks, many=True)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data, serializer.data)

    def test_get_task_detail(self):
        """Test getting recipe detail."""
        task = create_task(user=self.user)
        url = detail_url(task.id)
        res = self.client.get(url)

        serializer = TaskDetailSerializer(task)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data, serializer.data)

    def test_create_task(self):
        """Test creating a task using API."""
        payload = {
            'title': 'Sample Title',
            'description': 'Sample description'
        }

        res = self.client.post(TASK_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        task = Task.objects.get(id=res.data['id'])
        for k, v in payload.items():
            self.assertEqual(getattr(task, k), v)
        self.assertEqual(task.user, self.user)

    def test_task_partial_update(self):
        """Test a patch on task API."""
        task = create_task(user=self.user)
        payload = {
            'title': 'New Title'
        }
        url = detail_url(task.id)
        res = self.client.patch(url, payload)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        task.refresh_from_db()
        self.assertEqual(task.title, payload['title'])
        self.assertEqual(task.user, self.user)

    def test_task_full_update(self):
        """Test a full Update (put) on Task."""
        task = create_task(user=self.user)
        payload = {
            'title': 'New Title',
            'description': 'New Description',
            'is_completed': True
        }
        url = detail_url(task.id)
        res = self.client.put(url, payload)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        task.refresh_from_db()
        for k, v in payload.items():
            self.assertEqual(getattr(task, k), v)
        self.assertEqual(task.user, self.user)

    def test_change_user_raise_error(self):
        """Test changing the user raises an error."""
        task = create_task(user=self.user)
        new_user = create_user(
            email='new@example.com',
            password='testpass123',
            name='Test Name'
        )
        payload = {
            'user': new_user
        }
        url = detail_url(task.id)
        self.client.patch(url, payload)
        task.refresh_from_db()
        self.assertEqual(task.user, self.user)

    def test_task_delete(self):
        """Test deleting a task."""
        task = create_task(user=self.user)
        url = detail_url(task.id)
        res = self.client.delete(url)

        self.assertEqual(res.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Task.objects.filter(id=task.id).exists())

    def test_change_other_user_task(self):
        """Test changing other user's task."""
        new_user = create_user(
            email='new@example.com',
            password='testpass123',
            name='Test Name'
        )
        create_task(user=self.user)
        task = create_task(user=new_user)
        payload = {
            'title': 'New Title'
        }
        url = detail_url(task.id)
        res = self.client.patch(url, payload)
        self.assertEqual(res.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(task.title, 'Sample Title')
