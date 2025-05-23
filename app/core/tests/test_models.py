"""
Test for models.
"""
from django.test import TestCase
from django.contrib.auth import get_user_model

from core.models import Task


class ModelTest(TestCase):
    """Test for models."""

    def test_user_create_with_email_successful(self):
        """Test that creating a user with email is successful."""

        email = 'test@example.com'
        password = 'testpass123'
        user = get_user_model().objects.create_user(
            email=email,
            password=password
        )

        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))

    def test_new_user_email_normalized(self):
        """Test if new user's email is being normalized."""
        sample_emails = [
            ['test1@EXAMPLE.com', 'test1@example.com'],
            ['Test2@EXAMPLE.com', 'Test2@example.com'],
            ['TEST3@Example.com', 'TEST3@example.com'],
            ['test4@example.com', 'test4@example.com']
        ]

        for email, expected in sample_emails:
            user = get_user_model().objects.create_user(email, 'passtest123')
            self.assertEqual(user.email, expected)

    def test_new_user_without_email_raises_error(self):
        """Test that creating a new user without email raises an error."""
        with self.assertRaises(ValueError):
            get_user_model().objects.create_user('', 'testpass123')

    def test_create_super_user(self):
        """test creating a super user."""
        user = get_user_model().objects.create_superuser(
            'test@example.com',
            'testpass123'
        )
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)

    def test_create_task(self):
        """Test creating a task."""
        user = get_user_model().objects.create_user(
            email='test@example.com',
            password='testpass123',
            name='Test Name'
        )
        task = Task.objects.create(
            user=user,
            title='Sample Title',
            description='Sample Task Description'
        )

        self.assertEqual(str(task), task.title)
