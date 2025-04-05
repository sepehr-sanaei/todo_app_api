"""
Tests for user APIs.
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse

from rest_framework.test import APIClient
from rest_framework import status

from unittest.mock import patch

from core.models import OTP


CREATE_USER_API = reverse('user:create')
TOKEN_URL = reverse('user:token')
ME_URL = reverse('user:me')
CREATE_USER_API = reverse('user:create')
VERIFY_USER_API = reverse('user:verify-registration')


def create_user(**params):
    return get_user_model().objects.create_user(**params)


@patch('user.tasks.send_otp_email')
@patch('random.randint')
def test_create_user_success(self, mock_send_otp, mock_randint):
    """Test creating user with api is successful."""

    mock_randint.side_effect = [1, 2, 3, 4, 5, 6]

    init_res = self.client.post(CREATE_USER_API, self.payload)
    self.assertEqual(init_res.status_code, status.HTTP_200_OK)
    self.assertEqual(
        init_res.data['detail'],
        'OTP sent to email. Please verify to complete registration.'
    )

    otp = OTP.objects.get(email=self.payload['email'])
    print(f"Generated OTP: {otp.otp}")
    self.assertEqual(otp.otp, '123456')
    self.assertFalse(otp.is_used)

    verify_payload = {
        'email': self.payload['email'],
        'otp': '123456'
    }
    verify_res = self.client.post(VERIFY_USER_API, verify_payload)

    self.assertEqual(verify_res.status_code, status.HTTP_201_CREATED)
    user = get_user_model().objects.get(email=self.payload['email'])
    self.assertTrue(user.check_password(self.payload['password']))
    self.assertNotIn('password', verify_res.data)
    self.assertTrue(user.is_verified)

    # Verify OTP was marked as used
    otp.refresh_from_db()
    self.assertTrue(otp.is_used)

    def test_user_with_email_exists_error(self):
        """Test that creating user with used email raises error"""
        payload = {
            'email': 'test@example.com',
            'password': 'testpass1234',
            'name': 'Test Name'
        }
        create_user(**payload)
        res = self.client.post(CREATE_USER_API, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_too_short_error(self):
        """Test that creating a user with short password raises error."""
        payload = {
            'email': 'test@example.com',
            'password': '123',
            'name': 'Test Name'
        }
        res = self.client.post(CREATE_USER_API, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        user_exists = get_user_model().objects.filter(
            email=payload['email']
        ).exists()
        self.assertFalse(user_exists)

    def test_create_token_for_user(self):
        """Test creating a token authentication for user."""
        user_details = {
            'email': 'test@example.com',
            'password': 'Testpass123',
            'name': 'Test Name'
        }

        create_user(**user_details)
        payload = {
            'email': user_details['email'],
            'password': user_details['password']
        }
        res = self.client.post(TOKEN_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('token', res.data)

    def test_create_token_with_bad_credentials(self):
        """Test creating a token for a user with bad credentials."""
        create_user(email='test@example.com', password='goodpass')
        payload = {
            'email': 'test@example.com',
            'password': 'badpass'
        }
        res = self.client.post(TOKEN_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotIn('token', res.data)

    def test_create_token_with_blank_password(self):
        """Test creating a token for a user with blank password."""
        payload = {
            'email': 'test@example.com',
            'password': ''
        }
        res = self.client.post(TOKEN_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotIn('token', res.data)

    def test_retrieve_me_yrl_unauthorized(self):
        """Test retrieving data from me url with no authorization."""
        res = self.client.get(ME_URL)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


class PrivateUserApiTests(TestCase):
    """Test features of user API that requires authentication."""
    def setUp(self):
        self.client = APIClient()
        self.user = create_user(
            email='test@example.com',
            password='testpass123',
            name='Test Name'
        )
        self.client.force_authenticate(user=self.user)

    def test_retrieve_profile_success(self):
        """Test retrieving profile is successful."""
        res = self.client.get(ME_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data, {
            'email': self.user.email,
            'name': self.user.name
        })

    def test_post_me_not_allowed(self):
        """Test post method is now allowed to me url."""
        res = self.client.post(ME_URL, {})

        self.assertEqual(res.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_update_user_profile(self):
        """Test updating user profile."""
        payload = {
            'name': "Test Name",
            'password': 'newpass123'
        }
        res = self.client.patch(ME_URL, payload)

        self.user.refresh_from_db()
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.name, payload['name'])
        self.assertTrue(self.user.check_password(payload['password']))
