"""
Views for user APIs.
"""
from rest_framework import generics, status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.settings import api_settings
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from django.contrib.auth import get_user_model
from django.core.signing import Signer, BadSignature


from user.tasks import send_otp_email
from core.models import OTP

from user.serializers import (
    UserSerializer,
    AuthTokenSerializer,
    OTPSendSerializer,
    OTPVerifySerializer,
    UserRegistrationSerializer
)

import pyotp


class UserRegistrationInitView(generics.GenericAPIView):
    """View for creating a user - Step 1."""
    serializer_class = UserRegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Normalize email to lowercase
        email = serializer.validated_data['email'].lower()
        password = serializer.validated_data['password']
        name = serializer.validated_data['name']

        # Generate OTP
        totp = pyotp.TOTP(pyotp.random_base32(), digits=6, interval=300)
        otp_code = totp.now()

        # Sign data
        signer = Signer()
        signed_data = signer.sign_object({
            'email': email,
            'password': password,
            'name': name
        })

        # Invalidate previous OTPs and create new one
        OTP.objects.filter(email=email).update(is_used=True)
        OTP.objects.create(
            email=email,
            otp=otp_code,
            signed_data=signed_data
        )

        # Send email
        send_otp_email(email, otp_code)

        return Response(
            {
                'detail':
                '''
                    OTP sent to email. Please verify to complete registration.
                '''
            },
            status=status.HTTP_200_OK
        )


class UserRegistrationVerifyView(generics.GenericAPIView):
    """Second step - verify OTP and create user"""
    serializer_class = OTPVerifySerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email'].lower()
        otp_code = serializer.validated_data['otp'].strip()  # Clean whitespace

        try:
            # Get the most recent OTP for this email
            otp_record = OTP.objects.filter(
                email=email,
                is_used=False
            ).latest('created_at')
        except OTP.DoesNotExist:
            return Response(  # Ensure return here
                {'detail': 'Invalid OTP or email'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Verify OTP code match
        if otp_record.otp != otp_code:
            return Response(  # Ensure return here
                {'detail': 'Invalid OTP'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check expiration
        if not otp_record.is_valid():
            otp_record.is_used = True
            otp_record.save()
            return Response(  # Ensure return here
                {'detail': 'OTP has expired'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Verify signed data
        try:
            signer = Signer()
            user_data = signer.unsign_object(otp_record.signed_data)
        except BadSignature:
            return Response(  # Ensure return here
                {'detail': 'Invalid registration data'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create user
        try:
            User = get_user_model()
            user = User.objects.create_user(
                email=user_data['email'],
                password=user_data['password'],
                name=user_data['name'],
                is_verified=True
            )
        except KeyError as e:
            return Response(
                {'detail': f'Missing field in registration data: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Mark OTP as used
        otp_record.is_used = True
        otp_record.save()

        # Generate auth token
        token, created = Token.objects.get_or_create(user=user)

        return Response({  # Final return statement
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        }, status=status.HTTP_201_CREATED)


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


class OTPSendApiView(generics.GenericAPIView):
    """View for sending OTP."""
    serializer_class = OTPSendSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        User = get_user_model()

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {'detail': 'User with email does not exists'},
                status=status.HTTP_404_NOT_FOUND
            )

        # generate OTP
        totp = pyotp.TOTP(pyotp.random_base32(), digits=6, interval=300)
        otp_code = totp.now()

        # Create and save OTP
        OTP.objects.filter(user=user).update(is_used=True)
        OTP.objects.create(user=user, otp=otp_code)

        # send otp via celery task
        send_otp_email(user.email, otp_code)

        return Response(
            {'detail': 'OTP has been sent to your email'},
            status=status.HTTP_200_OK
        )


class OTPVerifyApiView(generics.GenericAPIView):
    """View for verifying OTP."""
    serializer_class = OTPVerifySerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        otp_code = serializer.validated_data['otp']

        User = get_user_model()

        try:
            user = User.objects.get(email=email)
            otp = OTP.objects.filter(
                user=user, is_used=False
            ).latest('created_at')
        except (User.DoesNotExist, OTP.DoesNotExist):
            return Response(
                {'detail': 'Invalid OTP or User'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not otp.is_valid() or otp.otp != otp_code:
            return Response(
                {'detail': 'Invalid or Expired OTP'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Mark OTP as used
        otp.is_used = True
        otp.save()

        user.is_verified = True
        user.save()

        # Generate or get authToken
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        })
