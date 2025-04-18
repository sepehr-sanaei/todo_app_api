"""
Serializers for user APIs.
"""
from rest_framework import serializers

from django.contrib.auth import (
    get_user_model,
    authenticate,
)

from django.utils.translation import gettext_lazy as _


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user model."""
    class Meta:
        model = get_user_model()
        fields = ['email', 'password', 'name']
        extra_kwargs = {
            'password': {'write_only': True, 'min_length': 5}
        }

    def create(self, validated_data):
        """Create and return user with encrypted password"""
        return get_user_model().objects.create_user(**validated_data)

    def update(self, instance, validated_data):
        password = validated_data.pop('password')
        user = super().update(instance, validated_data)

        if password:
            user.set_password(password)
            user.save()
        return user


class AuthTokenSerializer(serializers.Serializer):
    """Serializer for authentication token."""
    email = serializers.EmailField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        """Validate and authenticate the user."""
        email = attrs.get('email')
        password = attrs.get('password')
        user = authenticate(
            request=self.context.get('request'),
            username=email,
            password=password,
        )
        if not user:
            msg = _("Unable to authenticate with provided credentials")
            raise serializers.ValidationError(msg, code="authorization")

        attrs['user'] = user
        return attrs


class OTPSendSerializer(serializers.Serializer):
    """Serializer for sending email."""
    email = serializers.EmailField()


class OTPVerifySerializer(serializers.Serializer):
    """Serializer for verifying OTP."""
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, trim_whitespace=True)


class UserRegistrationSerializer(serializers.Serializer):
    """Serializer for initial registration step"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=5)
    name = serializers.CharField(max_length=255)

    def validate_email(self, value):
        """Validate Email."""
        if get_user_model().objects.filter(email=value).exists():
            raise serializers.ValidationError(
                'User with this email already exists.'
            )
        return value
