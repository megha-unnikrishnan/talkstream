# myapp/serializers.py
from datetime import date
from django.conf import settings
from rest_framework import serializers
from .models import CustomUser
from .utils import email_verification_token
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.exceptions import AuthenticationFailed
from django.core.mail import EmailMultiAlternatives
import logging
from django.core.mail import send_mail
from rest_framework.decorators import api_view

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate, update_session_auth_hash

logger = logging.getLogger(__name__)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = fields = ('id', 'username', 'first_name', 'email', 'bio', 'dob', 'mobile', 'profile_picture', 'cover_picture', 'created_at', 'updated_at', 'password','is_suspended','is_active')
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = fields = ('id', 'username', 'first_name',  'email','bio', 'dob', 'mobile','profile_picture', 'cover_picture')
    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.email = validated_data.get('email', instance.email)
        instance.bio = validated_data.get('bio', instance.bio)
        instance.dob = validated_data.get('dob', instance.dob)
        instance.mobile = validated_data.get('mobile', instance.mobile)
        instance.save()
        return instance



class UpdatePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def validate(self, data):
        user = self.context['request'].user
        
        # Check if old password is correct
        if not user.check_password(data['old_password']):
            raise serializers.ValidationError("Old password is incorrect.")
        
        # Check if new passwords match
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("New passwords do not match.")
        
        return data
class AdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'first_name', 'email', 'created_at', 'is_suspended']

class GoogleLoginSerializer(serializers.Serializer):
        idToken = serializers.CharField()

# class BlockUserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = CustomUser
#         fields = ['id', 'is_suspended']
    
#     def update(self, instance, validated_data):
#         instance.is_suspended = True
#         instance.save()
#         return instance

# class UnblockUserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = CustomUser
#         fields = ['id', 'is_suspended']
    
#     def update(self, instance, validated_data):
#         instance.is_suspended = False
#         instance.save()
#         return instance

class BlockUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['is_suspended', 'is_active']

    def update(self, instance, validated_data):
        instance.is_suspended = validated_data.get('is_suspended', instance.is_suspended)
        instance.is_active = False  # Set is_active to False when blocking
        instance.save()
        return instance

class UnblockUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['is_suspended', 'is_active']

    def update(self, instance, validated_data):
        instance.is_suspended = validated_data.get('is_suspended', instance.is_suspended)
        instance.is_active = True  # Set is_active to True when unblocking
        instance.save()
        return instance

class PasswordResetSerializer(serializers.Serializer):
    token = serializers.CharField()  # Token for password reset
    password = serializers.CharField(min_length=8, write_only=True)  # New password

    def validate(self, data):
        token = data.get('token')
        password = data.get('password')

        if not token or not password:
            raise serializers.ValidationError("Token and password are required.")

        user = self.get_user_from_token(token)
        if not user or not default_token_generator.check_token(user, token):
            raise serializers.ValidationError("Invalid or expired token")

        return data

    def get_user_from_token(self, token):
        # Since token doesn't contain user info directly, return None if token validation fails
        for user in CustomUser.objects.all():
            if default_token_generator.check_token(user, token):
                return user
        return None






class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'first_name', 'email', 'bio', 'dob', 'mobile', 'profile_picture', 'cover_picture', 'created_at', 'updated_at', 'password')
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def validate_username(self, value):
        if CustomUser.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists")
        return value

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists")
        return value

    def validate_mobile(self, value):
        if CustomUser.objects.filter(mobile=value).exists():
            raise serializers.ValidationError("User with this mobile number already exists.")
        return value

    def validate_dob(self, value):
        if value > date.today():
            raise serializers.ValidationError("Date of birth cannot be in the future.")
        return value

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        profile_picture = validated_data.pop('profile_picture', None)
        cover_picture = validated_data.pop('cover_picture', None)

        user = CustomUser.objects.create(**validated_data)
        user.is_active = False 

        if password:
            user.set_password(password)
        if profile_picture:
            user.profile_picture = profile_picture
        if cover_picture:
            user.cover_picture = cover_picture

        user.save()

        self.send_verification_email(user)

        return user
    
    def send_verification_email(self, user):
        token = email_verification_token.make_token(user)
        
        # Define your frontend base URL
        frontend_base_url = 'http://localhost:3000'  # Replace with your actual frontend URL
        
        # Build the verification URL for the frontend
        verification_url = f"{frontend_base_url}/verify-email/{user.id}/{token}/"
        
        subject = 'Verify your email address'
        message = f'Hi {user.first_name},\n\nPlease verify your email address by clicking the link below:\n{verification_url}\n\nThank you!'
        
        send_mail(
            subject,
            message,
            'noreply@yourdomain.com',
            [user.email],
            fail_silently=False,
        )

    class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
        def validate(self, attrs):
            data = super().validate(attrs)
            user = self.user

            if not user.is_active:
                raise AuthenticationFailed("Your email is not verified. Please verify your email.")

            data['userId'] = user.id
            return data
    