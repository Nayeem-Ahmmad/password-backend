from rest_framework import serializers
from .models import VaultEntry


class VaultEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = VaultEntry
        fields = ['id', 'name', 'encoded_password', 'created_at']
        read_only_fields = ['id', 'encoded_password', 'created_at']


class EncodeRequestSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    password = serializers.CharField(write_only=True)


class DecodeRequestSerializer(serializers.Serializer):
    encoded_password = serializers.CharField()
    master_key = serializers.CharField(write_only=True)


class SetupRequestSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    master_key = serializers.CharField(write_only=True)


class LoginRequestSerializer(serializers.Serializer):
    master_key = serializers.CharField(write_only=True)


class ResetKeyRequestSerializer(serializers.Serializer):
    new_master_key = serializers.CharField(write_only=True)