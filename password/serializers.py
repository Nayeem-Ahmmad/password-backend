from rest_framework import serializers
from .models import VaultEntry, normalize_answer, normalize_name


def validate_secrets(name, master_key, question, answer):
    if len(master_key) < 8:
        raise serializers.ValidationError({'master_key': ['Master key must be at least 8 characters.']})
    if normalize_name(master_key) == normalize_name(name):
        raise serializers.ValidationError({'master_key': ['Master key must be different from your name.']})
    if not question.strip():
        raise serializers.ValidationError({'recovery_question': ['Choose a recovery question.']})
    if len(normalize_answer(answer)) < 3:
        raise serializers.ValidationError({'recovery_answer': ['Recovery answer must be at least 3 characters.']})
    if normalize_answer(answer) == normalize_answer(master_key):
        raise serializers.ValidationError({'recovery_answer': ['Recovery answer must be different from the master key.']})


class VaultEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = VaultEntry
        fields = ['id', 'name', 'encoded_password', 'created_at']
        read_only_fields = ['id', 'encoded_password', 'created_at']


class RegisterSerializer(serializers.Serializer):
    name = serializers.CharField(min_length=2, max_length=60)
    master_key = serializers.CharField(write_only=True)
    recovery_question = serializers.CharField(max_length=255)
    recovery_answer = serializers.CharField(write_only=True)

    def validate(self, attrs):
        validate_secrets(
            attrs['name'], attrs['master_key'],
            attrs['recovery_question'], attrs['recovery_answer'],
        )
        return attrs


class LoginSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=60)
    master_key = serializers.CharField(write_only=True)


class RecoveryQuestionSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=60)


class VerifyRecoverySerializer(serializers.Serializer):
    name = serializers.CharField(max_length=60)
    recovery_answer = serializers.CharField(write_only=True)


class ResetKeySerializer(serializers.Serializer):
    reset_token = serializers.CharField(write_only=True)
    new_master_key = serializers.CharField(write_only=True)


class EncodeRequestSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    password = serializers.CharField(write_only=True)


class DecodeRequestSerializer(serializers.Serializer):
    encoded_password = serializers.CharField()
    master_key = serializers.CharField(write_only=True)