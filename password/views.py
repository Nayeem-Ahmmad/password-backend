from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response

from .models import VaultEntry, VaultConfig
from .serializers import (
    VaultEntrySerializer,
    EncodeRequestSerializer,
    DecodeRequestSerializer,
    SetupRequestSerializer,
    LoginRequestSerializer,
    ResetKeyRequestSerializer,
)
from .crypto import encrypt_password, decrypt_password


# ---------- Setup / Login / Reset ----------

class ConfigStatusView(APIView):
    def get(self, request):
        config = VaultConfig.objects.first()
        if not config:
            return Response({'configured': False})
        return Response({'configured': True, 'name': config.name})


class SetupView(APIView):
    def post(self, request):
        if VaultConfig.objects.exists():
            return Response({'detail': 'It has already been set up.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = SetupRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        config = VaultConfig(name=serializer.validated_data['name'])
        config.set_master_key(serializer.validated_data['master_key'])
        config.save()

        return Response({'success': True}, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    def post(self, request):
        config = VaultConfig.objects.first()
        if not config:
            return Response({'detail': 'It has not been set up yet'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = LoginRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if not config.check_master_key(serializer.validated_data['master_key']):
            return Response({'detail': 'Incorrect Master Key.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'success': True, 'name': config.name})


class ResetKeyView(APIView):

    def post(self, request):
        config = VaultConfig.objects.first()
        if not config:
            return Response({'detail': 'It has not been set up yet'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = ResetKeyRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        config.set_master_key(serializer.validated_data['new_master_key'])
        config.save()

        return Response({'success': True})


# ---------- Entries ----------

class VaultEntryListView(generics.ListAPIView):
    queryset = VaultEntry.objects.all()
    serializer_class = VaultEntrySerializer


class EncodePasswordView(APIView):
    def post(self, request):
        if not VaultConfig.objects.exists():
            return Response({'detail': 'It has not been set up yet'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = EncodeRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        name = serializer.validated_data['name']
        password = serializer.validated_data['password']

        encoded = encrypt_password(password)

        entry = VaultEntry.objects.create(name=name, encoded_password=encoded)
        out = VaultEntrySerializer(entry)
        return Response(out.data, status=status.HTTP_201_CREATED)


class DecodePasswordView(APIView):

    def post(self, request):
        config = VaultConfig.objects.first()
        if not config:
            return Response({'detail': 'It has not been set up yet'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = DecodeRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        encoded_password = serializer.validated_data['encoded_password']
        master_key = serializer.validated_data['master_key']

        if not config.check_master_key(master_key):
            return Response({'detail': 'Incorrect Master Key.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            original = decrypt_password(encoded_password)
        except ValueError as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'password': original}, status=status.HTTP_200_OK)


class DeleteEntryView(generics.DestroyAPIView):
    queryset = VaultEntry.objects.all()
    serializer_class = VaultEntrySerializer