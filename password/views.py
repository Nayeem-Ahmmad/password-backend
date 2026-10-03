import hashlib

from django.db import IntegrityError
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from . import crypto
from .authentication import VaultTokenAuthentication
from .models import Account, VaultEntry, normalize_name
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    RecoveryQuestionSerializer,
    VerifyRecoverySerializer,
    ResetKeySerializer,
    VaultEntrySerializer,
    EncodeRequestSerializer,
    DecodeRequestSerializer,
    validate_secrets,
)

FAKE_QUESTIONS = [
    'Favorite word',
    'Favorite food',
    'Favorite place',
    'Childhood nickname',
    'Favorite character or hero',
]


class AuthThrottle(AnonRateThrottle):
    scope = 'auth'
    rate = '40/min'


def bad(detail, code=status.HTTP_400_BAD_REQUEST):
    return Response({'detail': detail}, status=code)


def locked(account, kind):
    minutes = account.lock_minutes_left(kind)
    unit = 'minute' if minutes == 1 else 'minutes'
    return bad(f'Too many wrong attempts. Try again in {minutes} {unit}.', status.HTTP_429_TOO_MANY_REQUESTS)


def session_payload(account, data_key):
    return {
        'token': crypto.issue_token('session', account.pk, account.key_version, data_key),
        'name': account.name,
        'recovery_question': account.recovery_question,
    }


class RegisterView(APIView):
    throttle_classes = [AuthThrottle]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        name = ' '.join(data['name'].split())
        name_key = normalize_name(name)
        if Account.objects.filter(name_key=name_key).exists():
            return bad('That name is already taken. Try another one.')

        data_key = crypto.new_data_key()
        master_salt = crypto.new_salt()
        recovery_salt = crypto.new_salt()

        try:
            account = Account.objects.create(
                name=name,
                name_key=name_key,
                master_salt=master_salt,
                master_wrapped=crypto.wrap_data_key(data_key, data['master_key'], master_salt),
                recovery_question=data['recovery_question'].strip(),
                recovery_salt=recovery_salt,
                recovery_wrapped=crypto.wrap_data_key(
                    data_key, _answer_secret(data['recovery_answer']), recovery_salt
                ),
            )
        except IntegrityError:
            return bad('That name is already taken. Try another one.')

        return Response(session_payload(account, data_key), status=status.HTTP_201_CREATED)


def _answer_secret(answer: str) -> str:
    from .models import normalize_answer
    return normalize_answer(answer)


class LoginView(APIView):
    throttle_classes = [AuthThrottle]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        account = Account.objects.filter(name_key=normalize_name(data['name'])).first()
        if not account:
            crypto.burn(data['master_key'])
            return bad('Incorrect name or master key.')

        if account.is_locked('login'):
            return locked(account, 'login')

        try:
            data_key = crypto.unwrap_data_key(account.master_wrapped, data['master_key'], account.master_salt)
        except ValueError:
            account.register_failure('login')
            if account.is_locked('login'):
                return locked(account, 'login')
            return bad('Incorrect name or master key.')

        if account.login_failed or account.login_locked_until:
            account.clear_failures('login')

        return Response(session_payload(account, data_key))


class MeView(APIView):
    authentication_classes = [VaultTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({
            'name': request.user.name,
            'recovery_question': request.user.recovery_question,
        })


class RecoveryQuestionView(APIView):
    throttle_classes = [AuthThrottle]

    def post(self, request):
        serializer = RecoveryQuestionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        name_key = normalize_name(serializer.validated_data['name'])

        account = Account.objects.filter(name_key=name_key).first()
        if account:
            return Response({'question': account.recovery_question})

        index = int(hashlib.sha256(name_key.encode('utf-8')).hexdigest(), 16) % len(FAKE_QUESTIONS)
        return Response({'question': FAKE_QUESTIONS[index]})


class VerifyRecoveryView(APIView):
    throttle_classes = [AuthThrottle]

    def post(self, request):
        serializer = VerifyRecoverySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        secret = _answer_secret(data['recovery_answer'])

        account = Account.objects.filter(name_key=normalize_name(data['name'])).first()
        if not account:
            crypto.burn(secret)
            return bad('Wrong answer. Check it and try again.')

        if account.is_locked('recovery'):
            return locked(account, 'recovery')

        try:
            data_key = crypto.unwrap_data_key(account.recovery_wrapped, secret, account.recovery_salt)
        except ValueError:
            account.register_failure('recovery')
            if account.is_locked('recovery'):
                return locked(account, 'recovery')
            return bad('Wrong answer. Check it and try again.')

        account.clear_failures('recovery')
        token = crypto.issue_token('reset', account.pk, account.key_version, data_key)
        return Response({'reset_token': token})


class ResetKeyView(APIView):
    throttle_classes = [AuthThrottle]

    def post(self, request):
        serializer = ResetKeySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            account_id, version, data_key = crypto.read_token(data['reset_token'], 'reset')
        except ValueError:
            return bad('Reset session expired. Verify your recovery answer again.')

        account = Account.objects.filter(pk=account_id).first()
        if not account or account.key_version != version:
            return bad('Reset session is no longer valid. Verify your recovery answer again.')

        new_key = data['new_master_key']
        if len(new_key) < 8:
            return bad('Master key must be at least 8 characters.')
        if normalize_name(new_key) == account.name_key:
            return bad('Master key must be different from your name.')

        account.master_salt = crypto.new_salt()
        account.master_wrapped = crypto.wrap_data_key(data_key, new_key, account.master_salt)
        account.key_version += 1
        account.login_failed = 0
        account.login_locked_until = None
        account.save()

        return Response({'success': True})


class VaultEntryListView(generics.ListAPIView):
    authentication_classes = [VaultTokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = VaultEntrySerializer

    def get_queryset(self):
        return VaultEntry.objects.filter(account=self.request.user)


class EncodePasswordView(APIView):
    authentication_classes = [VaultTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = EncodeRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        encoded = crypto.encrypt_password(serializer.validated_data['password'], request.auth)
        entry = VaultEntry.objects.create(
            account=request.user,
            name=serializer.validated_data['name'],
            encoded_password=encoded,
        )
        return Response(VaultEntrySerializer(entry).data, status=status.HTTP_201_CREATED)


class DecodePasswordView(APIView):
    authentication_classes = [VaultTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DecodeRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        account = request.user

        if account.is_locked('login'):
            return locked(account, 'login')

        try:
            crypto.unwrap_data_key(account.master_wrapped, data['master_key'], account.master_salt)
        except ValueError:
            account.register_failure('login')
            if account.is_locked('login'):
                return locked(account, 'login')
            return bad('Incorrect Master Key.')

        try:
            original = crypto.decrypt_password(data['encoded_password'], request.auth)
        except ValueError as e:
            return bad(str(e))

        return Response({'password': original})


class DeleteEntryView(generics.DestroyAPIView):
    authentication_classes = [VaultTokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = VaultEntrySerializer

    def get_queryset(self):
        return VaultEntry.objects.filter(account=self.request.user)