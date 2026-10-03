import base64
import hashlib
import hmac
import json
import os

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

SESSION_TTL = 30 * 60
RESET_TTL = 10 * 60

_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAXMEM = 128 * 1024 * 1024


def _pepper() -> bytes:
    key = getattr(settings, 'ENCRYPTION_KEY', None)
    if not key:
        raise ImproperlyConfigured('ENCRYPTION_KEY is missing in the environment.')
    return key.encode('utf-8')


def _server_fernet() -> Fernet:
    raw = hashlib.sha256(b'vault-token|' + settings.SECRET_KEY.encode('utf-8')).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def new_salt() -> str:
    return base64.urlsafe_b64encode(os.urandom(16)).decode('ascii')


def new_data_key() -> bytes:
    return Fernet.generate_key()


def _derive(secret: str, salt: str) -> Fernet:
    pre = hmac.new(_pepper(), secret.encode('utf-8'), hashlib.sha256).digest()
    raw = hashlib.scrypt(
        pre,
        salt=base64.urlsafe_b64decode(salt.encode('ascii')),
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        maxmem=_SCRYPT_MAXMEM,
        dklen=32,
    )
    return Fernet(base64.urlsafe_b64encode(raw))


def wrap_data_key(data_key: bytes, secret: str, salt: str) -> str:
    return _derive(secret, salt).encrypt(data_key).decode('ascii')


def unwrap_data_key(wrapped: str, secret: str, salt: str) -> bytes:
    try:
        return _derive(secret, salt).decrypt(wrapped.encode('ascii'))
    except InvalidToken:
        raise ValueError('wrong secret')


def burn(secret: str) -> None:
    _derive(secret, 'AAAAAAAAAAAAAAAAAAAAAA==')


def encrypt_password(plain_password: str, data_key: bytes) -> str:
    return Fernet(data_key).encrypt(plain_password.encode('utf-8')).decode('utf-8')


def decrypt_password(encoded_password: str, data_key: bytes) -> str:
    try:
        return Fernet(data_key).decrypt(encoded_password.encode('utf-8')).decode('utf-8')
    except (InvalidToken, ValueError):
        raise ValueError('Incorrect encode value')


def issue_token(kind: str, account_id: int, key_version: int, data_key: bytes) -> str:
    payload = json.dumps({
        't': kind,
        'a': account_id,
        'v': key_version,
        'k': data_key.decode('ascii'),
    })
    return _server_fernet().encrypt(payload.encode('utf-8')).decode('ascii')


def read_token(token: str, kind: str):
    ttl = SESSION_TTL if kind == 'session' else RESET_TTL
    try:
        raw = _server_fernet().decrypt(token.encode('ascii'), ttl=ttl)
        payload = json.loads(raw.decode('utf-8'))
    except (InvalidToken, ValueError, UnicodeError):
        raise ValueError('invalid token')
    if payload.get('t') != kind:
        raise ValueError('invalid token')
    return payload['a'], payload['v'], payload['k'].encode('ascii')