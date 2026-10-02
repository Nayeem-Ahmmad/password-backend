from django.conf import settings
from cryptography.fernet import Fernet, InvalidToken


def _get_fernet() -> Fernet:
    return Fernet(settings.ENCRYPTION_KEY.encode('utf-8'))


def encrypt_password(plain_password: str) -> str:
    fernet = _get_fernet()
    token = fernet.encrypt(plain_password.encode('utf-8'))
    return token.decode('utf-8')


def decrypt_password(encoded_password: str) -> str:
    fernet = _get_fernet()
    try:
        plain = fernet.decrypt(encoded_password.encode('utf-8'))
    except InvalidToken:
        raise ValueError("Incorrect encode value")
    return plain.decode('utf-8')