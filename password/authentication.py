from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .crypto import read_token
from .models import Account


class VaultTokenAuthentication(BaseAuthentication):
    keyword = 'Bearer'

    def authenticate_header(self, request):
        return self.keyword

    def authenticate(self, request):
        header = request.headers.get('Authorization', '')
        parts = header.split()
        if len(parts) != 2 or parts[0] != self.keyword:
            return None

        try:
            account_id, version, data_key = read_token(parts[1], 'session')
        except ValueError:
            raise AuthenticationFailed('Session expired. Sign in again.')

        account = Account.objects.filter(pk=account_id).first()
        if not account or account.key_version != version:
            raise AuthenticationFailed('Session expired. Sign in again.')

        return account, data_key