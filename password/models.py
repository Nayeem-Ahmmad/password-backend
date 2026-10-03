import re
from datetime import timedelta
from math import ceil

from django.db import models
from django.utils import timezone

MAX_ATTEMPTS = 5
LOCK_MINUTES = 15


def normalize_name(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


def normalize_answer(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


class Account(models.Model):
    name = models.CharField(max_length=60)
    name_key = models.CharField(max_length=60, unique=True)
    master_salt = models.CharField(max_length=64)
    master_wrapped = models.TextField()
    recovery_question = models.CharField(max_length=255)
    recovery_salt = models.CharField(max_length=64)
    recovery_wrapped = models.TextField()
    key_version = models.PositiveIntegerField(default=1)
    login_failed = models.PositiveSmallIntegerField(default=0)
    login_locked_until = models.DateTimeField(null=True, blank=True)
    recovery_failed = models.PositiveSmallIntegerField(default=0)
    recovery_locked_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def is_authenticated(self) -> bool:
        return True

    def is_locked(self, kind: str) -> bool:
        until = getattr(self, f'{kind}_locked_until')
        return bool(until and until > timezone.now())

    def lock_minutes_left(self, kind: str) -> int:
        until = getattr(self, f'{kind}_locked_until')
        if not until or until <= timezone.now():
            return 0
        return max(1, ceil((until - timezone.now()).total_seconds() / 60))

    def register_failure(self, kind: str):
        failed = getattr(self, f'{kind}_failed') + 1
        if failed >= MAX_ATTEMPTS:
            setattr(self, f'{kind}_locked_until', timezone.now() + timedelta(minutes=LOCK_MINUTES))
            failed = 0
        setattr(self, f'{kind}_failed', failed)
        self.save()

    def clear_failures(self, kind: str):
        setattr(self, f'{kind}_failed', 0)
        setattr(self, f'{kind}_locked_until', None)
        self.save()

    def __str__(self):
        return self.name


class VaultEntry(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='entries')
    name = models.CharField(max_length=255)
    encoded_password = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.name