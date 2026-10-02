from django.db import models
from django.contrib.auth.hashers import make_password, check_password


class VaultConfig(models.Model):
    name = models.CharField(max_length=255)
    master_key_hash = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def set_master_key(self, raw_key: str):
        self.master_key_hash = make_password(raw_key)

    def check_master_key(self, raw_key: str) -> bool:
        return check_password(raw_key, self.master_key_hash)

    def __str__(self):
        return f"VaultConfig({self.name})"


class VaultEntry(models.Model):
    name = models.CharField(max_length=255)
    encoded_password = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.name