from django.contrib import admin
from .models import Account, VaultEntry


@admin.register(Account)
class AccountAdmin(admin.ModelAdmin):
    list_display = ['name', 'created_at']
    search_fields = ['name']
    readonly_fields = [
        'name_key', 'master_salt', 'master_wrapped', 'recovery_question',
        'recovery_salt', 'recovery_wrapped', 'key_version', 'created_at',
    ]


@admin.register(VaultEntry)
class VaultEntryAdmin(admin.ModelAdmin):
    list_display = ['name', 'account', 'created_at']
    search_fields = ['name', 'account__name']