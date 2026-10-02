from django.contrib import admin
from .models import VaultEntry


@admin.register(VaultEntry)
class VaultEntryAdmin(admin.ModelAdmin):
    list_display = ['name', 'created_at']
    search_fields = ['name']