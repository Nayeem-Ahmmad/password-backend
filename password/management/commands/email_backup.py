import json
from django.conf import settings
from django.core.mail import EmailMessage
from django.core.management.base import BaseCommand
from password.backup import export_all


class Command(BaseCommand):
    help = "Email a JSON backup of all vault data to the configured address."

    def handle(self, *args, **options):
        content = json.dumps(export_all(), indent=2)

        email = EmailMessage(
            subject="Personal Vault — automatic backup",
            body="Attached is the latest encrypted backup. ENCRYPTION_KEY and SECRET_KEY must stay unchanged to restore it.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[settings.BACKUP_EMAIL_TO],
        )
        email.attach("vault_backup.json", content, "application/json")
        email.send()

        self.stdout.write(self.style.SUCCESS(f"Backup emailed to {settings.BACKUP_EMAIL_TO}"))