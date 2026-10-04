import json
from django.core.management.base import BaseCommand, CommandError
from password.backup import restore_all


class Command(BaseCommand):
    help = "Restore accounts and vault entries from a JSON backup file."

    def add_arguments(self, parser):
        parser.add_argument("input")

    def handle(self, *args, **options):
        try:
            with open(options["input"]) as f:
                data = json.load(f)
        except FileNotFoundError:
            raise CommandError(f"File not found: {options['input']}")

        restored = restore_all(data)
        self.stdout.write(self.style.SUCCESS(f"Restored {len(restored)} account(s)."))