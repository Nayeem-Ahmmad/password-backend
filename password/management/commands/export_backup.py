import json
from django.core.management.base import BaseCommand
from password.backup import export_all


class Command(BaseCommand):
    help = "Export all accounts and vault entries as a JSON backup file."

    def add_arguments(self, parser):
        parser.add_argument("--output", default="vault_backup.json")

    def handle(self, *args, **options):
        data = export_all()
        with open(options["output"], "w") as f:
            json.dump(data, f, indent=2)
        self.stdout.write(self.style.SUCCESS(f"Backup written to {options['output']}"))