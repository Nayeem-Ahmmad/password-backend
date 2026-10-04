from django.utils.dateparse import parse_datetime
from .models import Account, VaultEntry


def export_account(account: Account) -> dict:
    return {
        "account": {
            "name": account.name,
            "name_key": account.name_key,
            "master_salt": account.master_salt,
            "master_wrapped": account.master_wrapped,
            "recovery_question": account.recovery_question,
            "recovery_salt": account.recovery_salt,
            "recovery_wrapped": account.recovery_wrapped,
            "key_version": account.key_version,
        },
        "entries": [
            {
                "name": entry.name,
                "encoded_password": entry.encoded_password,
                "created_at": entry.created_at.isoformat(),
            }
            for entry in account.entries.all()
        ],
    }


def export_all() -> dict:
    return {"accounts": [export_account(acc) for acc in Account.objects.all()]}


def restore_account(data: dict) -> Account:
    acc_data = data["account"]

    account, _ = Account.objects.update_or_create(
        name_key=acc_data["name_key"],
        defaults={
            "name": acc_data["name"],
            "master_salt": acc_data["master_salt"],
            "master_wrapped": acc_data["master_wrapped"],
            "recovery_question": acc_data["recovery_question"],
            "recovery_salt": acc_data["recovery_salt"],
            "recovery_wrapped": acc_data["recovery_wrapped"],
            "key_version": acc_data["key_version"],
        },
    )

    account.entries.all().delete()
    for entry in data["entries"]:
        VaultEntry.objects.create(
            account=account,
            name=entry["name"],
            encoded_password=entry["encoded_password"],
            created_at=parse_datetime(entry["created_at"]),
        )

    return account


def restore_all(data: dict) -> list:
    return [restore_account(acc_data) for acc_data in data["accounts"]]