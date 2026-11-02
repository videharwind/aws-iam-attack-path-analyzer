import argparse
import datetime
from pathlib import Path
import sys
import boto3
import botocore.exceptions

from IAM_Enumerator import configure_client
from IAM_Inventory import build_inventory, filter_
from effective_permission import build_permission_map
from snapshot import save_snapshot


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Collect AWS IAM configuration into a snapshot file."
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS credential profile name to use.",
    )
    parser.add_argument(
        "--region",
        default=None,
        help="AWS region name.",
    )
    parser.add_argument(
        "--prefix",
        default="test",
        help="Name prefix to filter entities by (empty string disables filtering).",
    )
    parser.add_argument(
        "--out",
        default="snapshots/scan.json",
        help="Path where snapshot JSON will be written (default: snapshots/scan.json).",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = Path.cwd() / out_path

    try:
        configure_client(profile=args.profile, region=args.region)
        inventory = build_inventory()
        if args.prefix:
            inventory = filter_(inventory, prefix=args.prefix)
        permission_map = build_permission_map(inventory)

        account_id = None
        try:
            session = boto3.Session(profile_name=args.profile, region_name=args.region)
            sts = session.client("sts")
            account_id = sts.get_caller_identity().get("Account")
        except Exception:
            account_id = None

        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        meta = {
            "created_at": created_at,
            "account_id": account_id,
            "prefix": args.prefix,
            "tool_version": "0.1",
        }

        save_snapshot(inventory, permission_map, out_path, meta=meta)
        print(
            f"Snapshot saved to {out_path} "
            f"({len(inventory.users)} users, {len(inventory.groups)} groups, "
            f"{len(inventory.roles)} roles, {len(inventory.policies)} policies)"
        )
        return 0
    except (
        botocore.exceptions.NoCredentialsError,
        botocore.exceptions.ProfileNotFound,
        botocore.exceptions.ClientError,
        botocore.exceptions.EndpointConnectionError,
    ) as e:
        print(f"AWS Error: {e}")
        print("Please check your AWS credentials (aws configure), profile name, or verify iam:List* and iam:Get* permissions.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

