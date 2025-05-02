#!/usr/bin/env python3

import boto3
import sys
import os

def get_current_account_id():
    """Retrieves the current AWS account ID."""
    try:
        sts_client = boto3.client('sts')
        caller_identity = sts_client.get_caller_identity()
        return caller_identity['Account']
    except Exception as e:
        print(f"Error getting AWS account ID: {e}", file=sys.stderr)
        sys.exit(1)

def assume_delivery_role(account_id):
    """Assumes the DeliveryRole in the specified account."""
    role_arn = f"arn:aws:iam::{account_id}:role/DeliveryRole"
    role_session_name = "DeliveryRoleSession"

    try:
        sts_client = boto3.client('sts')
        assumed_role_object = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=role_session_name
        )
        return assumed_role_object['Credentials']
    except Exception as e:
        print(f"Error assuming role {role_arn}: {e}", file=sys.stderr)
        print("Please ensure DeliveryRole exists and you have permissions to assume it.", file=sys.stderr)
        sys.exit(1)

def main():
    """Main function to assume role and print export commands."""
    account_id = get_current_account_id()
    print(f"Assuming DeliveryRole in account {account_id}...", file=sys.stderr)

    credentials = assume_delivery_role(account_id)

    access_key_id = credentials['AccessKeyId']
    secret_access_key = credentials['SecretAccessKey']
    session_token = credentials['SessionToken']

    print(f"\n# Run these commands to configure your shell:")
    current_region = boto3.Session().region_name

    print(f"\n# Run these commands to configure your shell:")
    print(f"export AWS_ACCESS_KEY_ID='{access_key_id}'")
    print(f"export AWS_SECRET_ACCESS_KEY='{secret_access_key}'")
    print(f"export AWS_SESSION_TOKEN='{session_token}'")
    if current_region:
        print(f"export AWS_DEFAULT_REGION='{current_region}'")
    else:
        print("# AWS_DEFAULT_REGION is not configured. You may need to set it manually.", file=sys.stderr)
        print("# export AWS_DEFAULT_REGION='your-region'")


if __name__ == "__main__":
    main()
