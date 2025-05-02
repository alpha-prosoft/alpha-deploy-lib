#!/usr/bin/python3


import argparse
import os
import sys
import boto3
import logging
import yaml
from botocore.exceptions import NoCredentialsError, ClientError


logging.basicConfig(
    level=logging.INFO,
    format='%(name)-10.10s - %(levelname)s: %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


def cloudformationName(environment_zone, environment_name_lower, service_name):
    """Constructs the standard CloudFormation stack name."""
    logger.debug(f"Generating CloudFormation stack name for {service_name} in {environment_zone}-{environment_name_lower.upper()}")
    return f"{environment_zone}-{environment_name_lower.upper()}-{service_name}"

def getStackOutputs(cf_client, stack_name):
    """Fetches and returns outputs for a single CloudFormation stack."""
    outputs = {}
    logger.info(f"Fetching outputs from stack: {stack_name}")
    try:
        response = cf_client.describe_stacks(StackName=stack_name)
        logger.debug("Validating CloudFormation describe_stacks response...")
        if not response or 'Stacks' not in response or not response['Stacks']:
            logger.warning(f"Stack '{stack_name}' not found or API response structure unexpected.")
            return outputs

        stack_info = response['Stacks'][0]
        stack_outputs = stack_info.get('Outputs', [])

        if not stack_outputs:
            logger.info(f"Stack '{stack_name}' has no outputs.")
            return outputs

        logger.info(f"Found {len(stack_outputs)} outputs for stack '{stack_name}'.")
        for output in stack_outputs:
            key = output.get('OutputKey')
            value = output.get('OutputValue')
            if key and value is not None:
                logger.debug(f"Adding parameter: {key}={value} from stack {stack_name}")
                outputs[key] = {'value': value, 'source_stack': stack_name}
            else:
                 logger.warning(f"Found output without Key or Value in stack '{stack_name}': {output}")

    except ClientError as e:
        if e.response['Error']['Code'] == 'ValidationError' and 'does not exist' in e.response['Error']['Message']:
            logger.error(f"Parent stack '{stack_name}' not found.")
        else:
            logger.error(f"Error fetching outputs from stack '{stack_name}': {e}")
        return {} # Return empty dict on error

    return outputs

import json # Add json import

def startDeployment(args):
    """Fetches outputs from parent CloudFormation stacks, aggregates them, and starts deployment."""
    aggregated_params = {}

    # Load initial parameters from the specified file, if provided
    if args.parameters_file:
        logger.info(f"Loading initial parameters from file: {args.parameters_file}")
        try:
            with open(args.parameters_file, 'r') as f:
                file_params_data = json.load(f)
                # Expecting the file to contain a 'params' key like group_vars/all.json
                file_params = file_params_data.get('params', {})
                if file_params:
                    logger.info(f"Found {len(file_params)} parameters in the file.")
                    # Convert to the expected structure for aggregated_params
                    for key, value in file_params.items():
                        aggregated_params[key] = {'value': str(value), 'source_stack': args.parameters_file} # Ensure value is string
                else:
                    logger.warning(f"No 'params' key found or 'params' dictionary is empty in {args.parameters_file}.")
        except FileNotFoundError:
            logger.error(f"Parameters file not found: {args.parameters_file}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from parameters file {args.parameters_file}: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error reading parameters file {args.parameters_file}: {e}")
            sys.exit(1)
    else:
        logger.info("No parameters file specified.")


    # Fetch parameters from parent CloudFormation stacks and merge/overwrite
    if args.parent_cloudformations:
        logger.info("Processing parent CloudFormation stacks...")
        cf_client = boto3.client('cloudformation', region_name=args.aws_region)
        # Split, strip whitespace, and filter out empty strings
        parent_services = [s.strip() for s in args.parent_cloudformations.split(',') if s.strip()]

        logger.debug("Parsing parent CloudFormation service names.")
        parent_services = [s.strip() for s in args.parent_cloudformations.split(',') if s.strip()]
        logger.debug(f"Parsed parent service names: {parent_services}")

        for service_name in parent_services:
            stack_name = cloudformationName(args.environment_zone, args.environment_name_lower, service_name)
            stack_params = getStackOutputs(cf_client, stack_name)
            # Update the main dictionary with parameters from the current stack
            # Note: This will overwrite parameters with the same key from earlier stacks
            logger.debug(f"Updating aggregated parameters with outputs from {stack_name}. Note: This overwrites existing keys.")
            aggregated_params.update(stack_params)
    else:
        logger.info("No parent CloudFormation stacks specified.")

    logger.info("\nAggregated parameters from parent stacks:")
    if aggregated_params:
        # Log parameters along with their source stack
        for key, data in aggregated_params.items():
            logger.info(f"  {key}: {data['value']} (from stack: {data['source_stack']})")
    else:
        logger.info("  No parameters aggregated.")

    logger.info("Proceeding with deployment using aggregated parameters...")

    template_params_keys = getApplicationParams(args.cloud_formation_file)
    logger.info("Parameters defined in the CloudFormation template:")
    if template_params_keys:
        for key in template_params_keys:
            logger.info(f"  - {key}")
    else:
        logger.info("  No parameters found or defined in the template.")

    final_deployment_params = {}
    logger.info("Validating and preparing final deployment parameters:")
    parameter_sources = {}
    for key in template_params_keys:
        if key in aggregated_params:
            final_deployment_params[key] = aggregated_params[key]['value']
            parameter_sources[key] = aggregated_params[key]['source_stack']
            logger.info(f"Using parameter '{key}' from parent stack: {parameter_sources[key]}")
        else:
            logger.warning(f"Parameter '{key}' defined in template but not found in parent stack outputs.")


    logger.info("Final parameters to be used for deployment:")
    if final_deployment_params:
        for key, value in final_deployment_params.items():
            source_info = f"(from stack: {parameter_sources[key]})" if key in parameter_sources else "(source not applicable or found)"
            logger.info(f"  {key}: {value} {source_info}")
    else:
        logger.info("  No valid parameters identified for deployment based on template definitions and parent outputs.")

    # Ensure cf_client is initialized if not done already (e.g., if no parent stacks)
    if 'cf_client' not in locals():
        logger.info("Initializing CloudFormation client...")
        cf_client = boto3.client('cloudformation', region_name=args.aws_region)

    target_stack_name = cloudformationName(args.environment_zone, args.environment_name_lower, args.service_name)

    logger.info(f"Starting deployment process for target stack: {target_stack_name}")
    processDeployment(cf_client, target_stack_name, args, final_deployment_params)


def processDeployment(cf_client, target_stack_name, args, deployment_params):
    """Checks target stack status, handles ROLLBACK_COMPLETE, and proceeds with deployment."""
    logger.info(f"Processing deployment for stack: {target_stack_name}")

    logger.info(f"Checking status for target stack: {target_stack_name}")
    try:
        stack_description = cf_client.describe_stacks(StackName=target_stack_name)
        stack_status = stack_description['Stacks'][0]['StackStatus']
        logger.info(f"  Stack '{target_stack_name}' found with status: {stack_status}")

        if stack_status == 'ROLLBACK_COMPLETE':
            logger.warning(f"  Stack '{target_stack_name}' is in ROLLBACK_COMPLETE status. Deleting stack before proceeding...")
            cf_client.delete_stack(StackName=target_stack_name)
            logger.info(f"  Waiting for stack '{target_stack_name}' deletion...")
            waiter = cf_client.get_waiter('stack_delete_complete')
            waiter.wait(StackName=target_stack_name)
            logger.info(f"Stack '{target_stack_name}' deleted successfully.")

    except ClientError as e:
        if e.response['Error']['Code'] == 'ValidationError' and 'does not exist' in e.response['Error']['Message']:
            logger.info(f"Stack '{target_stack_name}' does not exist. Proceeding with creation or update.")
        else:
            logger.error(f"Error checking stack status for '{target_stack_name}': {e}")
            logger.error("Exiting due to error during stack status check.")
            sys.exit(1)

    logger.info(f"Proceeding with deployment actions for stack '{target_stack_name}'...")
    logger.info("Using the following parameters for deployment:")
    if deployment_params:
        for key, value in deployment_params.items():
             logger.info(f"    {key}")
    else:
        logger.info("    No parameters derived from parent stacks for this deployment.")

    logger.info(f"Reading template file: {args.cloud_formation_file}")
    try:
        with open(args.cloud_formation_file, 'r') as file:
            template_body = file.read()
    except FileNotFoundError:
        logger.error(f"CloudFormation template file not found: {args.cloud_formation_file}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading template file {args.cloud_formation_file}: {e}")
        sys.exit(1)

    logger.debug("Formatting parameters for Boto3 API call.")
    boto_params = [{'ParameterKey': k, 'ParameterValue': v} for k, v in deployment_params.items()]

    try:
        logger.debug(f"Checking if stack '{target_stack_name}' exists...")
        try:
            cf_client.describe_stacks(StackName=target_stack_name)
            stack_exists = True
            logger.info(f"Stack '{target_stack_name}' exists. Attempting to update...")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ValidationError' and 'does not exist' in e.response['Error']['Message']:
                stack_exists = False
                logger.info(f"Stack '{target_stack_name}' does not exist. Attempting to create.")
            else:
                logger.error(f"Unexpected error during describe_stacks for '{target_stack_name}': {e}")
                # Re-raise unexpected errors during describe_stacks
                raise

        if stack_exists:
            logger.info("Initiating stack update...")
            cf_client.update_stack(
                StackName=target_stack_name,
                TemplateBody=template_body,
                Parameters=boto_params,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM', 'CAPABILITY_AUTO_EXPAND'] # Add capabilities as needed
            )
            logger.info(f"Update initiated for stack '{target_stack_name}'. Waiting for completion...")
            waiter = cf_client.get_waiter('stack_update_complete')
            waiter.wait(StackName=target_stack_name)
            logger.info(f"Stack '{target_stack_name}' updated successfully.")

        else:
            logger.info("Initiating stack creation...")
            cf_client.create_stack(
                StackName=target_stack_name,
                TemplateBody=template_body,
                Parameters=boto_params,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM', 'CAPABILITY_AUTO_EXPAND'] # Add capabilities as needed
            )
            logger.info(f"Creation initiated for stack '{target_stack_name}'. Waiting for completion...")
            waiter = cf_client.get_waiter('stack_create_complete')
            waiter.wait(StackName=target_stack_name)
            logger.info(f"Stack '{target_stack_name}' created successfully.")

    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        if error_code == 'ValidationError' and 'No updates are to be performed' in error_message:
            logger.info(f"Stack '{target_stack_name}' is already up-to-date. No changes made.")
        else:
            logger.error(f"Error during stack operation for '{target_stack_name}': {error_code} - {error_message}")
            try:
                logger.info(f"Fetching stack events for '{target_stack_name}' to provide more context...")
                events_response = cf_client.describe_stack_events(StackName=target_stack_name)
                for event in reversed(events_response['StackEvents']): # Show recent events first
                    status = event.get('ResourceStatus', 'N/A')
                    reason = event.get('ResourceStatusReason', '')
                    resource_type = event.get('ResourceType', 'N/A')
                    logical_id = event.get('LogicalResourceId', 'N/A')
                    timestamp = event.get('Timestamp')
                    log_level = logging.ERROR if 'FAILED' in status else logging.DEBUG # Use DEBUG for non-failed events
                    logger.log(log_level, f"Event: {timestamp} - {resource_type} ({logical_id}) - Status: {status} - Reason: {reason}")
                    # Stop logging events once we hit the initiating event or go too far back
                    if status in ('CREATE_IN_PROGRESS', 'UPDATE_IN_PROGRESS') and logical_id == target_stack_name:
                         break
            except ClientError as event_error:
                 logger.error(f"Could not fetch stack events for '{target_stack_name}': {event_error}")

            logger.error("Deployment failed.")
            sys.exit(1) # Exit after logging errors and events

    logger.info(f"Deployment process completed successfully for stack '{target_stack_name}'.")


def getApplicationParams(template_file_path):
    """Reads a CloudFormation template file and extracts its defined parameters."""
    logger.info(f"Reading CloudFormation template to extract parameters: {template_file_path}")
    try:
        with open(template_file_path, 'r') as file:
            template_data = yaml.safe_load(file)

        if not template_data:
            logger.warning("Template file is empty or not valid YAML.")
            return []

        parameters = template_data.get('Parameters', {})
        if not parameters:
            logger.info("No 'Parameters' section found in the template.")
            return []
        return list(parameters.keys())

    except FileNotFoundError:
        logger.error(f"CloudFormation template file not found: {template_file_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML file {template_file_path}: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred while reading template parameters: {e}")
        sys.exit(1)


def getCurrentAccountId():
    """Retrieves the current AWS account ID using STS."""
    try:
        sts_client = boto3.client('sts')
        caller_identity = sts_client.get_caller_identity()
        return caller_identity.get('Account')
    except (NoCredentialsError, ClientError) as e:
        logger.error(f"Error retrieving AWS Account ID: {e}")
        logger.error("Please ensure AWS credentials are configured correctly.")
        sys.exit(1)


def configure_defaults(args):
    """Sets default values for arguments (e.g., Account ID, Deploy ID) if not provided."""
    if args.deploy_id is None:
        args.deploy_id = args.build_id
        logger.info(f"Deploy ID not provided, defaulting to Build ID: {args.deploy_id}")

    if not args.account_id:
        logger.info("Account ID not provided, attempting to retrieve from current AWS context...")
        args.account_id = getCurrentAccountId()
        if args.account_id: # Check if retrieval was successful
             logger.info(f"Using Account ID: {args.account_id}")


def main():
    """Parses command-line arguments, configures defaults, and initiates the deployment process."""
    parser = argparse.ArgumentParser(description="Deploy CloudFormation stack.")

    # --- Argument Definitions ---
    parser.add_argument(
        "-pfile", "--parameters-file", # Changed short flag to avoid conflict with parent-cloudformations if -p is used there later
        required=False,
        help="Path to a JSON file containing initial deployment parameters under a 'params' key. Env: DEPLOY_PARAMS_FILE",
        metavar="DEPLOY_PARAMS_FILE",
        default=os.getenv("DEPLOY_PARAMS_FILE")
    )
    parser.add_argument(
        "-f", "--cloud-formation-file",
        required=False, # Check performed after parsing
        help="Path to the CloudFormation template file. Env: DEPLOY_FILE_PATH",
        metavar="DEPLOY_FILE_PATH",
        default=os.getenv("DEPLOY_FILE_PATH")
    )
    parser.add_argument(
        "-r", "--aws-region",
        required=False, # Check performed after parsing
        help="AWS region for deployment. Env: DEPLOY_REGION",
        metavar="DEPLOY_REGION",
        default=os.getenv("DEPLOY_REGION")
    )
    parser.add_argument(
        "-a", "--account-id",
        required=False,
        help="AWS account ID for deployment. Defaults to the current AWS context if not specified. Env: DEPLOY_ACCOUNT_ID",
        metavar="DEPLOY_ACCOUNT_ID",
        default=os.getenv("DEPLOY_ACCOUNT_ID")
    )
    parser.add_argument(
        "-e", "--environment-name-lower",
        required=False, # Check performed after parsing
        help="Lowercase name of the target environment (e.g., 'dev', 'staging', 'prod'). Env: DEPLOY_ENV_NAME",
        metavar="DEPLOY_ENV_NAME",
        default=os.getenv("DEPLOY_ENV_NAME")
    )
    parser.add_argument(
        "-z", "--environment-zone",
        required=False, # Check performed after parsing
        help="Environment zone or identifier (e.g., 'a', 'b', 'primary'). Env: DEPLOY_ZONE",
        metavar="DEPLOY_ZONE",
        default=os.getenv("DEPLOY_ZONE")
    )
    parser.add_argument(
        "-p", "--parent-cloudformations",
        required=False,
        help="Comma-separated list of parent CloudFormation stack names. Env: DEPLOY_PARENT_STACK_NAMES",
        metavar="DEPLOY_PARENT_STACK_NAMES",
        default=os.getenv("DEPLOY_PARENT_STACK_NAMES")
    )
    parser.add_argument(
        "-s", "--service-name",
        required=False, # Check performed after parsing
        help="Name of the service being deployed. Env: DEPLOY_SERVICE_NAME",
        metavar="DEPLOY_SERVICE_NAME",
        default=os.getenv("DEPLOY_SERVICE_NAME")
    )
    parser.add_argument(
        "--build-id",
        required=False, # Check performed after parsing
        help="Build identifier for the deployment. Env: DEPLOY_BUILD_ID",
        metavar="DEPLOY_BUILD_ID",
        default=os.getenv("DEPLOY_BUILD_ID")
    )
    parser.add_argument(
        "--deploy-id",
        required=False, # Defaults to build-id if not provided
        help="Deployment identifier. Defaults to the build-id if not specified. Env: DEPLOY_DEPLOY_ID",
        metavar="DEPLOY_DEPLOY_ID",
        default=os.getenv("DEPLOY_DEPLOY_ID")
    )

    args = parser.parse_args()

    # --- Validation for originally required arguments ---
    required_args = {
        'cloud_formation_file': args.cloud_formation_file,
        'aws_region': args.aws_region,
        'environment_name_lower': args.environment_name_lower,
        'environment_zone': args.environment_zone,
        'service_name': args.service_name,
        'build_id': args.build_id # Add build_id to required checks
    }

    missing_args = [name for name, value in required_args.items() if value is None]

    if missing_args:
        logger.error("Missing required arguments. Please provide them via command line or environment variables:")
        # Map back to CLI flags and env var names for user clarity
        arg_map = {
            'cloud_formation_file': ('-f/--cloud-formation-file', 'DEPLOY_FILE_PATH'),
            'aws_region': ('-r/--aws-region', 'DEPLOY_REGION'),
            'environment_name_lower': ('-e/--environment-name-lower', 'DEPLOY_ENV_NAME'),
            'environment_zone': ('-z/--environment-zone', 'DEPLOY_ZONE'),
            'service_name': ('-s/--service-name', 'DEPLOY_SERVICE_NAME'),
            'build_id': ('--build-id', 'DEPLOY_BUILD_ID') # Add build_id mapping
        }
        for arg_name in missing_args:
            flags, env_var = arg_map.get(arg_name, ('<unknown>', '<unknown>')) # Use .get for safety
            logger.error(f"  Argument: {arg_name}, Flag: {flags}, Environment Variable: {env_var}")
        parser.print_help(sys.stderr)
        sys.exit(1)

    configure_defaults(args)

    logger.info("Starting deployment with the following parameters:")
    logger.info(f"  CloudFormation File: {args.cloud_formation_file}")
    logger.info(f"  AWS Region: {args.aws_region}")
    logger.info(f"  Account ID: {args.account_id}")
    logger.info(f"  Environment Name: {args.environment_name_lower}")
    logger.info(f"  Environment Zone: {args.environment_zone}")
    logger.info(f"  Service Name: {args.service_name}")
    logger.info(f"  Parent CloudFormations: {args.parent_cloudformations if args.parent_cloudformations else 'None'}")
    logger.info(f"  Parameters File: {args.parameters_file if args.parameters_file else 'None'}")
    logger.info(f"  Build ID: {args.build_id}")
    logger.info(f"  Deploy ID: {args.deploy_id}")

    startDeployment(args)

if __name__ == "__main__":
    main()
