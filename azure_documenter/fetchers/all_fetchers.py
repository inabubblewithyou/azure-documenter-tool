import logging
import asyncio # Make sure asyncio is imported
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient # To find VMs first
from azure.core.exceptions import HttpResponseError
from .ai import fetch_ai_services

async def fetch_all_vm_details(credential, subscription_id):
    """Fetches detailed information for all Virtual Machines in a subscription."""
    # ... (rest of the function remains the same) ...

# Fetchers that need to be made async:
# fetch_networking_details, fetch_cost_details, fetch_detailed_cost_report, 
# fetch_governance_details, fetch_service_principal_summary, fetch_custom_roles,
# fetch_monitoring_details, fetch_key_vaults, fetch_key_vault_certificates,
# fetch_app_service_details, fetch_autoscale_settings, fetch_resources

# Example for fetch_resources:
async def fetch_resources(credential, subscription_id):
    """Fetches basic resource information for a subscription."""
    # ... (function body) ...

# Example for fetch_networking_details:
async def fetch_networking_details(credential, subscription_id, resources_list):
    """Fetches VNet, subnet, NSG, peering, Firewall, Public IP, Gateways, DDoS plans, Route Tables, App Gateways (WAF), WAF Policies for a subscription."""
    # ... (function body) ...

# ... Add `async def` to all other required fetcher functions ... 

__all__ = [
    'fetch_all_vm_details',
    'fetch_resources',
    'fetch_networking_details',
    'fetch_ai_services',  # Add the new AI services fetcher
] 