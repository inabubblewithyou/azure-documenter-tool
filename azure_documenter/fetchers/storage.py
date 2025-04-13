import logging
import asyncio
from azure.mgmt.storage import StorageManagementClient
from azure.core.exceptions import HttpResponseError

async def fetch_storage_details(credential, subscription_id):
    """Fetches comprehensive details for Storage Accounts."""
    logging.info(f"[{subscription_id}] Fetching storage account details...")
    
    storage_data = {
        "storage_accounts": [],
        "private_endpoints": [],
        "management_policies": []
    }
    
    try:
        storage_client = StorageManagementClient(credential, subscription_id)
        
        # Fetch Storage Accounts
        accounts = list(storage_client.storage_accounts.list())
        logging.info(f"[{subscription_id}] Found {len(accounts)} storage accounts.")
        
        for account in accounts:
            # Get the full properties of the storage account
            try:
                account_props = storage_client.storage_accounts.get_properties(
                    account.id.split('/')[4],  # Resource group name from ID
                    account.name
                )
                
                account_details = {
                    "id": account.id,
                    "name": account.name,
                    "resource_group": account.id.split('/')[4],  # Extract resource group from ID
                    "location": account.location,
                    "sku": {
                        "name": account.sku.name if account.sku else None,
                        "tier": account.sku.tier if account.sku else None
                    },
                    "kind": account.kind,
                    "access_tier": account.access_tier,
                    "creation_time": str(account.creation_time) if account.creation_time else None,
                    "enable_https_traffic_only": account.enable_https_traffic_only,
                    "is_hns_enabled": account.is_hns_enabled,  # Hierarchical Namespace
                    "minimum_tls_version": account.minimum_tls_version,
                    "provisioning_state": account.provisioning_state,
                    "primary_location": account.primary_location,
                    "secondary_location": account.secondary_location,
                    "status_of_primary": account.status_of_primary,
                    "status_of_secondary": account.status_of_secondary,
                    "encryption": {
                        "services": {
                            "blob": {
                                "enabled": account.encryption.services.blob.enabled if account.encryption and account.encryption.services and account.encryption.services.blob else None
                            },
                            "file": {
                                "enabled": account.encryption.services.file.enabled if account.encryption and account.encryption.services and account.encryption.services.file else None
                            },
                            "table": {
                                "enabled": account.encryption.services.table.enabled if account.encryption and account.encryption.services and account.encryption.services.table else None
                            },
                            "queue": {
                                "enabled": account.encryption.services.queue.enabled if account.encryption and account.encryption.services and account.encryption.services.queue else None
                            }
                        },
                        "key_source": str(account.encryption.key_source) if account.encryption else None,
                        "key_vault_properties": account.encryption.key_vault_properties.__dict__ if account.encryption and account.encryption.key_vault_properties else None
                    },
                    "network_rule_set": {
                        "bypass": [str(bypass) for bypass in account.network_rule_set.bypass] if account.network_rule_set else [],
                        "default_action": str(account.network_rule_set.default_action) if account.network_rule_set else None,
                        "ip_rules": [rule.ip_address_or_range for rule in account.network_rule_set.ip_rules] if account.network_rule_set and account.network_rule_set.ip_rules else [],
                        "virtual_network_rules": [rule.virtual_network_resource_id for rule in account.network_rule_set.virtual_network_rules] if account.network_rule_set and account.network_rule_set.virtual_network_rules else []
                    },
                    "private_endpoint_connections": [
                        {
                            "id": conn.id,
                            "private_endpoint": {
                                "id": conn.private_endpoint.id if conn.private_endpoint else None
                            },
                            "state": str(conn.private_link_service_connection_state.status) if conn.private_link_service_connection_state else None
                        } for conn in account.private_endpoint_connections
                    ] if account.private_endpoint_connections else [],
                    "routing_preference": {
                        "routing_choice": str(account.routing_preference.routing_choice) if account.routing_preference else None,
                        "publish_microsoft_endpoints": account.routing_preference.publish_microsoft_endpoints if account.routing_preference else None,
                        "publish_internet_endpoints": account.routing_preference.publish_internet_endpoints if account.routing_preference else None
                    },
                    "tags": account.tags
                }
                
                # Get blob service properties for soft delete settings
                try:
                    rg_name = account.id.split('/')[4]  # Extract resource group from ID
                    blob_props = storage_client.blob_services.get_service_properties(
                        rg_name,
                        account.name
                    )
                    account_details["blob_service_properties"] = {
                        "delete_retention_policy": {
                            "enabled": blob_props.delete_retention_policy.enabled if blob_props.delete_retention_policy else None,
                            "days": blob_props.delete_retention_policy.days if blob_props.delete_retention_policy else None
                        },
                        "container_delete_retention_policy": {
                            "enabled": blob_props.container_delete_retention_policy.enabled if blob_props.container_delete_retention_policy else None,
                            "days": blob_props.container_delete_retention_policy.days if blob_props.container_delete_retention_policy else None
                        },
                        "is_versioning_enabled": blob_props.is_versioning_enabled
                    }
                except Exception as blob_e:
                    logging.warning(f"[{subscription_id}] Could not fetch blob service properties for account {account.name}: {blob_e}")
                
                # Get management policies
                try:
                    policy = storage_client.management_policies.get(
                        rg_name,  # Use the extracted resource group name
                        account.name,
                        "default"  # The default management policy name
                    )
                    if policy.policy:
                        storage_data["management_policies"].append({
                            "storage_account_id": account.id,
                            "storage_account_name": account.name,
                            "rules": policy.policy.rules
                        })
                except HttpResponseError as policy_e:
                    if policy_e.status_code == 404:
                        # This is normal - not all storage accounts have management policies
                        logging.debug(f"[{subscription_id}] No management policy found for account {account.name}")
                    else:
                        logging.warning(f"[{subscription_id}] Error fetching management policy for account {account.name}: {policy_e}")
                except Exception as policy_e:
                    logging.warning(f"[{subscription_id}] Error fetching management policy for account {account.name}: {policy_e}")
                
                storage_data["storage_accounts"].append(account_details)
                
            except Exception as props_e:
                logging.error(f"[{subscription_id}] Error fetching properties for storage account {account.name}: {props_e}")
                # Add basic details even if detailed properties fetch fails
                storage_data["storage_accounts"].append({
                    "id": account.id,
                    "name": account.name,
                    "resource_group": account.resource_group_name,
                    "location": account.location,
                    "error": str(props_e)
                })
                
    except HttpResponseError as e:
        if e.status_code == 403:
            logging.warning(f"[{subscription_id}] Authorization failed for storage resources: {e.message}")
        else:
            logging.error(f"[{subscription_id}] Error fetching storage resources: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching storage resources: {e}")
    
    return storage_data 