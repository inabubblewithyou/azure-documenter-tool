import logging
import asyncio
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
from azure.mgmt.machinelearningservices import AzureMachineLearningWorkspaces
from azure.core.exceptions import HttpResponseError

async def fetch_ai_services(credential, subscription_id):
    """Fetches details for Azure AI services including Cognitive Services, Machine Learning workspaces, and OpenAI services."""
    logging.info(f"[{subscription_id}] Fetching AI service details...")
    
    ai_data = {
        "cognitive_services": [],
        "ml_workspaces": [],
        "openai_services": [],
        "search_services": [],
        "bot_services": []
    }
    
    # Fetch Cognitive Services accounts
    try:
        cognitive_client = CognitiveServicesManagementClient(credential, subscription_id)
        accounts = list(cognitive_client.accounts.list())
        logging.info(f"[{subscription_id}] Found {len(accounts)} Cognitive Services accounts.")
        
        for account in accounts:
            # Determine if this is an OpenAI service
            is_openai = account.kind.lower() == "openai"
            
            account_details = {
                "id": account.id,
                "name": account.name,
                "location": account.location,
                "resource_group": account.id.split('/')[4],
                "kind": account.kind,
                "sku": {
                    "name": account.sku.name if account.sku else None,
                    "tier": account.sku.tier if account.sku else None
                },
                "endpoint": account.properties.endpoint if hasattr(account.properties, 'endpoint') else None,
                "custom_sub_domain_name": account.properties.custom_sub_domain_name if hasattr(account.properties, 'custom_sub_domain_name') else None,
                "network_acls": {
                    "default_action": str(account.properties.network_acls.default_action) if account.properties.network_acls else None,
                    "ip_rules": [rule.value for rule in account.properties.network_acls.ip_rules] if account.properties.network_acls and account.properties.network_acls.ip_rules else [],
                    "virtual_network_rules": [rule.id for rule in account.properties.network_acls.virtual_network_rules] if account.properties.network_acls and account.properties.network_acls.virtual_network_rules else []
                } if hasattr(account.properties, 'network_acls') else None,
                "public_network_access": str(account.properties.public_network_access) if hasattr(account.properties, 'public_network_access') else None,
                "identity": {
                    "type": str(account.identity.type) if account.identity else None,
                    "principal_id": account.identity.principal_id if account.identity else None,
                    "tenant_id": account.identity.tenant_id if account.identity else None
                } if account.identity else None,
                "tags": account.tags
            }
            
            # Add deployment details for OpenAI services
            if is_openai:
                try:
                    deployments = list(cognitive_client.deployments.list(
                        account.resource_group_name,
                        account.name
                    ))
                    account_details["deployments"] = [{
                        "name": dep.name,
                        "model": dep.properties.model.name if dep.properties.model else None,
                        "version": dep.properties.model.version if dep.properties.model else None,
                        "sku": {
                            "name": dep.sku.name if dep.sku else None,
                            "capacity": dep.sku.capacity if dep.sku else None
                        }
                    } for dep in deployments]
                except Exception as e:
                    logging.warning(f"[{subscription_id}] Could not fetch deployments for OpenAI service {account.name}: {e}")
                    account_details["deployments"] = []
                
                ai_data["openai_services"].append(account_details)
            else:
                ai_data["cognitive_services"].append(account_details)
                
    except HttpResponseError as e:
        if e.status_code == 403:
            logging.warning(f"[{subscription_id}] Authorization failed for Cognitive Services: {e.message}")
        else:
            logging.error(f"[{subscription_id}] Error fetching Cognitive Services: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching Cognitive Services: {e}")

    # Fetch Machine Learning workspaces
    try:
        ml_client = AzureMachineLearningWorkspaces(credential, subscription_id)
        workspaces = list(ml_client.workspaces.list())
        logging.info(f"[{subscription_id}] Found {len(workspaces)} Machine Learning workspaces.")
        
        for ws in workspaces:
            workspace_details = {
                "id": ws.id,
                "name": ws.name,
                "location": ws.location,
                "resource_group": ws.id.split('/')[4],
                "sku": ws.sku,
                "workspace_url": ws.workspace_url if hasattr(ws, 'workspace_url') else None,
                "discovery_url": ws.discovery_url if hasattr(ws, 'discovery_url') else None,
                "storage_account": ws.storage_account if hasattr(ws, 'storage_account') else None,
                "key_vault": ws.key_vault if hasattr(ws, 'key_vault') else None,
                "container_registry": ws.container_registry if hasattr(ws, 'container_registry') else None,
                "application_insights": ws.application_insights if hasattr(ws, 'application_insights') else None,
                "public_network_access": str(ws.public_network_access) if hasattr(ws, 'public_network_access') else None,
                "identity": {
                    "type": str(ws.identity.type) if ws.identity else None,
                    "principal_id": ws.identity.principal_id if ws.identity else None,
                    "tenant_id": ws.identity.tenant_id if ws.identity else None
                } if ws.identity else None,
                "tags": ws.tags
            }
            
            # Try to fetch compute targets
            try:
                computes = list(ml_client.compute.list(ws.resource_group_name, ws.name))
                workspace_details["compute_targets"] = [{
                    "name": compute.name,
                    "type": compute.type,
                    "provisioning_state": compute.provisioning_state,
                    "description": compute.description
                } for compute in computes]
            except Exception as e:
                logging.warning(f"[{subscription_id}] Could not fetch compute targets for workspace {ws.name}: {e}")
                workspace_details["compute_targets"] = []
            
            ai_data["ml_workspaces"].append(workspace_details)
            
    except HttpResponseError as e:
        if e.status_code == 403:
            logging.warning(f"[{subscription_id}] Authorization failed for Machine Learning workspaces: {e.message}")
        else:
            logging.error(f"[{subscription_id}] Error fetching Machine Learning workspaces: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching Machine Learning workspaces: {e}")

    # Fetch Azure Search services
    try:
        from azure.mgmt.search import SearchManagementClient
        search_client = SearchManagementClient(credential, subscription_id)
        services = list(search_client.services.list_by_subscription())
        logging.info(f"[{subscription_id}] Found {len(services)} Search services.")
        
        for service in services:
            service_details = {
                "id": service.id,
                "name": service.name,
                "location": service.location,
                "resource_group": service.id.split('/')[4],
                "sku": {
                    "name": service.sku.name if service.sku else None,
                    "tier": service.sku.tier if service.sku else None
                },
                "replica_count": service.replica_count,
                "partition_count": service.partition_count,
                "hosting_mode": str(service.hosting_mode) if service.hosting_mode else None,
                "public_network_access": str(service.public_network_access) if hasattr(service, 'public_network_access') else None,
                "network_rulesets": {
                    "ip_rules": [rule.value for rule in service.network_rulesets.ip_rules] if service.network_rulesets and service.network_rulesets.ip_rules else [],
                    "virtual_network_rules": [rule.id for rule in service.network_rulesets.virtual_network_rules] if service.network_rulesets and service.network_rulesets.virtual_network_rules else []
                } if hasattr(service, 'network_rulesets') else None,
                "identity": {
                    "type": str(service.identity.type) if service.identity else None,
                    "principal_id": service.identity.principal_id if service.identity else None,
                    "tenant_id": service.identity.tenant_id if service.identity else None
                } if service.identity else None,
                "tags": service.tags
            }
            ai_data["search_services"].append(service_details)
            
    except ImportError:
        logging.warning(f"[{subscription_id}] Azure Search SDK not installed. Skipping Search services.")
    except HttpResponseError as e:
        if e.status_code == 403:
            logging.warning(f"[{subscription_id}] Authorization failed for Search services: {e.message}")
        else:
            logging.error(f"[{subscription_id}] Error fetching Search services: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching Search services: {e}")

    logging.info(f"[{subscription_id}] Finished fetching AI service details.")
    return ai_data 