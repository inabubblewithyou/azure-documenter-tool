"""
Module for fetching Azure AI and Machine Learning services details.
"""
import logging
from typing import Dict, Any, List

from azure.core.exceptions import HttpResponseError
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
from azure.mgmt.search import SearchManagementClient
from azure.mgmt.botservice import AzureBotService

logger = logging.getLogger(__name__)

async def fetch_ai_services(credential, subscription_id: str) -> Dict[str, Any]:
    """
    Fetches details about AI services in the subscription including:
    - Cognitive Services
    - Azure Search Services
    - Bot Services
    
    Args:
        credential: Azure credential object
        subscription_id: Target subscription ID

    Returns:
        Dictionary containing AI services information
    """
    ai_services_data = {
        "cognitive_services": [],
        "search_services": [],
        "bot_services": []
    }

    try:
        # Initialize clients
        cognitive_client = CognitiveServicesManagementClient(credential, subscription_id)
        search_client = SearchManagementClient(credential, subscription_id)
        bot_client = AzureBotService(credential, subscription_id)

        # Fetch Cognitive Services accounts
        try:
            accounts = list(cognitive_client.accounts.list())
            logger.info(f"[{subscription_id}] Found {len(accounts)} Cognitive Services accounts")
            
            for account in accounts:
                account_data = {
                    "name": account.name,
                    "type": account.kind,
                    "location": account.location,
                    "sku": account.sku.name if account.sku else None,
                    "endpoint": account.properties.endpoint if hasattr(account.properties, 'endpoint') else None,
                    "resource_group": account.id.split('/')[4] if account.id else None
                }
                ai_services_data["cognitive_services"].append(account_data)
        except HttpResponseError as e:
            logger.warning(f"Failed to fetch Cognitive Services accounts: {str(e)}")

        # Fetch Search Services
        try:
            services = list(search_client.services.list_by_subscription())
            logger.info(f"[{subscription_id}] Found {len(services)} Search services")
            
            for service in services:
                service_data = {
                    "name": service.name,
                    "location": service.location,
                    "sku": service.sku.name if service.sku else None,
                    "replica_count": service.replica_count,
                    "partition_count": service.partition_count,
                    "hosting_mode": service.hosting_mode,
                    "resource_group": service.id.split('/')[4] if service.id else None
                }
                ai_services_data["search_services"].append(service_data)
        except HttpResponseError as e:
            logger.warning(f"Failed to fetch Search services: {str(e)}")

        # Fetch Bot Services
        try:
            bots = list(bot_client.bots.list())
            logger.info(f"[{subscription_id}] Found {len(bots)} Bot services")
            
            for bot in bots:
                bot_data = {
                    "name": bot.name,
                    "location": bot.location,
                    "kind": bot.kind,
                    "sku": bot.sku.name if bot.sku else None,
                    "microsoft_app_id": bot.microsoft_app_id,
                    "resource_group": bot.id.split('/')[4] if bot.id else None
                }
                ai_services_data["bot_services"].append(bot_data)
        except HttpResponseError as e:
            logger.warning(f"Failed to fetch Bot services: {str(e)}")

    except Exception as e:
        logger.error(f"Error fetching AI services data: {str(e)}")
        raise

    return ai_services_data 