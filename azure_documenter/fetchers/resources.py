import logging
from azure.mgmt.resource import ResourceManagementClient

def fetch_resources(credential, subscription_id):
    """Fetches basic details for all resources in a subscription."""
    logging.info(f"[{subscription_id}] Fetching resources...")
    resources_list = []
    try:
        resource_client = ResourceManagementClient(credential, subscription_id)
        for resource in resource_client.resources.list():
            resources_list.append({
                "id": resource.id,
                "name": resource.name,
                "type": resource.type,
                "location": resource.location,
                "resource_group": resource.id.split('/')[4], # Extract RG from ID
                "tags": resource.tags
            })
        logging.info(f"[{subscription_id}] Found {len(resources_list)} resources.")
        return resources_list
    except Exception as e:
        logging.error(f"[{subscription_id}] Failed to fetch resources: {e}")
        # Optionally, check for specific exceptions like AuthorizationFailedError
        # from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
        # if isinstance(e, (ClientAuthenticationError, HttpResponseError)):
        #     if e.status_code == 403:
        #         logging.warning(f"[{subscription_id}] Authorization failed. Skipping resource fetch.")
        #     else:
        #         logging.error(f"[{subscription_id}] Error fetching resources: {e.message}")
        # else:
        #      logging.error(f"[{subscription_id}] Unexpected error fetching resources: {e}")
        return [] 