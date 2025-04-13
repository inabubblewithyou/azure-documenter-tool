import logging
import asyncio # Import asyncio
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.core.exceptions import HttpResponseError

async def fetch_resources(credential, subscription_id):
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

async def fetch_app_service_details(credential, subscription_id, resource_group_name, app_name):
    """Fetches detailed configuration for a specific App Service."""
    logging.info(f"[{subscription_id}] Fetching details for App Service '{app_name}' in RG '{resource_group_name}'...")
    app_details = {
        'configuration': None,
        'connection_strings': None,
        'metadata': None,
        'auth_settings': None,
        # Add more details as needed (e.g., site properties, diagnostic settings)
    }
    try:
        web_client = WebSiteManagementClient(credential, subscription_id)

        # Get general configuration (app settings, general settings)
        try:
            app_details['configuration'] = web_client.web_apps.list_application_settings(resource_group_name, app_name).properties
        except HttpResponseError as e:
            logging.warning(f"[{subscription_id}] Could not fetch application settings for {app_name}: {e}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching application settings for {app_name}: {e}")

        # Get connection strings
        try:
            app_details['connection_strings'] = web_client.web_apps.list_connection_strings(resource_group_name, app_name).properties
        except HttpResponseError as e:
            logging.warning(f"[{subscription_id}] Could not fetch connection strings for {app_name}: {e}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching connection strings for {app_name}: {e}")

        # Get metadata (potentially useful properties)
        try:
            app_details['metadata'] = web_client.web_apps.list_metadata(resource_group_name, app_name).properties
        except HttpResponseError as e:
            logging.warning(f"[{subscription_id}] Could not fetch metadata for {app_name}: {e}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching metadata for {app_name}: {e}")

        # Get Authentication / Authorization settings (V2)
        try:
            auth_settings_obj = web_client.web_apps.get_auth_settings_v2(resource_group_name, app_name)
            # Convert the SDK object to a dictionary for consistent storage
            if hasattr(auth_settings_obj, 'as_dict'):
                app_details['auth_settings'] = auth_settings_obj.as_dict()
            else:
                # Fallback if as_dict() isn't available (less likely for newer SDKs)
                # This might need refinement based on the actual object structure if as_dict fails
                app_details['auth_settings'] = str(auth_settings_obj) # Store as string as a basic fallback
                logging.warning(f"[{subscription_id}] Could not convert auth_settings object to dict for {app_name}. Storing as string.")

        except HttpResponseError as e:
            # Might return 404 if auth settings are not configured, which is okay.
            if e.status_code != 404:
                logging.warning(f"[{subscription_id}] Could not fetch auth settings for {app_name}: {e}")
            else:
                logging.info(f"[{subscription_id}] No explicit auth settings found for {app_name}.")
                app_details['auth_settings'] = {} # Indicate no settings found
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching auth settings for {app_name}: {e}")
            app_details['auth_settings'] = {'error': str(e)} # Store error indication

        # TODO: Fetch other details like:
        # - General site properties: web_client.web_apps.get(resource_group_name, app_name)
        # - Source control: web_client.web_apps.get_source_control(...)
        # - VNet integration: web_client.web_apps.get_virtual_network_connection(...)
        # - Diagnostic settings (requires Monitor client)

        logging.info(f"[{subscription_id}] Successfully fetched details for App Service '{app_name}'.")
        return app_details

    except Exception as e:
        logging.error(f"[{subscription_id}] Failed to initialize WebSiteManagementClient or other critical error for {app_name}: {e}")
        return app_details # Return partially fetched details or defaults 