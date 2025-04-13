# azure_documenter/fetchers/scaling.py
import logging
import asyncio # Import asyncio
from azure.mgmt.monitor import MonitorManagementClient
from azure.core.exceptions import HttpResponseError

async def fetch_autoscale_settings(credential, subscription_id):
    """Fetches Autoscale settings for the subscription."""
    logging.info(f"[{subscription_id}] Fetching Autoscale settings...")
    autoscale_settings_data = []
    try:
        monitor_client = MonitorManagementClient(credential, subscription_id)
        settings = list(monitor_client.autoscale_settings.list_by_subscription())
        logging.info(f"[{subscription_id}] Found {len(settings)} Autoscale settings.")

        for setting in settings:
            profiles_summary = []
            if setting.profiles:
                for profile in setting.profiles:
                    capacity_info = profile.capacity
                    if capacity_info:
                        profiles_summary.append({
                            "name": profile.name,
                            "min_capacity": capacity_info.minimum,
                            "max_capacity": capacity_info.maximum,
                            "default_capacity": capacity_info.default
                        })
                    else:
                        profiles_summary.append({"name": profile.name, "capacity": "N/A"})


            setting_details = {
                "id": setting.id,
                "name": setting.name,
                "location": setting.location,
                "resource_group": setting.id.split('/')[4] if len(setting.id.split('/')) > 4 else 'Unknown',
                "target_resource_uri": setting.target_resource_uri,
                "enabled": setting.enabled,
                "profiles": profiles_summary, # List of profile summaries
                "tags": setting.tags
            }
            autoscale_settings_data.append(setting_details)

    except HttpResponseError as e:
        # Check for specific errors like provider not registered
        if "Microsoft.Insights" in str(e) and "not registered" in str(e).lower():
             logging.warning(f"[{subscription_id}] Could not list Autoscale settings: Microsoft.Insights provider may not be registered. Skipping. Error: {e.message}")
        elif e.status_code == 403:
             logging.warning(f"[{subscription_id}] Authorization failed for listing Autoscale settings (Check Permissions?): {e.message}. Skipping.")
        else:
            logging.warning(f"[{subscription_id}] HTTP error listing Autoscale settings: {e.message}")
    except ImportError:
         # Catch if azure-mgmt-monitor is not installed
         logging.error(f"[{subscription_id}] Failed to fetch Autoscale settings: azure-mgmt-monitor library not found. Please install it.")
         # Optional: Re-raise or return specific error code
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching Autoscale settings: {e}")

    logging.info(f"[{subscription_id}] Finished fetching Autoscale settings.")
    # Return the data within a dictionary for consistency
    return {"autoscale_settings": autoscale_settings_data} 