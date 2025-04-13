import logging
import asyncio # Import asyncio
from azure.mgmt.web import WebSiteManagementClient
from azure.core.exceptions import HttpResponseError

async def fetch_app_service_details(credential, subscription_id):
    """Fetches details for App Services and Function Apps, including their settings."""
    logging.info(f"[{subscription_id}] Fetching App Service and Function App details...")
    web_client = WebSiteManagementClient(credential, subscription_id)
    apps_data = {
        "app_services": [],
        "function_apps": [],
        "app_settings": [], # Consolidated list of settings from all apps
        "app_service_plans": {} # Map of plan IDs to plan details
    }

    # First fetch all App Service Plans
    try:
        plans = list(web_client.app_service_plans.list())
        logging.info(f"[{subscription_id}] Found {len(plans)} App Service Plans.")
        for plan in plans:
            apps_data["app_service_plans"][plan.id.lower()] = {
                "id": plan.id,
                "name": plan.name,
                "resource_group": plan.resource_group,
                "location": plan.location,
                "sku": {
                    "name": plan.sku.name if plan.sku else None,
                    "tier": plan.sku.tier if plan.sku else None,
                    "size": plan.sku.size if plan.sku else None,
                    "capacity": plan.sku.capacity if plan.sku else None
                },
                "kind": plan.kind,
                "reserved": plan.reserved  # True for Linux plans
            }
    except HttpResponseError as e:
        if e.status_code == 403:
            logging.warning(f"[{subscription_id}] Authorization failed for listing app service plans: {e.message}")
        else:
            logging.error(f"[{subscription_id}] Error fetching app service plans: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching app service plans: {e}")

    try:
        web_apps = list(web_client.web_apps.list())
        logging.info(f"[{subscription_id}] Found {len(web_apps)} App Services/Function Apps.")

        for app in web_apps:
            # Get site config for runtime info
            try:
                site_config = web_client.web_apps.get_configuration(app.resource_group, app.name)
                runtime_info = {
                    "linux_fx_version": site_config.linux_fx_version,
                    "windows_fx_version": site_config.windows_fx_version,
                    "java_version": site_config.java_version,
                    "java_container": site_config.java_container,
                    "java_container_version": site_config.java_container_version,
                    "php_version": site_config.php_version,
                    "python_version": site_config.python_version,
                    "node_version": site_config.node_version,
                    "net_framework_version": site_config.net_framework_version,
                    "current_stack": next((meta.value for meta in (site_config.metadata or []) if meta.name == "CURRENT_STACK"), None)
                }
            except Exception as config_e:
                logging.warning(f"[{subscription_id}] Could not fetch site config for app '{app.name}': {config_e}")
                runtime_info = {}

            # Get associated App Service Plan details
            plan_id = app.server_farm_id.lower() if app.server_farm_id else None
            plan_details = apps_data["app_service_plans"].get(plan_id, {}) if plan_id else {}

            app_details = {
                "id": app.id,
                "name": app.name,
                "location": app.location,
                "resource_group": app.resource_group,
                "kind": app.kind, # Identifies if it's 'app', 'functionapp', 'api', etc.
                "state": app.state,
                "host_names": app.host_names,
                "https_only": app.https_only,
                "identity": {
                    "type": str(app.identity.type) if app.identity else None,
                    "principal_id": app.identity.principal_id if app.identity else None,
                    "tenant_id": app.identity.tenant_id if app.identity else None
                } if app.identity else None,
                "tags": app.tags,
                "runtime": runtime_info,
                "app_service_plan": {
                    "id": plan_id,
                    "name": plan_details.get("name"),
                    "sku": plan_details.get("sku"),
                    "kind": plan_details.get("kind"),
                    "reserved": plan_details.get("reserved")
                } if plan_id else None
            }

            is_function_app = "functionapp" in (app.kind or "").lower()
            if is_function_app:
                apps_data["function_apps"].append(app_details)
            else:
                apps_data["app_services"].append(app_details)

            # --- Fetch App Settings --- 
            try:
                settings = web_client.web_apps.list_application_settings(app.resource_group, app.name)
                if settings.properties:
                    logging.info(f"[{subscription_id}] Fetched {len(settings.properties)} settings for app '{app.name}'.")
                    app_settings_list = [
                        {"app_id": app.id, "app_name": app.name, "name": key, "value": "***" if "secret" in key.lower() or "key" in key.lower() or "connection" in key.lower() else value} 
                        for key, value in settings.properties.items()
                    ]
                    apps_data["app_settings"].extend(app_settings_list)
                else:
                    logging.info(f"[{subscription_id}] No application settings found for app '{app.name}'.")
            except HttpResponseError as settings_e:
                logging.warning(f"[{subscription_id}] Could not list settings for app '{app.name}' (RG: {app.resource_group}): {settings_e.message}")
            except Exception as settings_e:
                logging.error(f"[{subscription_id}] Unexpected error fetching settings for app '{app.name}': {settings_e}")

    except HttpResponseError as e:
        if e.status_code == 403:
            logging.warning(f"[{subscription_id}] Authorization failed for listing web apps: {e.message}. Skipping app services.")
        else:
            logging.error(f"[{subscription_id}] Error fetching web apps: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching web apps: {e}")

    logging.info(f"[{subscription_id}] Finished fetching App Service details.")
    return apps_data 