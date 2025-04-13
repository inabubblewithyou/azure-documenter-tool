import logging
import asyncio # Import asyncio
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.loganalytics import LogAnalyticsManagementClient # <-- Import Log Analytics client
from azure.core.exceptions import HttpResponseError

async def fetch_monitoring_details(credential, subscription_id):
    """Fetches Diagnostic Settings, Alert Rules, and Log Analytics Workspaces for a subscription."""
    logging.info(f"[{subscription_id}] Fetching monitoring details (Diagnostics, Alerts, LA Workspaces)...")
    monitor_client = MonitorManagementClient(credential, subscription_id)
    # Initialize Log Analytics client as well
    try:
        loganalytics_client = LogAnalyticsManagementClient(credential, subscription_id)
    except Exception as e:
        logging.error(f"[{subscription_id}] Failed to initialize LogAnalyticsManagementClient: {e}")
        loganalytics_client = None # Set to None to skip LA workspace fetch

    monitor_data = {
        "log_analytics_workspaces": [], # <-- Add key for workspaces
        "diagnostic_settings": [],
        "alert_rules": []
    }

    # --- Fetch Log Analytics Workspaces ---
    if loganalytics_client: # Only proceed if client initialized successfully
        try:
            workspaces = list(loganalytics_client.workspaces.list())
            logging.info(f"[{subscription_id}] Found {len(workspaces)} Log Analytics workspaces.")
            for ws in workspaces:
                # Get workspace features and solutions
                features = []
                solutions = []
                try:
                    features = list(loganalytics_client.workspaces.get_features(ws.resource_group_name, ws.name))
                    solutions = list(loganalytics_client.solutions.list_by_workspace(ws.resource_group_name, ws.name))
                except Exception as feature_e:
                    logging.warning(f"[{subscription_id}] Could not fetch features/solutions for workspace {ws.name}: {feature_e}")

                # Get linked services
                linked_services = []
                try:
                    services = list(loganalytics_client.linked_services.list(ws.resource_group_name, ws.name))
                    linked_services = [{"name": svc.name, "type": svc.type} for svc in services if hasattr(svc, 'name') and hasattr(svc, 'type')]
                except Exception as link_e:
                    logging.warning(f"[{subscription_id}] Could not fetch linked services for workspace {ws.name}: {link_e}")

                ws_details = {
                    "id": ws.id,
                    "name": ws.name,
                    "location": ws.location,
                    "resource_group": ws.id.split('/')[4] if '/' in ws.id else 'Unknown',
                    "sku": ws.sku.name if ws.sku else "Unknown",
                    "retention_in_days": ws.retention_in_days if hasattr(ws, 'retention_in_days') and ws.retention_in_days is not None else "Unknown",
                    "tags": ws.tags,
                    # Include properties which might have nested SKU/retention if direct attributes fail
                    "properties": {
                        "sku_name": ws.properties.sku.name if ws.properties and ws.properties.sku else "Unknown",
                        "retentionInDays": ws.properties.retention_in_days if ws.properties and hasattr(ws.properties, 'retention_in_days') else "Unknown",
                        "features": [{"name": f.name, "state": f.state} for f in features] if features else [],
                        "solutions": [{"name": s.name, "product": s.properties.product_name if hasattr(s, 'properties') and hasattr(s.properties, 'product_name') else None} for s in solutions] if solutions else [],
                        "linked_services": linked_services
                    }
                }
                # Refine SKU and Retention extraction, prioritizing direct attributes
                if ws_details["sku"] == "Unknown" and ws_details["properties"]["sku_name"] != "Unknown":
                    ws_details["sku"] = ws_details["properties"]["sku_name"]
                if ws_details["retention_in_days"] == "Unknown" and ws_details["properties"]["retentionInDays"] != "Unknown":
                    ws_details["retention_in_days"] = ws_details["properties"]["retentionInDays"]

                monitor_data["log_analytics_workspaces"].append(ws_details)
        except HttpResponseError as e:
             if e.status_code == 403:
                 logging.warning(f"[{subscription_id}] Authorization failed for Log Analytics Workspaces: {e.message}. Skipping.")
             elif "SubscriptionNotRegistered" in str(e) or "is not registered to use namespace 'microsoft.operationalinsights'" in str(e).lower():
                 logging.warning(f"[{subscription_id}] Log Analytics provider (microsoft.operationalinsights) not registered: {e.message}. Skipping LA Workspaces.")
             else:
                 logging.warning(f"[{subscription_id}] Could not list Log Analytics Workspaces: {e.message}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching Log Analytics Workspaces: {e}", exc_info=True)
    else:
         logging.warning(f"[{subscription_id}] Skipping Log Analytics workspace fetch due to client initialization failure.")

    # --- Fetch Diagnostic Settings (Subscription Scope) ---
    # Note: This lists settings defined AT the subscription scope.
    # Getting settings FOR specific resources requires iterating over resource IDs.
    # We'll start with subscription-level settings for now.
    try:
        diag_settings = list(monitor_client.diagnostic_settings.list(resource_uri=f"subscriptions/{subscription_id}"))
        logging.info(f"[{subscription_id}] Found {len(diag_settings)} diagnostic settings at subscription scope.")
        for setting in diag_settings:
            setting_details = {
                "id": setting.id,
                "name": setting.name,
                "resource_uri": f"subscriptions/{subscription_id}", # Explicitly stating scope
                "storage_account_id": setting.storage_account_id,
                "service_bus_rule_id": setting.service_bus_rule_id,
                "event_hub_authorization_rule_id": setting.event_hub_authorization_rule_id,
                "event_hub_name": setting.event_hub_name,
                "workspace_id": setting.workspace_id,
                "log_analytics_destination_type": setting.log_analytics_destination_type,
                "logs": [{"category": log.category, "enabled": log.enabled} for log in setting.logs] if setting.logs else [],
                "metrics": [{"category": metric.category, "enabled": metric.enabled, "time_grain": str(metric.time_grain)} for metric in setting.metrics] if setting.metrics else []
            }
            monitor_data["diagnostic_settings"].append(setting_details)
        # TODO: Consider iterating resource list to get resource-specific diagnostics
    except HttpResponseError as e:
         if "SubscriptionNotFound" in str(e) or "ResourceNotFound" in str(e):
              logging.warning(f"[{subscription_id}] Could not find subscription resource URI for diagnostic settings list: {e.message}")
         elif e.status_code == 403:
              logging.warning(f"[{subscription_id}] Authorization failed for Diagnostic Settings: {e.message}. Skipping.")
         else:
             logging.warning(f"[{subscription_id}] Could not list subscription-level Diagnostic Settings: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching subscription-level Diagnostic Settings: {e}")


    # --- Fetch Alert Rules (Subscription Scope) ---
    # This fetches classic metric alerts, activity log alerts, and log alerts (scheduled query rules)
    try:
        # Metric Alerts (includes v2 alerts)
        metric_alerts = list(monitor_client.metric_alerts.list_by_subscription())
        logging.info(f"[{subscription_id}] Found {len(metric_alerts)} metric alert rules.")
        for alert in metric_alerts:
             alert_details = {
                 "id": alert.id,
                 "name": alert.name,
                 "location": "global", # Metric alerts are global but evaluated on regional resources
                 "resource_group": alert.id.split('/')[4],
                 "type": "Metric",
                 "description": alert.description,
                 "severity": alert.severity,
                 "enabled": alert.enabled,
                 "scopes": alert.scopes, # List of resource IDs targeted
                 "evaluation_frequency": str(alert.evaluation_frequency),
                 "window_size": str(alert.window_size),
                 "criteria_type": alert.criteria.odata_type if alert.criteria else "Unknown",
                 "tags": alert.tags
                 # alert.criteria contains the specific conditions (complex object)
             }
             monitor_data["alert_rules"].append(alert_details)

        # Activity Log Alerts
        activity_log_alerts = list(monitor_client.activity_log_alerts.list_by_subscription_id())
        logging.info(f"[{subscription_id}] Found {len(activity_log_alerts)} activity log alert rules.")
        for alert in activity_log_alerts:
             alert_details = {
                 "id": alert.id,
                 "name": alert.name,
                 "location": alert.location, # Often 'global'
                 "resource_group": alert.id.split('/')[4],
                 "type": "Activity Log",
                 "description": alert.description,
                 "enabled": alert.enabled,
                 "scopes": alert.scopes, # List of resource IDs/subscription/RG targeted
                 "condition": alert.condition.__dict__ if alert.condition else None, # Condition details
                 "actions": alert.actions.__dict__ if alert.actions else None, # Action group details
                 "tags": alert.tags
             }
             monitor_data["alert_rules"].append(alert_details)

        # Log Alerts (Scheduled Query Rules V1 & V2)
        # Note: Requires Log Analytics workspace insights potentially
        log_alerts = list(monitor_client.scheduled_query_rules.list_by_subscription())
        logging.info(f"[{subscription_id}] Found {len(log_alerts)} scheduled query (Log Alert) rules.")
        for alert in log_alerts:
             alert_details = {
                 "id": alert.id,
                 "name": alert.name,
                 "location": alert.location,
                 "resource_group": alert.id.split('/')[4],
                 "type": "Log Alert",
                 "kind": alert.kind, # V1 or V2 (LogAlert, LogToMetric)
                 "description": alert.description,
                 "severity": alert.severity if hasattr(alert, 'severity') else None, # V2 only
                 "enabled": alert.enabled if hasattr(alert, 'enabled') else None, # V1 only uses 'provisioning_state'? Check enabled state based on type/version
                 "source": alert.source.__dict__ if alert.source else None, # Query details
                 "schedule": alert.schedule.__dict__ if alert.schedule else None, # How often query runs
                 "action": alert.action.__dict__ if alert.action else None, # What action to take
                 "scopes": alert.scopes if hasattr(alert, 'scopes') else None, # V2 only
                 "target_resource_types": alert.target_resource_types if hasattr(alert, 'target_resource_types') else None, # V2 only
                 "tags": alert.tags
             }
             monitor_data["alert_rules"].append(alert_details)

    except HttpResponseError as e:
        if e.status_code == 403:
             logging.warning(f"[{subscription_id}] Authorization failed for Monitor Alert Rules: {e.message}. Skipping.")
        elif "SubscriptionNotRegistered" in str(e) or "is not registered to use namespace 'microsoft.insights'" in str(e).lower():
             logging.warning(f"[{subscription_id}] Monitor provider (microsoft.insights) not registered: {e.message}. Skipping alerts.")
        else:
            logging.warning(f"[{subscription_id}] Could not list some Alert Rules: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching Alert Rules: {e}")


    logging.info(f"[{subscription_id}] Finished fetching monitoring details.")
    return monitor_data 