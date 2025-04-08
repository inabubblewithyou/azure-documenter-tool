import logging
from datetime import datetime, timedelta
from azure.mgmt.consumption import ConsumptionManagementClient
from azure.core.exceptions import HttpResponseError

def fetch_cost_details(credential, subscription_id):
    """Fetches month-to-date actual cost for the subscription."""
    logging.info(f"[{subscription_id}] Fetching cost details (MTD Actual)...")
    cost_data = {
        "mtd_actual_cost": None,
        "currency": None
    }

    try:
        consumption_client = ConsumptionManagementClient(credential, subscription_id)

        # Define the time period for the query (Month To Date)
        # Note: Azure billing periods might not align perfectly with calendar months
        # Using start of current month to now for simplicity
        today = datetime.utcnow().date()
        start_of_month = today.replace(day=1)
        # Usage details might lag, so querying up to 'today' should capture most recent MTD

        # Scope for the query (the subscription itself)
        scope = f"/subscriptions/{subscription_id}"

        # Query actual costs using filter
        # Added metric='ActualCost' which might return a more structured object
        usage_details = consumption_client.usage_details.list(scope=scope, filter=f"properties/usageStart ge '{start_of_month}' and properties/usageEnd le '{today}'")#, metric='ActualCost')
        # Note: The `metric` parameter might change the response object structure significantly. Let's stick to iterating for now.

        total_cost = 0.0
        currency = None

        for usage in usage_details:
            # Check common cost properties, prioritizing 'pretax_cost'
            cost_value = getattr(usage, 'pretax_cost', None)
            if cost_value is None:
                # Fallback 1: Check 'cost_in_billing_currency'
                cost_value = getattr(usage, 'cost_in_billing_currency', None)
            if cost_value is None:
                 # Fallback 2: Check nested 'cost' object (common in newer APIs)
                cost_obj = getattr(usage, 'cost', None)
                if cost_obj and hasattr(cost_obj, 'value'):
                    cost_value = getattr(cost_obj, 'value', 0.0)
                else:
                    cost_value = 0.0 # Give up if no known cost attribute found

            total_cost += cost_value

            # Try to find currency, checking multiple possible attributes
            if currency is None:
                 currency = getattr(usage, 'billing_currency', None)
            if currency is None:
                currency = getattr(usage, 'currency', None)
            # Check nested cost object for currency as well
            if currency is None:
                 cost_obj = getattr(usage, 'cost', None)
                 if cost_obj and hasattr(cost_obj, 'currency'):
                     currency = getattr(cost_obj, 'currency', None)

        # If currency is still None after iterating, try a broader fetch?
        # For now, we'll report cost without currency if undetected.
        cost_data["mtd_actual_cost"] = round(total_cost, 2)
        cost_data["currency"] = currency if currency else "N/A"

        logging.info(f"[{subscription_id}] Found MTD Actual Cost: {cost_data['mtd_actual_cost']} {cost_data['currency']}")

    except HttpResponseError as e:
         if e.status_code == 403:
             logging.warning(f"[{subscription_id}] Authorization failed for consumption details: {e.message}. Skipping costs.")
         # Handle common errors like EA accounts needing different API calls or permissions
         elif "does not have access to subscription" in str(e.message).lower():
              logging.warning(f"[{subscription_id}] Access denied for cost data (may require Billing permissions): {e.message}. Skipping costs.")
         elif "InvalidResourceType" in str(e):
             logging.warning(f"[{subscription_id}] Cost management query failed (potential issue with scope or API): {e.message}. Skipping costs.")
         else:
             logging.error(f"[{subscription_id}] Error fetching cost details: {e.message}")
    except Exception as e:
        # Catch potential errors if Consumption SDK isn't installed or other issues
        if "ConsumptionManagementClient" in str(e):
             logging.warning(f"[{subscription_id}] Could not initialize ConsumptionManagementClient. Is the SDK installed? Skipping costs.")
        else:
            logging.error(f"[{subscription_id}] Unexpected error fetching cost details: {e}")

    logging.info(f"[{subscription_id}] Finished fetching cost details.")
    return cost_data 