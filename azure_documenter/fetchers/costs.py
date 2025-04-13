import logging
import asyncio # Import asyncio
from datetime import datetime, timedelta, timezone
from azure.mgmt.consumption import ConsumptionManagementClient
from azure.mgmt.costmanagement import CostManagementClient
from azure.mgmt.costmanagement.models import QueryDefinition, QueryTimePeriod, QueryDataset, QueryAggregation, QueryGrouping, QueryFilter, QueryResult
from azure.core.exceptions import HttpResponseError

async def fetch_cost_details(credential, subscription_id):
    """Fetches month-to-date and year-to-date actual cost for the subscription using Consumption API."""
    logging.info(f"[{subscription_id}] Fetching basic cost details (MTD/YTD Actual - Consumption API)...")
    cost_data = {
        "mtd_actual_cost": None,
        "ytd_actual_cost": None,
        "currency": None,
        "forecast_cost": None,
        "resource_costs": [],
        "cost_by_service": []
    }

    try:
        consumption_client = ConsumptionManagementClient(credential, subscription_id)
        cost_client = CostManagementClient(credential)

        # Define time periods
        today = datetime.utcnow().date()
        start_of_month = today.replace(day=1)
        start_of_year = today.replace(month=1, day=1)
        
        # Scope for queries
        scope = f"/subscriptions/{subscription_id}"

        # Fetch MTD costs
        usage_details = consumption_client.usage_details.list(
            scope=scope, 
            filter=f"properties/usageStart ge '{start_of_month}' and properties/usageEnd le '{today}'"
        )

        total_cost = 0.0
        currency = None

        for usage in usage_details:
            cost_value = getattr(usage, 'pretax_cost', None)
            if cost_value is None:
                cost_value = getattr(usage, 'cost_in_billing_currency', None)
            if cost_value is None:
                cost_obj = getattr(usage, 'cost', None)
                if cost_obj and hasattr(cost_obj, 'value'):
                    cost_value = getattr(cost_obj, 'value', 0.0)
                else:
                    cost_value = 0.0

            total_cost += cost_value

            if currency is None:
                currency = getattr(usage, 'billing_currency', None)
            if currency is None:
                currency = getattr(usage, 'currency', None)
            if currency is None:
                cost_obj = getattr(usage, 'cost', None)
                if cost_obj and hasattr(cost_obj, 'currency'):
                    currency = getattr(cost_obj, 'currency', None)

        cost_data["mtd_actual_cost"] = round(total_cost, 2)
        cost_data["currency"] = currency if currency else "N/A"

        # Fetch YTD costs using Cost Management API
        try:
            ytd_query = QueryDefinition(
                type="ActualCost",
                timeframe="Custom",
                time_period=QueryTimePeriod(
                    from_property=start_of_year.strftime('%Y-%m-%d'),
                    to=today.strftime('%Y-%m-%d')
                ),
                dataset=QueryDataset(
                    granularity="None",
                    aggregation={
                        "totalCost": QueryAggregation(name="Cost", function="Sum")
                    }
                )
            )
            
            ytd_result = cost_client.query.usage(scope=scope, parameters=ytd_query)
            if ytd_result and ytd_result.rows:
                cost_data["ytd_actual_cost"] = round(float(ytd_result.rows[0][0]), 2)

            # Fetch cost forecast for next 30 days
            forecast_query = QueryDefinition(
                type="ActualCost",
                timeframe="BillingMonthToDate",
                dataset=QueryDataset(
                    granularity="None",
                    aggregation={
                        "totalCost": QueryAggregation(name="Cost", function="Sum")
                    }
                )
            )
            
            try:
                forecast_result = cost_client.query.usage(scope=scope, parameters=forecast_query)
                if forecast_result and forecast_result.rows:
                    # Get the total forecast and multiply by remaining days ratio for simple projection
                    current_cost = float(forecast_result.rows[0][0])
                    days_in_month = (today.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
                    days_passed = today.day
                    days_remaining = days_in_month.day - days_passed
                    if days_passed > 0:  # Avoid division by zero
                        daily_rate = current_cost / days_passed
                        forecast = current_cost + (daily_rate * days_remaining)
                        cost_data["forecast_cost"] = round(forecast, 2)
            except HttpResponseError as fe:
                logging.warning(f"[{subscription_id}] Failed to fetch forecast data: {fe.message}")

            # Fetch cost by resource
            resource_query = QueryDefinition(
                type="ActualCost",
                timeframe="Custom",
                time_period=QueryTimePeriod(
                    from_property=start_of_month.strftime('%Y-%m-%d'),
                    to=today.strftime('%Y-%m-%d')
                ),
                dataset=QueryDataset(
                    granularity="None",
                    aggregation={
                        "totalCost": QueryAggregation(name="Cost", function="Sum")
                    },
                    grouping=[
                        QueryGrouping(type="Dimension", name="ResourceId"),
                        QueryGrouping(type="Dimension", name="ResourceType"),
                        QueryGrouping(type="Dimension", name="ResourceLocation")
                    ]
                )
            )
            
            resource_result = cost_client.query.usage(scope=scope, parameters=resource_query)
            if resource_result and resource_result.rows:
                for row in resource_result.rows:
                    if len(row) >= 4:  # Ensure we have all expected columns
                        cost_data["resource_costs"].append({
                            "cost": round(float(row[0]), 2),
                            "resource_id": row[1],
                            "resource_type": row[2],
                            "location": row[3]
                        })

            # Fetch cost by service
            service_query = QueryDefinition(
                type="ActualCost",
                timeframe="Custom",
                time_period=QueryTimePeriod(
                    from_property=start_of_month.strftime('%Y-%m-%d'),
                    to=today.strftime('%Y-%m-%d')
                ),
                dataset=QueryDataset(
                    granularity="None",
                    aggregation={
                        "totalCost": QueryAggregation(name="Cost", function="Sum")
                    },
                    grouping=[
                        QueryGrouping(type="Dimension", name="ServiceName")
                    ]
                )
            )
            
            service_result = cost_client.query.usage(scope=scope, parameters=service_query)
            if service_result and service_result.rows:
                for row in service_result.rows:
                    if len(row) >= 2:  # Ensure we have cost and service name
                        cost_data["cost_by_service"].append({
                            "service": row[1],
                            "cost": round(float(row[0]), 2)
                        })

        except HttpResponseError as e:
            logging.warning(f"[{subscription_id}] Cost Management API error: {e.message}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error in Cost Management queries: {e}")

    except HttpResponseError as e:
        if e.status_code == 403:
            logging.warning(f"[{subscription_id}] Authorization failed for consumption details: {e.message}. Skipping costs.")
        elif "does not have access to subscription" in str(e.message).lower():
            logging.warning(f"[{subscription_id}] Access denied for cost data (may require Billing permissions): {e.message}. Skipping costs.")
        elif "InvalidResourceType" in str(e):
            logging.warning(f"[{subscription_id}] Cost management query failed (potential issue with scope or API): {e.message}. Skipping costs.")
        else:
            logging.error(f"[{subscription_id}] Error fetching cost details: {e.message}")
    except Exception as e:
        if "ConsumptionManagementClient" in str(e):
            logging.warning(f"[{subscription_id}] Could not initialize ConsumptionManagementClient. Is the SDK installed? Skipping costs.")
        else:
            logging.error(f"[{subscription_id}] Unexpected error fetching cost details: {e}")

    logging.info(f"[{subscription_id}] Finished fetching basic cost details.")
    return cost_data

async def fetch_detailed_cost_report(credential, subscription_id):
    """Fetches a detailed, aggregated cost report for the current month using Cost Management API."""
    logging.info(f"[{subscription_id}] Fetching detailed cost report (MTD Aggregated - Cost Management API)...")
    cost_report_data = {
        "rows": [],
        "error": None
    }
    scope = f"/subscriptions/{subscription_id}"

    try:
        cost_client = CostManagementClient(credential)

        # Define time period: Start of current month to today (UTC)
        today_utc = datetime.now(timezone.utc)
        start_of_month_utc = today_utc.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Define the query
        query = QueryDefinition(
            type="ActualCost",
            timeframe="Custom",
            time_period=QueryTimePeriod(from_property=start_of_month_utc, to=today_utc),
            dataset=QueryDataset(
                granularity="None", # We aggregate over the whole period
                aggregation={
                    "totalCost": QueryAggregation(name="PreTaxCost", function="Sum")
                },
                grouping=[
                    QueryGrouping(type="Dimension", name="ResourceGroupName"),
                    QueryGrouping(type="Dimension", name="ServiceName")
                ]
            )
        )

        # Execute the query
        result = cost_client.query.usage(scope=scope, parameters=query)

        if result and result.rows:
            logging.info(f"[{subscription_id}] Found {len(result.rows)} rows in detailed cost report.")
            # Format: [Cost, Date, ResourceGroupName, ServiceName, Currency]
            # Column order depends on aggregation and grouping
            cost_report_data["rows"] = result.rows
            # Example row access (assuming columns are Cost, Date, RG, Service, Currency):
            # for row in result.rows:
            #     cost = row[0]
            #     rg = row[2]
            #     service = row[3]
            #     currency = row[4]
            #     print(f"RG: {rg}, Service: {service}, Cost: {cost} {currency}")
        else:
             logging.info(f"[{subscription_id}] No data found in detailed cost report for the specified period.")

    except HttpResponseError as e:
         error_message = f"Error fetching detailed cost report: {e.message}"
         cost_report_data["error"] = error_message
         if e.status_code == 403:
             logging.warning(f"[{subscription_id}] Authorization failed for Cost Management Query: {e.message}. Skipping detailed report.")
         elif "InvalidResourceType" in str(e):
             logging.warning(f"[{subscription_id}] Cost Management query failed (potential issue with scope or API): {e.message}. Skipping detailed report.")
         else:
             logging.error(f"[{subscription_id}] {error_message}")
    except ImportError as e:
        error_message = f"CostManagementClient or related models not found. Is azure-mgmt-costmanagement installed? {e}"
        cost_report_data["error"] = error_message
        logging.warning(f"[{subscription_id}] {error_message}. Skipping detailed cost report.")
    except Exception as e:
        error_message = f"Unexpected error fetching detailed cost report: {e}"
        cost_report_data["error"] = error_message
        logging.error(f"[{subscription_id}] {error_message}")

    logging.info(f"[{subscription_id}] Finished fetching detailed cost report.")
    return cost_report_data 