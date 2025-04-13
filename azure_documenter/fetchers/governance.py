import logging
import asyncio # Import asyncio
# Use PolicyClient for assignments
from azure.mgmt.resource.policy import PolicyClient
from azure.mgmt.policyinsights import PolicyInsightsClient
from azure.mgmt.advisor import AdvisorManagementClient
from azure.mgmt.managementgroups import ManagementGroupsAPI
from azure.core.exceptions import HttpResponseError
from azure.mgmt.policyinsights.models import QueryOptions

# New function to fetch Management Groups (tenant level)
async def fetch_management_groups(credential):
    """Fetches Management Groups for the tenant."""
    logging.info("Fetching Management Groups...")
    management_groups_data = []
    try:
        # Client doesn't take subscription_id for tenant-level operations
        mg_client = ManagementGroupsAPI(credential)
        groups = list(mg_client.management_groups.list())
        logging.info(f"Found {len(groups)} management groups.")
        for group in groups:
            details = mg_client.management_groups.get(group.name, expand="children")
            management_groups_data.append({
                "id": details.id,
                "name": details.name,
                "type": details.type,
                "display_name": details.display_name,
                "tenant_id": details.tenant_id,
                "parent": details.details.parent.id if details.details and details.details.parent else None,
                "children": [
                    {"id": child.id, "name": child.name, "type": child.type, "display_name": child.display_name}
                    for child in details.children
                ] if details.children else []
            })
    except HttpResponseError as e:
        logging.warning(f"Could not list Management Groups (Check Tenant Permissions?): {e.message}")
    except Exception as e:
        logging.error(f"Unexpected error fetching Management Groups: {e}")
    logging.info("Finished fetching Management Groups.")
    return management_groups_data

async def fetch_governance_details(credential, subscription_id):
    """Fetches Policy assignments, definitions, compliance states, and Advisor recommendations."""
    logging.info(f"[{subscription_id}] Fetching governance details (Policy, Advisor)...")
    governance_data = {
        "policy_assignments": [],
        "policy_definitions": [],
        "policy_states": [],
        "advisor_recommendations": []
    }
    policy_client = None
    try:
        # Use PolicyClient instead of ResourceManagementClient for assignments & definitions
        policy_client = PolicyClient(credential, subscription_id)
    except Exception as e:
        logging.error(f"[{subscription_id}] Failed to initialize PolicyClient: {e}")
        # Return early if client fails to initialize
        return governance_data

    # Fetch Policy Assignments
    try:
        assignments = list(policy_client.policy_assignments.list())
        logging.info(f"[{subscription_id}] Found {len(assignments)} policy assignments at subscription scope.")
        for assign in assignments:
            governance_data["policy_assignments"].append({
                "id": assign.id,
                "name": assign.name,
                "display_name": assign.display_name,
                "policy_definition_id": assign.policy_definition_id,
                "scope": assign.scope,
            })
    except HttpResponseError as e:
        logging.warning(f"[{subscription_id}] Could not list Policy Assignments (Check Permissions?): {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching Policy Assignments: {e}")

    # Fetch Policy Definitions (Subscription scope)
    try:
        definitions = list(policy_client.policy_definitions.list())
        logging.info(f"[{subscription_id}] Found {len(definitions)} policy definitions at subscription scope.")
        for definition in definitions:
            governance_data["policy_definitions"].append({
                "id": definition.id,
                "name": definition.name,
                "policy_type": str(definition.policy_type),
                "display_name": definition.display_name,
                "description": definition.description,
                "mode": definition.mode,
            })
    except HttpResponseError as e:
        logging.warning(f"[{subscription_id}] Could not list Policy Definitions: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching Policy Definitions: {e}")

    # Fetch Policy Compliance States
    try:
        policy_insights_client = PolicyInsightsClient(credential, subscription_id)
        # Query for non-compliant policy states at the subscription scope
        # Note: This can be slow and return a lot of data for large environments.
        # Consider adding filters (e.g., time range, specific policies) if performance is an issue.

        # Correctly use QueryOptions model for filter parameter
        query_options = QueryOptions(filter="IsCompliant eq false")

        states = list(policy_insights_client.policy_states.list_query_results_for_subscription(
            policy_states_resource="latest",
            subscription_id=subscription_id,
            query_options=query_options
        ))
        logging.info(f"[{subscription_id}] Found {len(states)} non-compliant policy states.")
        for state in states:
             # Extract key info. The state object can be complex.
            governance_data["policy_states"].append({
                "timestamp": state.timestamp,
                "resource_id": state.resource_id,
                "policy_assignment_id": state.policy_assignment_id,
                "policy_definition_id": state.policy_definition_id,
                "is_compliant": state.is_compliant,
                "compliance_state": "NonCompliant",
                "subscription_id": state.subscription_id,
                "resource_type": state.resource_type,
                "resource_location": state.resource_location,
                "resource_group": state.resource_group,
                "policy_assignment_name": state.policy_assignment_name,
                "policy_definition_name": state.policy_definition_name,
            })

    except HttpResponseError as e:
        if e.status_code == 403:
             logging.warning(f"[{subscription_id}] Authorization failed for Policy Insights: {e.message}. Skipping policy states.")
        elif "SubscriptionNotRegistered" in str(e):
             logging.warning(f"[{subscription_id}] Policy Insights provider not registered: {e.message}. Skipping policy states.")
        else:
            logging.error(f"[{subscription_id}] Error fetching policy states: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching policy states: {e}")

    # Fetch Advisor Recommendations
    try:
        advisor_client = AdvisorManagementClient(credential, subscription_id)
        recommendations = list(advisor_client.recommendations.list())
        logging.info(f"[{subscription_id}] Found {len(recommendations)} Advisor recommendations.")
        for rec in recommendations:
            governance_data["advisor_recommendations"].append({
                "id": rec.id,
                "name": rec.name,
                "category": str(rec.category),
                "impact": str(rec.impact),
                "impacted_field": rec.impacted_field,
                "impacted_value": rec.impacted_value,
                "last_updated": rec.last_updated,
                "recommendation_type_id": rec.recommendation_type_id,
                "short_description": rec.short_description.problem if rec.short_description else None,
                "resource_metadata": rec.resource_metadata.__dict__ if rec.resource_metadata else None
            })
    except HttpResponseError as e:
        if e.status_code == 403:
             logging.warning(f"[{subscription_id}] Authorization failed for Azure Advisor: {e.message}. Skipping recommendations.")
        elif "SubscriptionNotRegistered" in str(e):
             logging.warning(f"[{subscription_id}] Advisor provider not registered: {e.message}. Skipping recommendations.")
        else:
            logging.error(f"[{subscription_id}] Error fetching Advisor recommendations: {e.message}")
    except Exception as e:
        # Catch potential errors if Advisor SDK isn't installed
        if "AdvisorManagementClient" in str(e):
             logging.warning(f"[{subscription_id}] Could not initialize AdvisorManagementClient. Is the SDK installed? Skipping recommendations.")
        else:
            logging.error(f"[{subscription_id}] Unexpected error fetching Advisor recommendations: {e}")

    logging.info(f"[{subscription_id}] Finished fetching governance details.")
    return governance_data 