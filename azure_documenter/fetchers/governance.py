import logging
# Use PolicyClient for assignments
from azure.mgmt.resource.policy import PolicyClient
from azure.mgmt.policyinsights import PolicyInsightsClient
from azure.mgmt.advisor import AdvisorManagementClient
from azure.core.exceptions import HttpResponseError
from azure.mgmt.policyinsights.models import QueryOptions

def fetch_governance_details(credential, subscription_id):
    """Fetches Policy assignments, compliance states, and Advisor recommendations."""
    logging.info(f"[{subscription_id}] Fetching governance details (Policy, Advisor)...")
    governance_data = {
        "policy_assignments": [],
        "policy_states": [],
        "advisor_recommendations": []
    }

    # Fetch Policy Assignments
    try:
        # Use PolicyClient instead of ResourceManagementClient for assignments
        policy_client = PolicyClient(credential, subscription_id)
        # Try using list() - maybe it implicitly uses the client's subscription scope?
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
                # Add more fields as needed, e.g., state.policy_set_definition_id
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
                "category": str(rec.category), # Enum
                "impact": str(rec.impact), # Enum
                "impacted_field": rec.impacted_field,
                "impacted_value": rec.impacted_value,
                "last_updated": rec.last_updated,
                "recommendation_type_id": rec.recommendation_type_id,
                "short_description": rec.short_description.problem if rec.short_description else None,
                "resource_metadata": rec.resource_metadata.__dict__ if rec.resource_metadata else None # Capture resource target
                # Add extended properties if needed: rec.extended_properties
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