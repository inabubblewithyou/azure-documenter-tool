import logging
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.security import SecurityCenter
from azure.core.exceptions import HttpResponseError
# Import Graph SDK components
from msgraph import GraphServiceClient
from msgraph.generated.models.o_data_errors.o_data_error import ODataError
# Import RequestConfiguration components from Kiota
from kiota_abstractions.request_option import RequestOption
from kiota_abstractions.base_request_configuration import BaseRequestConfiguration
# Import httpx for Headers object
import httpx

# List of privileged role definition IDs to look for
PRIVILEGED_ROLE_IDS = {
    # Global Administrator - /subscriptions/{id}/providers/Microsoft.Authorization/roleDefinitions/b1be1c3e-b65c-4f19-8427-f6fa0d97feb9
    "b1be1c3e-b65c-4f19-8427-f6fa0d97feb9",
    # Owner - /subscriptions/{id}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    # User Access Administrator - /subscriptions/{id}/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
    # Contributor - /subscriptions/{id}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c
    "b24988ac-6180-42a0-ab88-20f7382dd24c",
    # Security Administrator - /subscriptions/{id}/providers/Microsoft.Authorization/roleDefinitions/fb1c8493-542b-48eb-b624-b4c8fea62acd
    "fb1c8493-542b-48eb-b624-b4c8fea62acd",
    # Key Vault Administrator - /subscriptions/{id}/providers/Microsoft.Authorization/roleDefinitions/00482a5a-887f-4fb3-b363-3b7fe8e74483 
    "00482a5a-887f-4fb3-b363-3b7fe8e74483",
    # Role Based Access Control Administrator (preview)
    "f58310d9-a9f6-4397-9e8d-162e79143b1b",
    # Add other highly privileged roles as needed (e.g., Security Admin, Compliance Admin in Entra if applicable)
}

# Mapping of role IDs to friendly names
ROLE_ID_TO_NAME = {
    "b1be1c3e-b65c-4f19-8427-f6fa0d97feb9": "Global Administrator",
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "fb1c8493-542b-48eb-b624-b4c8fea62acd": "Security Administrator",
    "00482a5a-887f-4fb3-b363-3b7fe8e74483": "Key Vault Administrator",
    "f58310d9-a9f6-4397-9e8d-162e79143b1b": "RBAC Administrator",
    # Common Reader roles (usually not considered highly privileged)
    # "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
    # "43d0d8ad-25c7-4714-9337-8ba259a9fe05": "Monitoring Reader",
    # Add more common built-in roles if desired
}

async def fetch_security_details(credential, subscription_id):
    """Fetches RBAC role assignments and Security Center score for a subscription."""
    logging.info(f"[{subscription_id}] Fetching security details (RBAC, Security Score)...")
    security_data = {
        "role_assignments": [],
        "privileged_accounts": [],
        "security_score": None
    }

    # --- Initialize Graph Client Once ---
    graph_client = None
    graph_error_logged = False
    try:
        graph_client = GraphServiceClient(credentials=credential)
    except ImportError:
        logging.warning(f"[{subscription_id}] msgraph-sdk not installed. Cannot resolve principal names.")
        graph_error_logged = True # Prevent repeated Graph errors later
    except Exception as client_e:
        logging.warning(f"[{subscription_id}] Failed to initialize GraphServiceClient: {client_e}")
        graph_error_logged = True
    # -------------------------------------

    # Fetch RBAC Role Assignments
    try:
        auth_client = AuthorizationManagementClient(credential, subscription_id)
        assignments = list(auth_client.role_assignments.list_for_subscription())
        logging.info(f"[{subscription_id}] Found {len(assignments)} role assignments.")
        
        # Fetch role definitions to resolve names
        role_definitions = {}
        try:
            for role_def in auth_client.role_definitions.list(scope=f"/subscriptions/{subscription_id}"):
                role_definitions[role_def.id] = role_def.role_name
        except Exception as e:
            logging.warning(f"[{subscription_id}] Could not fetch role definitions: {e}")
            
        # Process each role assignment
        for assign in assignments:
            # Extract relevant details - resolving names might require Graph API calls (complex)
            # For now, store IDs.
            role_def_id = assign.role_definition_id
            
            # Try to resolve role name from our cached definitions
            role_name = None
            if role_def_id in role_definitions:
                role_name = role_definitions[role_def_id]
            else:
                # Extract just the GUID part from the ID string
                role_guid = role_def_id.split('/')[-1] if role_def_id else None
                if role_guid in ROLE_ID_TO_NAME:
                    role_name = ROLE_ID_TO_NAME[role_guid]
            
            assignment_data = {
                "id": assign.id,
                "name": assign.name,
                "scope": assign.scope,
                "role_definition_id": role_def_id,
                "role_name": role_name,
                "principal_id": assign.principal_id,
                "principal_type": str(assign.principal_type) # Enum to string
            }
            
            security_data["role_assignments"].append(assignment_data)
            
            # Check if this is a privileged role
            role_guid = role_def_id.split('/')[-1] if role_def_id else None
            if role_guid in PRIVILEGED_ROLE_IDS:
                principal_id = assign.principal_id
                principal_type = str(assign.principal_type)
                display_name = f"Principal {principal_id[:8]}..." # Default

                # --- Attempt to resolve Display Name via Graph API ---
                if graph_client:
                    try:
                        # Create httpx Headers object
                        graph_headers = httpx.Headers({"ConsistencyLevel": "eventual"})
                        # Use BaseRequestConfiguration with the httpx Headers object
                        request_config = BaseRequestConfiguration(
                            headers=graph_headers 
                        )
                        
                        if principal_type == "User":
                            # Pass the configured request_config object
                            user = await graph_client.users.by_user_id(principal_id).get()
                            if user and user.display_name:
                                display_name = user.display_name
                        elif principal_type == "Group":
                            # Pass the configured request_config object
                            group = await graph_client.groups.by_group_id(principal_id).get()
                            if group and group.display_name:
                                display_name = group.display_name
                        elif principal_type == "ServicePrincipal":
                            # Pass the configured request_config object
                            sp = await graph_client.service_principals.by_service_principal_id(principal_id).get()
                            if sp and sp.app_display_name:
                                display_name = sp.app_display_name # Use app_display_name for SPs
                            elif sp and sp.display_name:
                                 display_name = sp.display_name # Fallback to display_name

                    except ODataError as graph_error:
                        if not graph_error_logged: # Log only once per type of error
                            logging.warning(f"[{subscription_id}] Graph API error resolving name for {principal_type} {principal_id}: {graph_error.error.message}. Using default.")
                            # graph_error_logged = True # Could set flag here if needed
                    except Exception as graph_e:
                        if not graph_error_logged:
                            logging.warning(f"[{subscription_id}] Unexpected error resolving name for {principal_type} {principal_id} via Graph: {graph_e}. Using default.")
                            # graph_error_logged = True 
                elif not graph_error_logged:
                    # Log only once if client init failed
                    logging.warning(f"[{subscription_id}] Graph client not available. Cannot resolve principal names. Using default.")
                    graph_error_logged = True
                # -------------------------------------------------------

                # Check if we already have this principal
                existing_principal = next((p for p in security_data["privileged_accounts"] 
                                         if p.get("object_id") == principal_id), None)
                
                if existing_principal:
                    # Add this role to existing principal
                    if role_name and role_name not in existing_principal["role_names"]:
                        existing_principal["role_names"].append(role_name)
                else:
                    # Create new principal entry
                    security_data["privileged_accounts"].append({
                        "object_id": principal_id,
                        "display_name": display_name,
                        "principal_type": principal_type,
                        "role_names": [role_name] if role_name else [f"Role {role_guid[:8]}..."]
                    })
        
        logging.info(f"[{subscription_id}] Found {len(security_data['privileged_accounts'])} privileged accounts.")
    
    except HttpResponseError as e:
        if e.status_code == 403:
             logging.warning(f"[{subscription_id}] Authorization failed for RBAC details: {e.message}. Skipping RBAC.")
        else:
            logging.error(f"[{subscription_id}] Error fetching RBAC details: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching RBAC details: {e}")

    # Fetch Security Center Secure Score
    try:
        security_client = SecurityCenter(credential, subscription_id, asc_location="global")
        scores = list(security_client.secure_scores.list())
        if scores:
            asc_score = next((s for s in scores if hasattr(s, 'name') and s.name == 'ascScore'), scores[0]) # Find 'ascScore' or take the first

            # Corrected access to score details - Check for direct attributes
            current_score = getattr(asc_score, 'current', None)
            max_score = getattr(asc_score, 'max', None)
            percentage = getattr(asc_score, 'percentage', None) # Percentage might be directly available

            if current_score is not None and max_score is not None:
                # Calculate percentage if not directly available
                if percentage is None and max_score > 0:
                    percentage = current_score / max_score
                elif percentage is None:
                    percentage = 0

                security_data["security_score"] = {
                    "id": getattr(asc_score, 'id', None),
                    "name": getattr(asc_score, 'display_name', 'ascScore'),
                    "current": current_score,
                    "max": max_score,
                    "percentage": percentage
                 }
                logging.info(f"[{subscription_id}] Found security score: {security_data['security_score']['current']}/{security_data['security_score']['max']}.")
            else:
                logging.info(f"[{subscription_id}] Found secure score object(s) but could not extract current/max score details.")
        else:
             logging.info(f"[{subscription_id}] No security scores found.")

    except HttpResponseError as e:
        if e.status_code == 403:
             logging.warning(f"[{subscription_id}] Authorization failed for Security Center score: {e.message}. Skipping score.")
        # Handle cases where Security Center might not be enabled/configured
        elif "SubscriptionNotRegistered" in str(e) or "NotFound" in str(e):
             logging.warning(f"[{subscription_id}] Security Center not configured or score unavailable: {e.message}. Skipping score.")
        else:
            logging.error(f"[{subscription_id}] Error fetching Security Center score: {e.message}")
    except Exception as e:
        # Catch potential errors if Security Center SDK isn't installed or other issues
        if "SecurityCenterClient" in str(e):
             logging.warning(f"[{subscription_id}] Could not initialize SecurityCenterClient. Is the SDK installed and configured? Skipping score.")
        elif "SecurityCenter" in str(e):
             logging.warning(f"[{subscription_id}] Could not initialize SecurityCenter. Is the SDK installed and configured? Skipping score.")
        else:
            logging.error(f"[{subscription_id}] Unexpected error fetching Security Center score: {e}")


    logging.info(f"[{subscription_id}] Finished fetching security details.")
    return security_data 

# New function to fetch JIT Network Access Policies
async def fetch_jit_policies(credential, subscription_id):
    """Fetches JIT Network Access Policies for the subscription."""
    logging.info(f"[{subscription_id}] Fetching JIT Network Access Policies...")
    jit_policies_data = []
    
    try:
        # JIT Policies are typically listed by location and resource group.
        # We need the locations where JIT might be configured.
        # A common approach is to list for known locations or derive from resources.
        # For simplicity, let's try listing across the subscription first, then maybe per location.
        # NOTE: The SDK structure for JIT might require specific locations.
        # Let's assume we need a SecurityCenter client per location, or list globally if possible.

        # Initialize Security Center client (often needs location hint, but let's try global)
        # Check API docs: jit_network_access_policies.list() might be subscription-level
        # Update: list() is subscription level, but list_by_region requires asc_location.
        # Let's use list() first.
        security_client = SecurityCenter(credential, subscription_id, asc_location="global") # Using global, might need adjustment

        jit_policies = list(security_client.jit_network_access_policies.list())
        logging.info(f"[{subscription_id}] Found {len(jit_policies)} JIT Network Access Policies via subscription-level list.")

        for policy in jit_policies:
            policy_details = {
                "id": policy.id,
                "name": policy.name, # Typically 'default'
                "location": policy.location, # The Azure region where the policy resides
                "resource_group": policy.id.split('/')[4],
                "kind": policy.kind,
                "provisioning_state": policy.provisioning_state,
                "virtual_machines": []
            }
            if policy.virtual_machines:
                 for vm_rule in policy.virtual_machines:
                     vm_info = {
                         "id": vm_rule.id,
                         "ports": []
                     }
                     if vm_rule.ports:
                         for port_rule in vm_rule.ports:
                             vm_info["ports"].append({
                                 "number": port_rule.number,
                                 "protocol": str(port_rule.protocol), # Enum
                                 "allowed_source_address_prefix": port_rule.allowed_source_address_prefix,
                                 "max_request_access_duration": port_rule.max_request_access_duration
                             })
                     policy_details["virtual_machines"].append(vm_info)
            
            jit_policies_data.append(policy_details)

    except HttpResponseError as e:
         if e.status_code == 403:
             logging.warning(f"[{subscription_id}] Authorization failed for JIT Policies: {e.message}. Skipping JIT.")
         elif "SubscriptionNotRegistered" in str(e) or "NotFound" in str(e):
              logging.warning(f"[{subscription_id}] Security Center not configured or JIT unavailable: {e.message}. Skipping JIT.")
         else:
             logging.warning(f"[{subscription_id}] Could not list JIT Policies: {e.message}")
    except ImportError:
         logging.error(f"[{subscription_id}] azure-mgmt-security library not found. Cannot fetch JIT Policies.")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching JIT Policies: {e}")

    logging.info(f"[{subscription_id}] Finished fetching JIT policies.")
    return jit_policies_data 