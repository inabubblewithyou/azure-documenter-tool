import logging
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.security import SecurityCenter
from azure.core.exceptions import HttpResponseError

# List of privileged role definition IDs to look for
PRIVILEGED_ROLE_IDS = [
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
    "00482a5a-887f-4fb3-b363-3b7fe8e74483"
]

# Mapping of role IDs to friendly names
ROLE_ID_TO_NAME = {
    "b1be1c3e-b65c-4f19-8427-f6fa0d97feb9": "Global Administrator",
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "fb1c8493-542b-48eb-b624-b4c8fea62acd": "Security Administrator",
    "00482a5a-887f-4fb3-b363-3b7fe8e74483": "Key Vault Administrator"
}

def fetch_security_details(credential, subscription_id):
    """Fetches RBAC role assignments and Security Center score for a subscription."""
    logging.info(f"[{subscription_id}] Fetching security details (RBAC, Security Score)...")
    security_data = {
        "role_assignments": [],
        "privileged_accounts": [],
        "security_score": None
    }

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
                # Try to resolve display name using Microsoft Graph API
                # This would require additional permissions and Graph SDK
                # For now, we'll use what we have
                principal_id = assign.principal_id
                principal_type = str(assign.principal_type)
                
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
                        "display_name": f"Principal {principal_id[:8]}...",  # Without Graph API we don't have names
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