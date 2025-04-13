import logging
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.mgmt.authorization import AuthorizationManagementClient
import asyncio # Ensure asyncio is imported

# --- Add Graph SDK Imports ---
# Test basic import first
try:
    import msgraph
    logging.debug("Successfully imported the base 'msgraph' package.")
except ImportError as e:
    logging.error(f"Failed to import the base 'msgraph' package: {e}", exc_info=True)
    # Re-raise or handle as critical if needed, otherwise allow later code to fail
    # raise # Optional: Stop execution immediately if base import fails

from msgraph import GraphServiceClient
from msgraph.generated.models.o_data_errors.o_data_error import ODataError
# Import only the main request builders
from msgraph.generated.organization.organization_request_builder import OrganizationRequestBuilder
from msgraph.generated.service_principals.service_principals_request_builder import ServicePrincipalsRequestBuilder
# Import the generic RequestConfiguration and QueryParameters base
from kiota_abstractions.base_request_configuration import RequestConfiguration
from kiota_abstractions.default_query_parameters import QueryParameters # Base for our custom query params
# Import the HeadersCollection
from kiota_abstractions.headers_collection import HeadersCollection
# ---------------------------


async def fetch_service_principal_summary(credential):
    """
    Fetches a summary of service principals using Microsoft Graph API.
    Requires appropriate Application Permissions (e.g., Directory.Read.All) 
    granted to the credential. Returns a dictionary containing the count 
    and a list of SP details. Now uses asyncio internally.
    """
    logging.info("Fetching Service Principals via Microsoft Graph API...")
    sp_summary = {
        "status": "pending",
        "count": 0,
        "principals": [],
        "error": None
    }

    async def _internal_get_sps():
        """Internal async function to handle Graph API call and pagination."""
        principals_list = []
        try:
            scopes = ['https://graph.microsoft.com/.default']
            graph_client = GraphServiceClient(credentials=credential, scopes=scopes)

            # Define query parameters class inline or import if defined elsewhere
            class SPGetQueryParameters:
                select: list[str] = ["id", "appId", "displayName"]
                # Add count parameter
                count: bool = True # Request a count of items
                # Order by display name for consistency (optional)
                orderby: list[str] = ["displayName"]

            query_params = SPGetQueryParameters()
            
            # Create and populate the HeadersCollection first
            headers_collection = HeadersCollection()
            headers_collection.add("ConsistencyLevel", "eventual") # Use add for single header

            # Instantiate the generic RequestConfiguration, passing the collection directly
            request_configuration = RequestConfiguration(
                query_parameters=query_params, # Pass the SP query params instance
                headers=headers_collection     # Pass the HeadersCollection instance during init
            )
            
            # Assign the populated HeadersCollection to the configuration object
            # request_configuration.headers = headers_collection # No longer needed

            # Initial request using the correctly instantiated generic configuration
            result = await graph_client.service_principals.get(request_configuration=request_configuration)
            
            page_count = 0
            total_sps_count = 0 # Will be set by the response if available
            logged_total_count = False # Flag to log total count only once

            # Iterate through pages using the SDK's pattern or manually
            while result:
                page_count += 1
                if result.value:
                    principals_list.extend(result.value)
                
                # Get total count from the first response if available and log once
                if not logged_total_count and hasattr(result, 'odata_count') and result.odata_count is not None:
                    total_sps_count = result.odata_count
                    logging.info(f"Graph API reports total Service Principal count: {total_sps_count}")
                    logged_total_count = True # Prevent logging again

                logging.debug(f"Processed page {page_count} of SPs. Fetched {len(result.value) if result.value else 0} on this page. Total fetched so far: {len(principals_list)}.")

                if result.odata_next_link:
                    # Use the SDK's ability to follow the nextLink
                    # Re-create the client is simpler than trying to manage session state across async calls
                    # Re-initializing client for next page request
                    graph_client_next = GraphServiceClient(credentials=credential, scopes=scopes)
                    result = await graph_client_next.service_principals.with_url(result.odata_next_link).get()
                else:
                    break # No more pages

            # logging.info(f"Finished fetching SPs. Total pages: {page_count}. Total SPs fetched: {len(principals_list)}.") # Replaced by message below
            return principals_list, total_sps_count # Return list and total count

        except ODataError as odata_error:
            error_message = f"Microsoft Graph API error fetching SPs: {odata_error.error.message}"
            sp_summary["status"] = "error_graph_api"
            sp_summary["error"] = error_message
            if "Authorization_RequestDenied" in str(odata_error.error.code):
                logging.warning(f"Graph API Access Denied for SPs. Ensure SP has Directory.Read.All permission. Error: {odata_error.error.message}")
            else:
                logging.error(error_message, exc_info=True)
            return None, 0 # Indicate error
            
        except ClientAuthenticationError as auth_error:
            error_message = f"Graph Authentication failed for SPs: {auth_error}"
            sp_summary["status"] = "error_authentication"
            sp_summary["error"] = error_message
            logging.error(error_message)
            return None, 0 # Indicate error

        except Exception as e:
            error_message = f"Unexpected error in _internal_get_sps: {e}"
            sp_summary["status"] = "error_unexpected"
            sp_summary["error"] = error_message
            logging.error(error_message, exc_info=True)
            return None, 0 # Indicate error

    # Run the internal async function
    try:
        # Directly await the internal coroutine, don't use asyncio.run
        fetched_principals, reported_count = await _internal_get_sps()

        if fetched_principals is not None: # Check if the async function succeeded
            sp_summary["count"] = len(fetched_principals) 
            # Optionally use reported_count if available and seems reliable
            # sp_summary["count"] = reported_count if reported_count > 0 else len(fetched_principals)
            sp_summary["principals"] = [
                {"id": sp.id, "appId": sp.app_id, "displayName": sp.display_name}
                for sp in fetched_principals
            ]
            sp_summary["status"] = "success"
            # logging.info(f"Successfully processed {sp_summary['count']} service principals.") # Removed redundant message
            logging.info(f"Finished fetching Service Principals. Found: {sp_summary['count']}.") # Consolidated finish message
        # If fetched_principals is None, the error status/message was already set inside _internal_get_sps

    except RuntimeError as rt_error:
         # Handle case where asyncio.run is called from an already running event loop
         error_message = f"Asyncio runtime error calling _internal_get_sps: {rt_error}"
         sp_summary["status"] = "error_async"
         sp_summary["error"] = error_message
         logging.error(error_message)
    except Exception as e:
        # Catch any other unexpected errors during asyncio.run or processing
        error_message = f"Unexpected error running SP fetch task: {e}"
        sp_summary["status"] = "error_unexpected_run"
        sp_summary["error"] = error_message
        logging.error(error_message, exc_info=True)

    return sp_summary

async def fetch_custom_roles(credential, subscription_id):
    """Fetches Custom RBAC Role Definitions for the subscription scope."""
    logging.info(f"[{subscription_id}] Fetching Custom RBAC Roles...")
    custom_roles_data = []
    scope = f"/subscriptions/{subscription_id}"

    try:
        auth_client = AuthorizationManagementClient(credential, subscription_id)

        # List all role definitions at the subscription scope
        role_definitions = list(auth_client.role_definitions.list(scope=scope, filter="type eq 'CustomRole'"))
        logging.info(f"[{subscription_id}] Found {len(role_definitions)} custom role definitions at subscription scope.")

        for role_def in role_definitions:
            permissions_details = []
            if role_def.permissions:
                 for perm in role_def.permissions:
                     permissions_details.append({
                         "actions": perm.actions,
                         "not_actions": perm.not_actions,
                         "data_actions": perm.data_actions,
                         "not_data_actions": perm.not_data_actions
                     })

            role_details = {
                "id": role_def.id,
                "name": role_def.name, # GUID
                "role_name": role_def.role_name,
                "description": role_def.description,
                "type": role_def.type, # Should be 'CustomRole'
                "assignable_scopes": role_def.assignable_scopes,
                "permissions": permissions_details
            }
            custom_roles_data.append(role_details)

        # Note: Could also check Management Group scopes if needed, requires MG client/permissions

    except HttpResponseError as e:
         if e.status_code == 403:
             logging.warning(f"[{subscription_id}] Authorization failed for listing Role Definitions: {e.message}. Skipping custom roles.")
         else:
             logging.warning(f"[{subscription_id}] Could not list Role Definitions: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching custom roles: {e}")

    logging.info(f"[{subscription_id}] Finished fetching custom roles.")
    return custom_roles_data

# --- Function to Fetch Tenant Details via Graph ---
async def fetch_tenant_details(credential):
    """Fetches Tenant ID, Display Name, and Default Domain using Microsoft Graph API."""
    logging.info("Fetching Tenant details via Microsoft Graph API...")
    tenant_details = {
        "tenant_id": None,
        "display_name": None,
        "default_domain": None,
        "error": None
    }

    async def _internal_get_org():
        # Define query parameters class 
        class OrgGetQueryParameters:
             select: list[str] = ["id", "displayName", "verifiedDomains"]
        
        # Define the request configuration class for the GET operation
        # This class holds headers, options, and query parameters
        # REMOVED Import from here: from msgraph.generated.organization.organization_request_builder import OrganizationRequestBuilderGetRequestConfiguration 
        
        # Instantiate the query parameters
        query_params = OrgGetQueryParameters()
        
        # Instantiate the generic RequestConfiguration 
        # and assign query params instance
        request_configuration = RequestConfiguration(
            query_parameters=query_params # Pass the Org query params instance
        )

        scopes = ['https://graph.microsoft.com/.default']
        graph_client = GraphServiceClient(credentials=credential, scopes=scopes)
        
        # Perform the async call using the correct generic request configuration object
        return await graph_client.organization.get(request_configuration=request_configuration)

    try:
        # Await the result from the internal function
        organization_result = await _internal_get_org()

        # Check if the result and the value list exist and have at least one org
        if organization_result and organization_result.value and len(organization_result.value) > 0:
            # Access the first organization object in the collection
            org_info = organization_result.value[0]
            
            # Extract Tenant ID (which is the organization ID)
            tenant_details["tenant_id"] = org_info.id
            tenant_details["display_name"] = org_info.display_name
            
            # Find the default verified domain
            default_domain_found = None
            if org_info.verified_domains: # Use org_info here
                for domain in org_info.verified_domains:
                    if domain.is_default:
                        default_domain_found = domain.name
                        break # Found the default
            tenant_details["default_domain"] = default_domain_found

            # Log successful retrieval
            logging.info(f"Graph API found Tenant ID: {tenant_details['tenant_id']}")
            if tenant_details["display_name"]:
                logging.info(f"Graph API found Tenant Display Name: {tenant_details['display_name']}")
            if tenant_details["default_domain"]:
                 logging.info(f"Graph API found Tenant Default Domain: {tenant_details['default_domain']}")
            else:
                # Log if default domain couldn't be found, but don't treat as error
                logging.warning("Could not determine default domain from Graph API verified domains.")

        else:
            # Handle case where Graph call succeeded but returned no result in the value list
            tenant_details["error"] = "Graph API call succeeded but returned no organization details in the value list."
            logging.warning(tenant_details["error"])
                
    except ODataError as odata_error:
        error_message = f"Microsoft Graph API error fetching tenant details: {odata_error.error.message}"
        tenant_details["error"] = error_message
        logging.error(error_message, exc_info=True)
    except ClientAuthenticationError as auth_error:
        error_message = f"Graph Authentication failed for tenant details: {auth_error}"
        tenant_details["error"] = error_message
        logging.error(error_message, exc_info=True)
    except Exception as e:
        error_message = f"Unexpected error fetching tenant details: {e}"
        tenant_details["error"] = error_message
        logging.error(error_message, exc_info=True)

    return tenant_details

# --- Get Organization by ID (Placeholder - if needed later) ---
# async def get_organization_by_id(credential, tenant_id):
#     # ... implementation ...
#     pass 
