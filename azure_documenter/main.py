import argparse
import logging
import os
import json # For saving raw data
import sys # For explicit stdout handler
from datetime import datetime, timezone # Add timezone import
import time  # For local timezone handling
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.resource.subscriptions import SubscriptionClient # Already imported, but clarify usage
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.core.exceptions import HttpResponseError

# --- Rich Import ---
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    # Use rich print if available, otherwise fallback to standard print
    from rich import print as rprint 
    _RICH_AVAILABLE = True
except ImportError:
    # Fallback if rich is not installed
    rprint = print 
    Console = None
    Panel = None
    _RICH_AVAILABLE = False
# -------------------

# Import fetchers
from fetchers.resources import fetch_resources, fetch_app_service_details
from fetchers.network import fetch_networking_details
from fetchers.security import fetch_security_details
from fetchers.costs import fetch_cost_details
from fetchers.governance import fetch_governance_details
from fetchers.identity import fetch_service_principal_summary

# Import generators
from generators.markdown_writer import generate_markdown_report
from generators.diagram_generator import generate_all_diagrams
from generators.html_exporter import export_markdown_to_html
from generators.llm_writer import enhance_report_with_llm # Import LLM writer
from generators.design_document_writer import generate_design_document # Added import

# Import Config
import config # To check LLM provider status

# Import Delta Modules
from delta_analyzer import analyze_delta, load_audit_data
from generators.delta_report_writer import generate_delta_report

# Global flag for silent mode
SILENT_MODE = False
# Global rich console
console = Console() if _RICH_AVAILABLE else None

# Define output directory relative to the script location FIRST
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_BASE_DIR = os.path.join(SCRIPT_DIR, "outputs")
DATA_DIR = os.path.join(OUTPUT_BASE_DIR, "data")
REPORT_DIR = os.path.join(OUTPUT_BASE_DIR, "reports") # For consistency
DIAGRAM_DIR = os.path.join(OUTPUT_BASE_DIR, "diagrams")
LOG_DIR = os.path.join(OUTPUT_BASE_DIR, "logs") # Explicit log dir
VERSION_TRACKING_DIR = os.path.join(OUTPUT_BASE_DIR, "version_tracking") # Version tracking dir

# --- End Version Tracking Functions ---

def get_formatted_timestamp():
    """Returns a timestamp string in the local timezone (respecting DST)"""
    # Get current time in the local timezone (including DST if applicable)
    local_time = datetime.now()
    return local_time.strftime("%Y%m%d_%H%M%S")

# Configure logging - setup root logger and handlers
logger = logging.getLogger() # Get the root logger
logger.setLevel(logging.DEBUG) # Set root logger level to DEBUG to capture everything

# Clear existing handlers
for handler in logger.handlers[:]:
    logger.removeHandler(handler)

# --- Console Handler (INFO level) ---
# Use rich handler if available, otherwise standard StreamHandler
if _RICH_AVAILABLE:
    from rich.logging import RichHandler
    console_handler = RichHandler(level=logging.INFO, console=console, show_path=False, show_time=False)
    formatter = logging.Formatter("%(message)s") # Rich handler handles its own formatting mostly
    console_handler.setFormatter(formatter)
else:
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO) # Console shows INFO and above
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
logger.addHandler(console_handler) # Add console handler to root logger

# --- File Handler (DEBUG level) ---
# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)
log_filename = f"azure_documenter_run_{get_formatted_timestamp()}.log"
log_filepath = os.path.join(LOG_DIR, log_filename)

file_handler = logging.FileHandler(log_filepath, encoding='utf-8')
file_handler.setLevel(logging.DEBUG) # File logs everything (DEBUG and above)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler) # Add file handler to root logger

# Suppress verbose Azure SDK logging (Set levels on specific loggers AFTER root logger is configured)
for azure_logger_name in ['azure', 'azure.core', 'azure.identity', 'msrest', 'msal']:
    logging.getLogger(azure_logger_name).setLevel(logging.WARNING) # Changed to WARNING for less noise

# --- Initial Log Message ---
logging.info(f"Logging initialized. Console Level: INFO, File Level: DEBUG. Log file: {log_filepath}")

# --- Version Tracking Functions ---

def get_next_version(tenant_id):
    """Gets the next version number for a given tenant."""
    os.makedirs(VERSION_TRACKING_DIR, exist_ok=True)
    version_file_path = os.path.join(VERSION_TRACKING_DIR, f"tenant_{tenant_id}.json")
    current_version = 0.0 # Default to 0.0, so the first version becomes 1.0
    
    if os.path.exists(version_file_path):
        try:
            with open(version_file_path, 'r') as f:
                data = json.load(f)
                # Use get() with default to handle missing key or incorrect type gracefully
                version_read = data.get("version", 0.0) 
                if isinstance(version_read, (int, float)):
                    current_version = float(version_read)
                else:
                    logging.warning(f"Invalid version format found in {version_file_path}. Resetting to 0.0.")
                    current_version = 0.0
        except json.JSONDecodeError:
            logging.warning(f"Could not decode JSON from {version_file_path}. Resetting version.")
            current_version = 0.0
        except Exception as e:
            logging.error(f"Error reading version file {version_file_path}: {e}. Resetting version.")
            current_version = 0.0
            
    next_version = current_version + 1.0
    logging.info(f"Determined next version for tenant {tenant_id}: {next_version}")
    return next_version

def save_version(tenant_id, version):
    """Saves the current version number for a given tenant."""
    os.makedirs(VERSION_TRACKING_DIR, exist_ok=True)
    version_file_path = os.path.join(VERSION_TRACKING_DIR, f"tenant_{tenant_id}.json")
    try:
        with open(version_file_path, 'w') as f:
            json.dump({"version": version}, f, indent=4)
        logging.info(f"Saved version {version} for tenant {tenant_id} to {version_file_path}")
    except Exception as e:
        logging.error(f"Failed to save version file {version_file_path}: {e}")

# --- End Version Tracking Functions ---

def get_subscriptions(credential):
    """Lists all accessible Azure subscriptions."""
    try:
        subscription_client = SubscriptionClient(credential)
        subscriptions = list(subscription_client.subscriptions.list())
        if not SILENT_MODE:
            # Use rich print for this line if available
            rprint(f"[bold green]Found {len(subscriptions)} subscriptions.[/bold green]")
        logging.info(f"Found {len(subscriptions)} subscriptions.")
        return [{ 
            "id": sub.subscription_id, 
            "display_name": sub.display_name, 
            "tenant_id": sub.tenant_id,
            "state": str(sub.state)
        } for sub in subscriptions]
    except Exception as e:
        if not SILENT_MODE:
            rprint(f"[bold red]Failed to list subscriptions:[/bold red] {e}") # Use rich print
        logging.error(f"Failed to list subscriptions: {e}")
        return []

def select_subscriptions(subscriptions):
    """Interactive menu to select which subscriptions to audit."""
    if not subscriptions:
        if not SILENT_MODE:
            print("No subscriptions found. Cannot continue.")
        return []
        
    if not SILENT_MODE:
        print("\n=== Subscription Selection ===")
        print("Please select which subscriptions to audit:")
        print(" 0: All subscriptions")
        
        for i, sub in enumerate(subscriptions, 1):
            print(f" {i}: {sub['display_name']} ({sub['id']})")
    
    selected_indices = []
    valid_selection = False
    
    while not valid_selection:
        try:
            if SILENT_MODE:
                # In silent mode, automatically select all subscriptions
                return subscriptions
                
            selection = input("\nEnter subscription numbers separated by commas (e.g. 1,3,4), or 0 for all: ")
            
            # Check for "all" option
            if selection.strip() == "0":
                print("Selected all subscriptions.")
                return subscriptions
                
            # Parse individual selections
            indices = [int(idx.strip()) for idx in selection.split(",") if idx.strip()]
            
            # Validate selections
            if not indices:
                print("No valid selections made. Please try again.")
                continue
                
            valid_indices = [idx for idx in indices if 1 <= idx <= len(subscriptions)]
            
            if len(valid_indices) != len(indices):
                print(f"Some selections were out of range. Valid range: 1-{len(subscriptions)}")
                continue
                
            selected_subs = [subscriptions[idx-1] for idx in valid_indices]
            
            # Confirm selection
            print("\nSelected subscriptions:")
            for sub in selected_subs:
                print(f" - {sub['display_name']} ({sub['id']})")
                
            confirm = input("\nProceed with these selections? (y/n): ").lower()
            if confirm == 'y':
                valid_selection = True
                return selected_subs
            else:
                print("Selection cancelled. Please try again.")
                
        except ValueError:
            print("Invalid input. Please enter comma-separated numbers.")
        except Exception as e:
            print(f"Error during selection: {e}")
            print("Please try again.")
    
    return []

def save_raw_data(data, filename_prefix, timestamp_str):
    """Saves the collected data to a timestamped JSON file."""
    os.makedirs(DATA_DIR, exist_ok=True)
    filename = f"{filename_prefix}_{timestamp_str}.json"
    filepath = os.path.join(DATA_DIR, filename)
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4, default=str)
        if not SILENT_MODE:
            rprint(f"[green]Successfully saved raw data to[/green] [cyan]{filepath}[/cyan]") # Use rich print
        logging.info(f"Successfully saved raw data to {filepath}")
        return filepath
    except Exception as e:
        if not SILENT_MODE:
            rprint(f"[red]Failed to save raw data to[/red] [cyan]{filepath}[/cyan]: {e}") # Use rich print
        logging.error(f"Failed to save raw data to {filepath}: {e}")
        return None

def main():
    # Parse arguments here, then call main with args
    parser = argparse.ArgumentParser(description="Azure Infrastructure Documenter Tool")
    parser.add_argument(
        "--mode",
        choices=["Audit", "Design"],
        default="Audit",
        help="Specify the output mode: Audit (technical details) or Design (summaries and diagrams)."
    )
    # Add delta comparison argument
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("TIMESTAMP1", "TIMESTAMP2"),
        help="Compare two previous audit runs using their timestamps (YYYYMMDD_HHMMSS format). Skips new audit."
    )
    # Add a flag to skip the interactive menu and audit all subscriptions
    parser.add_argument(
        "--all-subscriptions",
        action="store_true",
        help="Audit all accessible subscriptions without interactive selection."
    )
    # Add silent mode flag
    parser.add_argument(
        "--silent",
        action="store_true",
        help="Run in silent mode without printing to console. Output is still logged to file."
    )
    
    args = parser.parse_args()
    
    # Set global silent mode flag
    global SILENT_MODE
    SILENT_MODE = args.silent
    
    # Configure logging for silent mode
    if SILENT_MODE:
        # Remove console handler in silent mode
        for handler in logger.handlers[:]:
            if isinstance(handler, logging.StreamHandler) and handler.stream == sys.stdout:
                logger.removeHandler(handler)
        
        # Make sure we still have a file handler to capture logs
        log_dir = os.path.join(OUTPUT_BASE_DIR, "logs")
        os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.FileHandler(os.path.join(log_dir, f"azure_documenter_{get_formatted_timestamp()}.log"))
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # --- Handle Delta Comparison Mode ---
    if args.compare:
        timestamp1, timestamp2 = args.compare
        if not SILENT_MODE:
            # Use rich print for delta mode start
            rprint(f"[bold yellow]Running in Delta Comparison mode:[/bold yellow] Comparing [cyan]{timestamp1}[/cyan] vs [cyan]{timestamp2}[/cyan]")
        logging.info(f"Running in Delta Comparison mode: Comparing {timestamp1} vs {timestamp2}")

        # Construct file paths
        file1 = os.path.join(DATA_DIR, f"azure_audit_raw_data_{timestamp1}.json")
        file2 = os.path.join(DATA_DIR, f"azure_audit_raw_data_{timestamp2}.json")

        if not os.path.exists(file1):
            if not SILENT_MODE:
                print(f"Comparison file not found: {file1}")
            logging.error(f"Comparison file not found: {file1}")
            return
        if not os.path.exists(file2):
            if not SILENT_MODE:
                print(f"Comparison file not found: {file2}")
            logging.error(f"Comparison file not found: {file2}")
            return

        if not SILENT_MODE:
            print(f"Loading data from {file1} and {file2}...")
        logging.info(f"Loading data from {file1} and {file2}...")
        data1 = load_audit_data(file1)
        data2 = load_audit_data(file2)
        
        if data1 and data2:
            if not SILENT_MODE:
                print("Analyzing differences between the two audit files...")
            logging.info("Analyzing differences between the two audit files...")
            delta = analyze_delta(data1, data2)
            
            if not SILENT_MODE:
                print("Generating delta report...")
            logging.info("Generating delta report...")
            delta_report_path = generate_delta_report(delta, timestamp1, timestamp2, OUTPUT_BASE_DIR)
            
            if delta_report_path:
                # Generate HTML version of the delta report
                if not SILENT_MODE:
                    print("Converting delta report to HTML...")
                logging.info("Converting delta report to HTML...")
                html_report_path = export_markdown_to_html(delta_report_path, REPORT_DIR, f"delta_{timestamp1}_vs_{timestamp2}")
                
                # Log paths to both reports for user convenience
                if html_report_path:
                    if not SILENT_MODE:
                        print(f"Delta reports generated:")
                        print(f"  - Markdown: {delta_report_path}")
                        print(f"  - HTML: {html_report_path}")
                    logging.info(f"Delta reports generated:")
                    logging.info(f"  - Markdown: {delta_report_path}")
                    logging.info(f"  - HTML: {html_report_path}")
                else:
                    if not SILENT_MODE:
                        print(f"Delta report generated: {delta_report_path}")
                    logging.info(f"Delta report generated: {delta_report_path}")
            else:
                if not SILENT_MODE:
                    print("Failed to generate delta report.")
                logging.error("Failed to generate delta report.")
        else:
            if not SILENT_MODE:
                print("Failed to load data for comparison.")
            logging.error("Failed to load data for comparison.")

        if not SILENT_MODE:
            print("Azure Documenter Delta Comparison finished.")
        logging.info("Azure Documenter Delta Comparison finished.")
        return # Exit after comparison
        
    # --- Normal Audit Mode (if --compare is not used) ---
    # Generate timestamp for this run (using local timezone)
    run_timestamp = get_formatted_timestamp()
    if not SILENT_MODE:
        rprint(Panel(f"""Starting Azure Documenter
Mode: [bold]{args.mode}[/bold]
Run ID: [cyan]{run_timestamp}[/cyan]""", 
                     title="[bold blue]Azure Documenter[/bold blue]", 
                     subtitle="Starting Run", 
                     border_style="blue"))
        rprint("[italic grey50]This Run ID can be used later with --compare to identify changes[/italic grey50]")
    logging.info(f"Starting Azure Documenter in {args.mode} mode (Run ID: {run_timestamp}).")

    # --- Authentication ---
    if not SILENT_MODE:
        rprint("""
[bold blue]Authenticating using DefaultAzureCredential...[/bold blue]""")
    timestamp_str = get_formatted_timestamp()
    if not SILENT_MODE:
        print(f"Audit timestamp: {timestamp_str}")
    logging.info(f"Audit timestamp: {timestamp_str}")

    if not SILENT_MODE:
        print("\nAuthenticating using DefaultAzureCredential...")
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        available_subscriptions = list(subscription_client.subscriptions.list())
        # Test credential early by listing subscriptions
        all_subscriptions = get_subscriptions(credential)
    except Exception as e:
        if not SILENT_MODE:
            print(f"Authentication failed: {e}")
        logging.critical(f"Authentication failed: {e}")
        return

    if not all_subscriptions:
        if not SILENT_MODE:
            print("No accessible subscriptions found. Exiting.")
        logging.warning("No accessible subscriptions found. Exiting.")
        return

    # Select subscriptions unless --all-subscriptions is used
    if args.all_subscriptions:
        selected_subscriptions = all_subscriptions
        if not SILENT_MODE:
            rprint(f"[yellow]--all-subscriptions flag detected. Auditing all [bold]{len(selected_subscriptions)}[/bold] accessible subscriptions.[/yellow]")
        logging.info(f"Auditing all {len(selected_subscriptions)} accessible subscriptions due to --all-subscriptions flag.")
    else:
        selected_subscriptions = select_subscriptions(all_subscriptions)

    if not selected_subscriptions:
        if not SILENT_MODE:
            print("No subscriptions selected for audit. Exiting.")
        logging.info("No subscriptions selected for audit. Exiting.")
        return

    # Fetch tenant-level info once (like Service Principals)
    # We need the credential, which we have
    service_principal_info = fetch_service_principal_summary(credential)

    # --- Process selected subscriptions ---
    all_subscription_data = {}
    tenant_display_name = "Unknown Tenant" # Store display name (e.g., "Contoso Corp")
    tenant_default_domain = "example.onmicrosoft.com" # Store default domain (e.g., "contoso.onmicrosoft.com")
    first_sub = True

    if not SILENT_MODE:
        rprint(f"""
[bold blue]Starting data fetch for {len(selected_subscriptions)} selected subscription(s)...[/bold blue]""")

    for i, sub_info in enumerate(selected_subscriptions):
        sub_id = sub_info['id']
        sub_display_name = sub_info['display_name']
        if not SILENT_MODE:
            # Use simple styled print for subscription header to avoid Panel/Linter issues
            rprint(f"\n[bold magenta]--- Processing Subscription {i+1}/{len(selected_subscriptions)}: {sub_display_name} ({sub_id}) ---[/bold magenta]")
        logging.info(f"Processing Subscription: {sub_display_name} ({sub_id})")

        # --- Attempt to fetch Tenant Info (only once) ---
        if first_sub and sub_info.get('tenant_id'):
            current_tenant_id = sub_info['tenant_id']
            # Determine document version based on tenant ID BEFORE fetching details
            document_version = get_next_version(current_tenant_id)
            if not SILENT_MODE:
                rprint(f"[blue]Determined Document Version for Tenant ({current_tenant_id}): {document_version}[/blue]")
            
            try:
                tenants = list(subscription_client.tenants.list())
                if tenants:
                    # Find the tenant matching the current subscription's tenant_id
                    current_tenant = next((t for t in tenants if t.tenant_id == current_tenant_id), None)
                    if current_tenant:
                        # Prioritize Display Name
                        if current_tenant.display_name:
                            tenant_display_name = current_tenant.display_name
                            logging.info(f"Successfully fetched Tenant Display Name: {tenant_display_name}")
                        else:
                            tenant_display_name = f"{current_tenant_id} (No Display Name)" # Fallback if display name empty
                            logging.warning(f"Tenant {current_tenant_id} found, but display_name property is missing or empty.")
                        
                        # Get Default Domain
                        if current_tenant.default_domain:
                            tenant_default_domain = current_tenant.default_domain
                            logging.info(f"Successfully fetched Tenant Default Domain: {tenant_default_domain}")
                        else:
                            tenant_default_domain = f"{current_tenant_id}.onmicrosoft.com" # Educated guess fallback
                            logging.warning(f"Tenant {current_tenant_id} found, but default_domain property is missing. Using fallback: {tenant_default_domain}")
                    else:
                        logging.warning(f"Could not find specific tenant match for ID {current_tenant_id} in tenants list.")
                        tenant_display_name = f"{current_tenant_id} (Tenant ID)" # Fallback
                        tenant_default_domain = f"{current_tenant_id}.onmicrosoft.com" # Fallback
                else:
                    logging.warning("subscription_client.tenants.list() returned no tenants.")
                    tenant_display_name = f"{current_tenant_id} (Tenant ID)" # Fallback
                    tenant_default_domain = f"{current_tenant_id}.onmicrosoft.com" # Fallback

            except Exception as e:
                logging.warning(f"Could not fetch tenant details using SubscriptionClient (Permissions? Error: {e}). Falling back to Tenant ID.")
                tenant_display_name = f"{current_tenant_id} (Tenant ID)"
                tenant_default_domain = f"{current_tenant_id}.onmicrosoft.com"
            
            first_sub = False # Don't try fetching again
        elif first_sub: # Handle case where first sub has no tenant_id (shouldn't happen)
            tenant_display_name = "Unknown Tenant"
            tenant_default_domain = "unknown.onmicrosoft.com"
            first_sub = False
            logging.error("First subscription processed lacked a tenant_id.")

        # Pass the determined tenant_display_name and tenant_default_domain to the subscription_info
        sub_data = {
            "subscription_info": {
                "id": sub_id, 
                "display_name": sub_display_name, 
                "tenant_id": sub_info.get('tenant_id'), 
                "state": str(sub_info.get('state')), 
                "tenant_domain": tenant_default_domain, # Store domain per sub for potential use
                "identity": {
                    "service_principals": service_principal_info
                }
            },
            "resources": [],
            "networking": {},
            "security": {},
            "costs": {},
            "governance": {},
            "monitoring": {}
        }

        # Fetch base resources
        if not SILENT_MODE: rprint("  Fetching base resources...")
        resources_list = fetch_resources(credential, sub_id)

        # --- Extract Resource Group Names ---
        resource_groups_in_sub = set()
        if resources_list:
            for resource in resources_list:
                if resource.get('resource_group'):
                    resource_groups_in_sub.add(resource.get('resource_group'))
        resource_groups_in_sub = list(resource_groups_in_sub) # Convert to list if needed by fetchers
        logging.info(f"[{sub_id}] Found {len(resource_groups_in_sub)} resource groups in subscription.")
        # ------------------------------------

        # --- Enhance Resources with App Service Details ---
        enriched_resources = []
        app_service_count = sum(1 for res in resources_list if res.get('type') == 'Microsoft.Web/sites') if resources_list else 0
        if app_service_count > 0 and not SILENT_MODE: rprint(f"  Fetching details for {app_service_count} App Service(s)...")
        for resource in resources_list:
            if resource.get('type') == 'Microsoft.Web/sites':
                resource_group = resource.get('resource_group')
                app_name = resource.get('name')
                if resource_group and app_name:
                    logging.info(f"Found App Service '{app_name}'. Fetching details...")
                    details = fetch_app_service_details(credential, sub_id, resource_group, app_name)
                    resource['app_service_details'] = details # Add details to the resource dict
                else:
                    logging.warning(f"Could not determine RG or Name for App Service ID: {resource.get('id')}. Skipping detail fetch.")
            enriched_resources.append(resource)

        sub_data['resources'] = enriched_resources
        # --------------------------------------------------

        # Fetch other details
        if not SILENT_MODE: rprint("  Fetching networking details...")
        sub_data['networking'] = fetch_networking_details(credential, sub_id, enriched_resources) 
        if not SILENT_MODE: rprint("  Fetching security details...")
        sub_data['security'] = fetch_security_details(credential, sub_id)
        if not SILENT_MODE: rprint("  Fetching cost details...")
        sub_data['costs'] = fetch_cost_details(credential, sub_id)
        if not SILENT_MODE: rprint("  Fetching governance details...")
        sub_data['governance'] = fetch_governance_details(credential, sub_id)

        # Fetch monitoring details
        if not SILENT_MODE: rprint("  Fetching monitoring details (Log Analytics)...")
        try:
            loganalytics_client = LogAnalyticsManagementClient(credential, sub_id)
            workspaces = []
            # Try listing by subscription first
            try:
                workspaces = list(loganalytics_client.workspaces.list())
                logging.info(f"[{sub_id}] Found {len(workspaces)} Log Analytics Workspaces via subscription list.")
            except HttpResponseError as sub_list_error:
                logging.warning(f"[{sub_id}] Could not list Log Analytics Workspaces by subscription ({sub_list_error.message}). Falling back to listing by resource group.")
                if resource_groups_in_sub:
                    for rg_name in resource_groups_in_sub:
                        try:
                            rg_workspaces = list(loganalytics_client.workspaces.list_by_resource_group(resource_group_name=rg_name))
                            if rg_workspaces: workspaces.extend(rg_workspaces)
                        except Exception as rg_error:
                            logging.warning(f"[{sub_id}] Failed listing LA Workspaces in RG '{rg_name}': {rg_error}")
                else:
                    logging.warning(f"[{sub_id}] Cannot list LA Workspaces by RG as no RGs were identified.")
            
            # Process workspaces
            processed_workspaces = []
            for ws in workspaces:
                ws_details = {
                    "id": ws.id,
                    "name": ws.name,
                    "location": ws.location,
                    "resource_group": ws.id.split('/')[4],
                    "sku": ws.sku.name if ws.sku else "Unknown",
                    "retention_in_days": ws.retention_in_days,
                    "tags": ws.tags,
                    "solutions": [] # Placeholder for solutions
                }
                processed_workspaces.append(ws_details)
            sub_data['monitoring']['log_analytics_workspaces'] = processed_workspaces
            logging.info(f"[{sub_id}] Successfully processed {len(processed_workspaces)} Log Analytics Workspaces.")
            if not SILENT_MODE: rprint(f"    Found {len(processed_workspaces)} Log Analytics Workspaces.")
            
        except ImportError:
            logging.error(f"[{sub_id}] azure-mgmt-loganalytics library not found. Skipping Log Analytics fetch.")
            if not SILENT_MODE: rprint("[yellow]    Skipping Log Analytics: Library not found.[/yellow]")
        except HttpResponseError as la_error:
            logging.warning(f"[{sub_id}] Authorization/API error fetching Log Analytics: {la_error.message}")
            if not SILENT_MODE: rprint(f"[yellow]    Warning fetching Log Analytics: {la_error.message}[/yellow]")
        except Exception as la_ex:
            logging.error(f"[{sub_id}] Unexpected error fetching Log Analytics: {la_ex}")
            if not SILENT_MODE: rprint(f"[red]    Error fetching Log Analytics: {la_ex}[/red]")

        if not SILENT_MODE:
            # Ensure triple quotes for the multi-line f-string below
            rprint(f"""[bold green]--> Finished processing Subscription: {sub_display_name}[/bold green]
""") # Add space after finishing
        logging.info(f"Finished processing Subscription: {sub_display_name}")

        all_subscription_data[sub_id] = sub_data
        logging.info(f"Processing Subscription: {sub_display_name} ({sub_id}) END")

    if not SILENT_MODE:
        rprint("[bold blue]All data fetching complete.[/bold blue]")
    logging.info("All data fetching complete.")

    # Save the raw data
    raw_data_filepath = save_raw_data(all_subscription_data, "azure_audit_raw_data", timestamp_str)

    # --- Report Generation (pass timestamp and version) ---
    if not SILENT_MODE:
        rprint("""
[bold blue]Proceeding to report generation...[/bold blue]""")
    logging.info("Proceeding to report generation...")

    # Generate Diagrams (pass timestamp)
    if not SILENT_MODE:
        rprint("  Generating network diagrams...")
    logging.info("Generating diagrams...")
    generated_diagram_paths = generate_all_diagrams(all_subscription_data, DIAGRAM_DIR, run_timestamp)

    # Generate Markdown Report (pass timestamp and version)
    generated_report_path = None # Initialize path

    # Determine tenant_id for saving version (use the one from the first valid sub)
    final_tenant_id = None
    if selected_subscriptions and selected_subscriptions[0].get('tenant_id'):
        final_tenant_id = selected_subscriptions[0]['tenant_id']
    else:
        logging.error("Could not determine Tenant ID after processing subscriptions. Cannot save version.")

    if args.mode == "Design":
        if not SILENT_MODE:
            rprint(f"  Generating [bold]{args.mode}[/bold] document...")
        logging.info("Generating design document...")
        # Call the new design document generator
        generated_report_path = generate_design_document(
            all_subscription_data,
            OUTPUT_BASE_DIR,
            tenant_display_name=tenant_display_name, # Pass Display Name
            tenant_default_domain=tenant_default_domain, # Pass Domain Name
            document_version=document_version, # Pass Version
            diagram_paths=generated_diagram_paths,
            timestamp_str=run_timestamp,
            silent_mode=SILENT_MODE
        )
    else: # Default to Audit mode
        if not SILENT_MODE:
            rprint(f"  Generating [bold]{args.mode}[/bold] report...")
        logging.info("Generating audit report...")
        # Call the original markdown generator
        generated_report_path = generate_markdown_report(
            all_subscription_data,
            OUTPUT_BASE_DIR,
            tenant_display_name=tenant_display_name, # Pass Display Name
            tenant_default_domain=tenant_default_domain, # Pass Domain Name (though maybe not used in Audit)
            document_version=document_version, # Pass Version
            diagram_paths=generated_diagram_paths,
            timestamp_str=run_timestamp,
            silent_mode=SILENT_MODE
        )

    # --- Enhance Report with LLM (Optional, based on config) ---
    llm_enhanced_report_path = None
    if generated_report_path and config.LLM_PROVIDER and config.LLM_API_KEY and config.LLM_MODEL:
        if not SILENT_MODE:
            rprint(f"  Enhancing {args.mode} document with LLM ([cyan]{config.LLM_PROVIDER}[/cyan])...")
        logging.info(f"Enhancing {args.mode} document with LLM ({config.LLM_PROVIDER})...")
        # Pass the correct base report path to the enhancer
        llm_enhanced_report_path = enhance_report_with_llm(
            generated_report_path, # Use the path generated above
            all_subscription_data,
            args.mode # Pass the mode to the LLM enhancer
        )
        # Update report path if enhancement was successful
        if llm_enhanced_report_path:
            if not SILENT_MODE:
                rprint(f"  LLM enhancement complete. Enhanced report: [cyan]{llm_enhanced_report_path}[/cyan]")
            logging.info(f"LLM enhancement complete. Enhanced report: {llm_enhanced_report_path}")
            # Use the enhanced path for HTML conversion etc.
            final_report_path = llm_enhanced_report_path 
        else:
            if not SILENT_MODE:
                rprint("[yellow]  LLM enhancement failed or was skipped. Using original report.[/yellow]")
            logging.warning("LLM enhancement failed or skipped. Using original report.")
            final_report_path = generated_report_path # Fall back to original
    else:
        if generated_report_path: # Only log if a report was actually generated
            if not SILENT_MODE:
                rprint("[yellow]  LLM enhancement skipped (LLM not configured).[/yellow]")
            logging.info("LLM enhancement skipped (LLM not configured).")
        final_report_path = generated_report_path # Use original if LLM not configured

    # --- Generate HTML Report (Pass Version) ---
    html_report_path = None # Initialize
    if final_report_path:
        if not SILENT_MODE:
            rprint("  Converting report to HTML...")
        logging.info("Converting report to HTML...")
        # Determine filename prefix based on mode and enhancement
        html_filename_prefix = f"azure_{args.mode.lower()}_report"
        if llm_enhanced_report_path:
            html_filename_prefix += "_llm_enhanced"
        
        html_report_path = export_markdown_to_html(
            final_report_path,
            REPORT_DIR,
            tenant_display_name=tenant_display_name, # Pass Display Name
            tenant_default_domain=tenant_default_domain, # Pass Domain Name
            document_version=document_version, # Pass Version
            timestamp_str=run_timestamp, # Pass the pure timestamp 
            silent_mode=SILENT_MODE
        )

        # Log paths for user convenience using rich print
        if not SILENT_MODE:
            rprint(f"""
[bold green]{args.mode} Documentation Generation Complete:[/bold green]""")
            if raw_data_filepath: rprint(f"  - Raw Data JSON: [cyan]{raw_data_filepath}[/cyan]")
            
            if final_report_path == llm_enhanced_report_path and llm_enhanced_report_path:
                rprint(f"  - Original Markdown Report: [cyan]{generated_report_path}[/cyan]") 
                rprint(f"  - LLM Enhanced Markdown Report: [cyan]{final_report_path}[/cyan]")
            elif final_report_path:
                rprint(f"  - Markdown Report: [cyan]{final_report_path}[/cyan]")
            
            # --- Improved Diagram Path Output --- 
            if generated_diagram_paths:
                rprint("  - Diagrams Generated:")
                # Print tenant diagrams first
                tenant_diagrams = generated_diagram_paths.get("tenant_diagrams", {})
                for key, filename in tenant_diagrams.items():
                    diagram_type = key.replace('_', ' ').title()
                    rprint(f"    - Tenant {diagram_type}: [cyan]{filename}[/cyan]")
                    
                # Print subscription-specific diagrams (more readable)
                for sub_id, diagrams in generated_diagram_paths.items():
                    if sub_id == "tenant_diagrams": continue 
                    
                    sub_name = all_subscription_data.get(sub_id, {}).get("subscription_info", {}).get("display_name", sub_id)
                    if isinstance(diagrams, dict):
                         rprint(f"    - Subscription '[bold]{sub_name}[/bold]':")
                         for key, filename in diagrams.items():
                             diagram_type = key.replace('_', ' ').title()
                             rprint(f"      - {diagram_type}: [cyan]{filename}[/cyan]")
                    else:
                        logging.warning(f"Unexpected diagram path format for subscription {sub_id}: {diagrams}")
                        rprint(f"    - Subscription '[bold]{sub_name}[/bold]': (Diagram path format unexpected)")
                        
            if html_report_path:
                rprint(f"  - HTML Report: [cyan]{html_report_path}[/cyan]")

        # --- Simplified Final Log Message ---
        diagram_log_msg = "Diagrams generated." if generated_diagram_paths else "No diagrams generated."
        logging.info(f"Documentation generated. Raw data: {raw_data_filepath}, Report: {final_report_path}, {diagram_log_msg}, HTML: {html_report_path}")

        # --- Save Version AFTER successful report generation ---
        if final_tenant_id:
            save_version(final_tenant_id, document_version)
        else:
            logging.error("Skipping version save because Tenant ID could not be confirmed.")

    else:
        if not SILENT_MODE:
            rprint("[red]Skipping HTML conversion as report generation failed.[/red]")
        logging.error("Markdown report generation failed or skipped.")
        # Do NOT save version if report generation failed
        logging.warning(f"Version {document_version} for tenant {final_tenant_id} was NOT saved because report generation failed.")
    
    if not SILENT_MODE:
        rprint(Panel(f"""Azure Documenter run finished.
Run ID: [cyan]{run_timestamp}[/cyan]""", 
                     title="[bold green]Run Complete[/bold green]", 
                     border_style="green"))
    logging.info(f"Azure Documenter run finished (Run ID: {run_timestamp}).")

if __name__ == "__main__":
    main() 