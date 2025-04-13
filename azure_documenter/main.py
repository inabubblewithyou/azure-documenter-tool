import argparse
import logging
import os
import json # For saving raw data
import sys # For explicit stdout handler
from datetime import datetime, timezone # Add timezone import
import time  # For local timezone handling
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.resource.subscriptions import SubscriptionClient
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.core.exceptions import HttpResponseError
import asyncio # Add asyncio import
import platform
from typing import Dict, List, Tuple, Any

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
from fetchers.compute import fetch_all_vm_details
from fetchers.network import fetch_networking_details
from fetchers.security import fetch_security_details, fetch_jit_policies
from fetchers.costs import fetch_cost_details, fetch_detailed_cost_report
from fetchers.governance import fetch_governance_details, fetch_management_groups
from fetchers.identity import fetch_service_principal_summary, fetch_custom_roles, fetch_tenant_details
from fetchers.monitor import fetch_monitoring_details
from fetchers.keyvault import fetch_key_vaults, fetch_key_vault_certificates
from fetchers.web import fetch_app_service_details # Fetcher for app services and settings
from fetchers.scaling import fetch_autoscale_settings 
from fetchers.database import fetch_database_details
from fetchers.storage import fetch_storage_details
from fetchers.ai_services import fetch_ai_services

# Import generators
from generators.markdown_writer import generate_markdown_report
from generators.diagram_generator import generate_all_diagrams, generate_tenant_network_diagram
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

async def process_subscription(credential, subscription_info, tenant_sp_summary):
    """Fetches all data for a single subscription."""
    sub_id = subscription_info['id']
    sub_name = subscription_info['display_name']
    if not SILENT_MODE: rprint(f"\n[bold magenta]--- Processing Subscription: {sub_name} ({sub_id}) ---[/bold magenta]")
    logging.info(f"Processing Subscription: {sub_name} ({sub_id}) START")

    subscription_data = { "subscription_info": subscription_info } # Start with basic info
    
    # Wrap fetches in try/except to allow continuing if one fetcher fails
    try:
        if not SILENT_MODE: rprint("  Fetching Resources...")
        resources = await fetch_resources(credential, sub_id)
        subscription_data["resources"] = resources
    except Exception as e:
        logging.error(f"[{sub_id}] Failed during fetch_resources: {e}", exc_info=True)
        subscription_data["error"] = f"fetch_resources failed: {e}"
        return sub_id, subscription_data

    # --- Fetch Resource Groups --- 
    try:
        if not SILENT_MODE: rprint("  Fetching Resource Groups...")
        resource_client = ResourceManagementClient(credential, sub_id)
        rg_list = list(resource_client.resource_groups.list())
        subscription_data["resource_groups"] = [
            {
                "id": rg.id,
                "name": rg.name,
                "location": rg.location,
                "managed_by": rg.managed_by,
                "tags": rg.tags
            } for rg in rg_list
        ]
        logging.info(f"[{sub_id}] Found {len(rg_list)} resource groups.")
    except Exception as e:
        logging.error(f"[{sub_id}] Failed during resource group fetch: {e}", exc_info=True)
        subscription_data["resource_groups"] = {"error": str(e)}

    # --- Other Fetchers (Make them async and await them) ---
    # Initial batch of fetchers
    fetch_tasks = {
        "compute": fetch_all_vm_details(credential, sub_id),
        "networking": fetch_networking_details(credential, sub_id, resources),
        "security": fetch_security_details(credential, sub_id),
        "costs": fetch_cost_details(credential, sub_id),
        "governance": fetch_governance_details(credential, sub_id),
        "monitoring": fetch_monitoring_details(credential, sub_id),
        "key_vaults": fetch_key_vaults(credential, sub_id),
        "web_details": fetch_app_service_details(credential, sub_id),
        "scaling": fetch_autoscale_settings(credential, sub_id),
        "database": fetch_database_details(credential, sub_id),
        "storage": fetch_storage_details(credential, sub_id),
        "ai_services": fetch_ai_services(credential, sub_id)  # Add AI services fetcher
    }

    results = await asyncio.gather(*fetch_tasks.values(), return_exceptions=True)
    
    fetch_keys = list(fetch_tasks.keys())
    for i, result in enumerate(results):
        key = fetch_keys[i]
        if isinstance(result, Exception):
            logging.error(f"[{sub_id}] Failed during {key} fetch: {result}", exc_info=True)
            subscription_data["error"] = subscription_data.get("error", "") + f"; {key} fetch failed: {result}"
            subscription_data[key] = {"error": str(result)}
        else:
            subscription_data[key] = result

    # --- Fetch Key Vault Certificates (After fetching vaults) ---
    if "key_vaults" in subscription_data and not isinstance(subscription_data["key_vaults"], dict):
        vaults_list = subscription_data["key_vaults"]
        if vaults_list:
            cert_tasks = []
            vault_uri_map = {}
            for index, vault_info in enumerate(vaults_list):
                if isinstance(vault_info, dict) and vault_info.get("vault_uri"):
                    vault_uri = vault_info["vault_uri"]
                    cert_tasks.append(fetch_key_vault_certificates(credential, vault_uri))
                    vault_uri_map[index] = vault_uri
                else:
                    logging.warning(f"[{sub_id}] Skipping certificate fetch for vault entry due to missing URI: {vault_info}")

            if cert_tasks:
                cert_results = await asyncio.gather(*cert_tasks, return_exceptions=True)
                for i, cert_result in enumerate(cert_results):
                    original_vault_uri = vault_uri_map.get(i)
                    if original_vault_uri:
                        target_vault = next((v for v in vaults_list if isinstance(v, dict) and v.get("vault_uri") == original_vault_uri), None)
                        if target_vault:
                            if isinstance(cert_result, Exception):
                                error_msg = f"Failed fetching certificates for vault {original_vault_uri}: {cert_result}"
                                logging.error(f"[{sub_id}] {error_msg}", exc_info=cert_result)
                                target_vault["certificates"] = {"error": error_msg}
                                subscription_data["error"] = subscription_data.get("error", "") + f"; Cert fetch failed for {original_vault_uri}"
                            elif isinstance(cert_result, dict):
                                target_vault["certificates"] = cert_result.get("certificates", [])
                                if cert_result.get("error"):
                                    target_vault["certificate_fetch_error"] = cert_result["error"]
                                    logging.warning(f"[{sub_id}] Error reported within certificate fetch result for {original_vault_uri}: {cert_result['error']}")
                            else:
                                logging.warning(f"[{sub_id}] Unexpected result type for certificate fetch for {original_vault_uri}: {type(cert_result)}")
                                target_vault["certificates"] = {"error": "Unexpected result type"}
                        else:
                            logging.warning(f"[{sub_id}] Could not find original vault entry for URI {original_vault_uri} after fetching certificates.")
                    else:
                        logging.warning(f"[{sub_id}] Could not map certificate result index {i} back to a vault URI.")

    # --- Merge detailed VM info into the main resources list ---
    try:
        if ("resources" in subscription_data and "compute" in subscription_data and
            isinstance(subscription_data["resources"], list) and
            isinstance(subscription_data["compute"], dict) and
            "error" not in subscription_data["compute"] and
            "vms" in subscription_data["compute"] and
            isinstance(subscription_data["compute"]["vms"], list)):

            vm_list_from_fetcher = subscription_data["compute"]["vms"]
            vm_details_map = {vm.get("id"): vm for vm in vm_list_from_fetcher if isinstance(vm, dict) and vm.get("id")}
            
            if not vm_details_map and vm_list_from_fetcher:
                logging.debug(f"[{sub_id}] No valid VM details found to merge with resources list.")
            
            # Update resources with VM details where applicable
            for resource in subscription_data["resources"]:
                if isinstance(resource, dict) and resource.get("type") == "Microsoft.Compute/virtualMachines":
                    vm_id = resource.get("id")
                    if vm_id and vm_id in vm_details_map:
                        resource.update(vm_details_map[vm_id])

            merged_count = len(vm_details_map)
            logging.info(f"[{sub_id}] Merged details for {merged_count} VMs into the main resource list.")

    except Exception as merge_e:
        logging.error(f"[{sub_id}] Failed to merge VM details into resource list: {merge_e}", exc_info=True)

    # --- Fetch JIT Policies ---
    try:
        jit_policies = await fetch_jit_policies(credential, sub_id)
        if "security" in subscription_data and isinstance(subscription_data["security"], dict):
            subscription_data["security"]["jit_policies"] = jit_policies
        else:
            subscription_data["jit_policies"] = jit_policies
    except Exception as jit_e:
        logging.error(f"[{sub_id}] Failed during JIT policies fetch: {jit_e}", exc_info=jit_e)
        if "security" in subscription_data and isinstance(subscription_data["security"], dict):
            subscription_data["security"]["jit_policies"] = {"error": str(jit_e)}
        else:
            subscription_data["jit_policies"] = {"error": str(jit_e)}

    # --- Fetch Custom Roles ---
    try:
        custom_roles = await fetch_custom_roles(credential, sub_id)
        subscription_data["identity"] = {
            "service_principal_summary": tenant_sp_summary,
            "custom_roles": custom_roles
        }
    except Exception as id_e:
        logging.error(f"[{sub_id}] Failed during identity fetch (SP Summary or Custom Roles): {id_e}", exc_info=id_e)
        subscription_data["identity"] = {"error": str(id_e)}
        if "error" not in subscription_data:
            subscription_data["error"] = f"identity fetch failed: {id_e}"

    if not SILENT_MODE: rprint(f"[green]--> Finished processing {sub_name}.[/green]")
    logging.info(f"Processing Subscription: {sub_name} ({sub_id}) END")
    return sub_id, subscription_data

async def main():
    global SILENT_MODE # Allow modifying the global flag

    # Argument Parsing
    parser = argparse.ArgumentParser(description="Azure Documentation Tool")
    parser.add_argument("--mode", choices=["Audit", "Design", "Compare"], default="Audit", help="Specify the output mode: Audit, Design, or Compare.")
    parser.add_argument("--compare", nargs=2, metavar=("TIMESTAMP1", "TIMESTAMP2"), help="Compare two previous audit runs using timestamps (YYYYMMDD_HHMMSS format). Used with --mode Compare.")
    parser.add_argument("--all-subscriptions", action="store_true", help="Audit all accessible subscriptions without interactive selection.")
    parser.add_argument("--silent", "-s", action="store_true", help="Run in silent mode (suppress console output, but still log to file).")
    args = parser.parse_args()
    
    # Set global silent mode flag
    SILENT_MODE = args.silent
    
    # --- Configure Logging for Silent Mode ---
    if SILENT_MODE:
        # Remove console handler if it exists
        if console_handler and console_handler in logger.handlers:
             logger.removeHandler(console_handler)
        # Ensure Rich console is also silenced if it was initialized
        global console
        if console: 
             console.quiet = True 
             console.file = open(os.devnull, 'w') # Redirect rich output to null
    elif _RICH_AVAILABLE and console_handler not in logger.handlers: 
         logger.addHandler(console_handler) # Re-add if not silent and was removed
    # ---------------------------------------

    # --- Handle Delta Comparison Mode (Restored) ---
    if args.mode == "Compare":
        if not args.compare:
            if not SILENT_MODE: rprint("[red]Error: --compare requires two timestamps when using --mode Compare.[/red]")
            logging.error("Compare mode selected without providing two timestamps via --compare.")
            sys.exit(1)
        
        timestamp1, timestamp2 = args.compare
        if not SILENT_MODE: rprint(f"[bold yellow]Running in Delta Comparison mode:[/bold yellow] Comparing [cyan]{timestamp1}[/cyan] vs [cyan]{timestamp2}[/cyan]")
        logging.info(f"Running in Delta Comparison mode: Comparing {timestamp1} vs {timestamp2}")

        file1 = os.path.join(DATA_DIR, f"azure_audit_raw_data_{timestamp1}.json")
        file2 = os.path.join(DATA_DIR, f"azure_audit_raw_data_{timestamp2}.json")

        if not os.path.exists(file1) or not os.path.exists(file2):
            if not SILENT_MODE: rprint(f"[red]Error: Comparison file(s) not found. Checked paths:\n - {file1}\n - {file2}[/red]")
            logging.error(f"Comparison file(s) not found: {file1}, {file2}")
            sys.exit(1)

        if not SILENT_MODE: rprint(f"Loading data from {file1} and {file2}...")
        logging.info(f"Loading data from {file1} and {file2}...")
        data1 = load_audit_data(file1)
        data2 = load_audit_data(file2)
        
        if data1 and data2:
            if not SILENT_MODE: rprint("Analyzing differences...")
            logging.info("Analyzing differences...")
            delta = analyze_delta(data1, data2)
            
            if not SILENT_MODE: rprint("Generating delta report...")
            logging.info("Generating delta report...")
            # Pass base output dir for consistency
            delta_report_path = generate_delta_report(delta, timestamp1, timestamp2, OUTPUT_BASE_DIR)
            
            if delta_report_path:
                if not SILENT_MODE: rprint("Converting delta report to HTML...")
                logging.info("Converting delta report to HTML...")
                # Pass REPORT_DIR and base filename prefix
                html_report_path = export_markdown_to_html(delta_report_path, REPORT_DIR, f"delta_{timestamp1}_vs_{timestamp2}")
                
                if html_report_path:
                    if not SILENT_MODE:
                        rprint("[green]Delta reports generated:[/green]")
                        rprint(f"  - Markdown: {delta_report_path}")
                        rprint(f"  - HTML: {html_report_path}")
                    logging.info(f"Delta reports generated: Markdown: {delta_report_path}, HTML: {html_report_path}")
                else:
                    if not SILENT_MODE: rprint(f"[green]Delta report generated:[/green] {delta_report_path}")
                    logging.info(f"Delta report generated: {delta_report_path}")
            else:
                if not SILENT_MODE: rprint("[yellow]Failed to generate delta report (or no differences found).[/yellow]")
                logging.warning("Failed to generate delta report (or no differences found).")
        else:
            if not SILENT_MODE: rprint("[red]Failed to load data for comparison.[/red]")
            logging.error("Failed to load data for comparison.")

        if not SILENT_MODE: rprint("Azure Documenter Delta Comparison finished.")
        logging.info("Azure Documenter Delta Comparison finished.")
        sys.exit(0) # Exit after comparison
    # --- End Delta Comparison Mode ---
        
    # --- Normal Audit/Design Mode ---
    run_timestamp = get_formatted_timestamp() # Timestamp for this run
    if not SILENT_MODE:
        rprint(Panel(f"""Starting Azure Documenter
Mode: [bold]{args.mode}[/bold]
Run ID: [cyan]{run_timestamp}[/cyan]""", 
                     title="[bold blue]Azure Documenter[/bold blue]", 
                     subtitle="Starting Run", 
                     border_style="blue"))
    logging.info(f"Starting Azure Documenter in {args.mode} mode (Run ID: {run_timestamp}).")

    # --- Authentication ---
    if not SILENT_MODE: rprint("[cyan]Attempting Azure authentication...[/cyan]")
    logging.info("Attempting Azure authentication...")
    try:
        credential = DefaultAzureCredential()
        # Quick test: list tenants to validate credentials early
        tenant_details_result = await fetch_tenant_details(credential)
        tenant_id = tenant_details_result.get("tenant_id", "unknown_tenant")
        error_value = tenant_details_result.get("error")

        # Refined Check: Exit if tenant_id is invalid OR if error_value is truthy (not None, not empty string)
        if not tenant_id or tenant_id == "unknown_tenant" or error_value:
             # Determine the message: Use error_value if it's truthy, otherwise use the generic message.
             error_msg = error_value if error_value else "Could not determine tenant ID or credential validation failed."
             if not SILENT_MODE: rprint(f"[bold red]Credential Error:[/bold red] {error_msg}")
             logging.error(f"Credential Error: {error_msg}")
             sys.exit(1)
        
        # If we reach here, tenant_id is valid and there's no blocking error
        if not SILENT_MODE: rprint(f"[green]Credentials acquired for tenant: {tenant_id}[/green]")
        logging.info(f"Credentials acquired for tenant: {tenant_id}")

        # --- Fetch Tenant-Level Data (Once) ---
        if not SILENT_MODE: rprint("Fetching tenant-level information (Management Groups, SP Summary)...")
        logging.info("Fetching tenant-level information...")
        tenant_data_tasks = {
             "management_groups": fetch_management_groups(credential),
             "tenant_details": asyncio.sleep(0, result=tenant_details_result), # Use already fetched details
             "sp_summary": fetch_service_principal_summary(credential) # Fetch SP summary here
        }
        tenant_results = await asyncio.gather(
            *tenant_data_tasks.values(),
            return_exceptions=True
        )
        
        # Process tenant-level results
        processed_tenant_results = {}
        tenant_fetch_errors = []
        for i, key in enumerate(tenant_data_tasks.keys()):
            result = tenant_results[i]
            if isinstance(result, Exception):
                error_msg = f"Failed to fetch tenant {key}: {result}"
                logging.error(error_msg, exc_info=result)
                tenant_fetch_errors.append(error_msg)
                processed_tenant_results[key] = {"error": error_msg}
            else:
                processed_tenant_results[key] = result
                logging.info(f"Successfully fetched tenant {key}.")
        
        # Make SP summary available outside this block
        tenant_sp_summary = processed_tenant_results.get("sp_summary", {"error": "SP Summary fetch failed or was not attempted."})
        
        if tenant_fetch_errors and not SILENT_MODE:
             rprint("[yellow]Warning: Failed to fetch some tenant-level data:[/yellow]")
             for err in tenant_fetch_errors:
                 rprint(f"  - {err}")
        # --- End Tenant-Level Fetch ---
        
        # --- Get and Select Subscriptions ---
        all_subscriptions = get_subscriptions(credential)
        if args.all_subscriptions:
            selected_subscriptions = all_subscriptions
            if not SILENT_MODE: rprint(f"[yellow]--all-subscriptions flag detected. Processing [bold]{len(selected_subscriptions)}[/bold] subscription(s).[/yellow]")
            logging.info(f"Processing all {len(selected_subscriptions)} subscriptions due to --all-subscriptions flag.")
        else:
            selected_subscriptions = select_subscriptions(all_subscriptions)

        if not selected_subscriptions:
            logging.warning("No subscriptions selected. Exiting.")
            if not SILENT_MODE: rprint("[yellow]No subscriptions selected. Exiting.[/yellow]")
            sys.exit(0)

        # --- Process Selected Subscriptions ---
        if not SILENT_MODE: rprint(f"\nProcessing {len(selected_subscriptions)} selected subscription(s)...\n")
        logging.info(f"Processing {len(selected_subscriptions)} selected subscription(s)...\n")

        all_subscription_data = {}
        tasks = []
        for sub in selected_subscriptions:
            # Pass the fetched tenant_sp_summary to each task
            tasks.append(process_subscription(credential, sub, tenant_sp_summary))

        # Run subscription processing concurrently
        results = await asyncio.gather(*tasks)
        for sub_id, data in results:
            all_subscription_data[sub_id] = data
            
    except Exception as e:
        logging.error(f"Main processing failed: {e}")
        if not SILENT_MODE:
            rprint(f"[bold red]Main processing failed:[/bold red] {e}")
        sys.exit(1)

    # --- Add Management Group Data to the final dict (for saving) ---
    final_audit_data_to_save = { 
         # Add run details for context in the JSON file
         "run_details": {
             "timestamp_utc": datetime.now(timezone.utc).isoformat(),
             "timestamp_local": run_timestamp, 
             "mode": args.mode,
             "version": get_next_version(tenant_id),
             "tenant_id": tenant_id, # Use the determined tenant_id
             "tenant_display_name": processed_tenant_results.get("tenant_details", {}).get("display_name", "Unknown Tenant"), # Use the potentially Graph-fetched name
             "selected_subscription_ids": [sub['id'] for sub in selected_subscriptions],
         },
         "management_groups": processed_tenant_results.get("management_groups", []),
         "subscriptions": all_subscription_data # The main data keyed by sub ID
     }
    # --------------------------------------------------------------

    # --- Save Raw Audit Data (JSON) ---
    raw_data_filepath = save_raw_data(final_audit_data_to_save, "azure_audit_raw_data", run_timestamp)

    # --- Report Generation ---
    if not SILENT_MODE: rprint("[bold blue]Proceeding to report generation...")
    logging.info("Proceeding to report generation...")

    # Generate Diagrams 
    if not SILENT_MODE: rprint("  Generating network diagrams...")
    logging.info("Generating diagrams...")
    # Pass the subscription data dict directly
    generated_diagram_paths = generate_all_diagrams(all_subscription_data, DIAGRAM_DIR, run_timestamp)

    # --- Generate Markdown Report (Audit or Design) ---
    generated_report_path = None 
    if args.mode == "Design":
        if not SILENT_MODE: rprint(f"  Generating [bold]{args.mode}[/bold] document...")
        logging.info("Generating design document...")
        generated_report_path = generate_design_document(
            all_subscription_data, # Pass ONLY the subscription data dict
            OUTPUT_BASE_DIR,
            processed_tenant_results.get("tenant_details", {}).get("display_name", "Unknown Tenant"),
            processed_tenant_results.get("tenant_details", {}).get("default_domain", "unknown.onmicrosoft.com"),
            get_next_version(tenant_id),
            management_group_data=processed_tenant_results.get("management_groups", []), # Pass MG data separately
            diagram_paths=generated_diagram_paths,
            timestamp_str=run_timestamp,
            silent_mode=SILENT_MODE
        )
    else: # Default to Audit mode
        if not SILENT_MODE: rprint(f"  Generating [bold]{args.mode}[/bold] report...")
        logging.info("Generating audit report...")
        # Pass the FINAL combined data structure
        generated_report_path = generate_markdown_report(
            final_audit_data_to_save, # Use the dict with MG data included
            OUTPUT_BASE_DIR,
            processed_tenant_results.get("tenant_details", {}).get("display_name", "Unknown Tenant"), 
            processed_tenant_results.get("tenant_details", {}).get("default_domain", "unknown.onmicrosoft.com"), 
            get_next_version(tenant_id), 
            diagram_paths=generated_diagram_paths,
            timestamp_str=run_timestamp,
            silent_mode=SILENT_MODE
        )
    # ----------------------------------------------------

    # --- LLM Enhancement (Disabled by default now) ---
    llm_enhanced_report_path = None
    # Keep the code structure but effectively disable unless config is explicitly set
    # if generated_report_path and config.LLM_PROVIDER != "none":
    #    # ... LLM enhancement code ...
    #    final_report_path = llm_enhanced_report_path or generated_report_path
    # else:
    #     final_report_path = generated_report_path 
    final_report_path = generated_report_path # Use the generated path directly
    # ---------------------------------------------------

    # --- Generate HTML Report ---
    html_report_path = None
    if final_report_path:
        if not SILENT_MODE: rprint("  Converting report to HTML...")
        logging.info("Converting report to HTML...")
        html_filename_prefix = f"azure_{args.mode.lower()}_report"
        html_report_path = export_markdown_to_html(
            final_report_path,
            REPORT_DIR,
            tenant_display_name=processed_tenant_results.get("tenant_details", {}).get("display_name", "Unknown Tenant"), 
            tenant_default_domain=processed_tenant_results.get("tenant_details", {}).get("default_domain", "unknown.onmicrosoft.com"), 
            document_version=get_next_version(tenant_id), 
            timestamp_str=run_timestamp, 
            silent_mode=SILENT_MODE
        )

        if not SILENT_MODE:
            rprint(f"\n[bold green]{args.mode} Documentation Generation Complete:[/bold green]")

            if raw_data_filepath: rprint(f"  - Raw Data JSON: [cyan]{raw_data_filepath}[/cyan]")
            if final_report_path: rprint(f"  - Markdown Report: [cyan]{final_report_path}[/cyan]")
            # Diagram output logging needs adjustment based on generate_all_diagrams structure
            if generated_diagram_paths:
                 rprint("  - Diagrams: Check output in [cyan]{DIAGRAM_DIR}[/cyan]") # Simplified log
            if html_report_path: rprint(f"  - HTML Report: [cyan]{html_report_path}[/cyan]")

        logging.info(f"Documentation generated. Raw: {raw_data_filepath}, Report: {final_report_path}, HTML: {html_report_path}")

        # --- Save Version AFTER successful report generation ---
        save_version(tenant_id, get_next_version(tenant_id))

    else:
        if not SILENT_MODE: rprint("[red]Report generation failed or skipped. Skipping HTML conversion and version save.[/red]")
        logging.error("Markdown report generation failed or skipped. Not saving version.")

    # --- Finalization ---
    if not SILENT_MODE:
        rprint(Panel(f"""Azure Documenter run finished.\nRun ID: [cyan]{run_timestamp}[/cyan]""", 
                     title=" [bold green]Run Complete[/bold green] ", 
                     border_style="green"))
    logging.info(f"Azure Documenter run finished (Run ID: {run_timestamp}).")

if __name__ == "__main__":
    # Run the async main function
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main()) 