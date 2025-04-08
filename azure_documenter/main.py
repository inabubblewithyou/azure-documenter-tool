import argparse
import logging
import os
import json # For saving raw data
import sys # For explicit stdout handler
from datetime import datetime, timezone # Add timezone import
import time  # For local timezone handling
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient

# Import fetchers
from fetchers.resources import fetch_resources
from fetchers.network import fetch_networking_details
from fetchers.security import fetch_security_details
from fetchers.costs import fetch_cost_details
from fetchers.governance import fetch_governance_details

# Import generators
from generators.markdown_writer import generate_markdown_report
from generators.diagram_generator import generate_all_diagrams
from generators.html_exporter import export_markdown_to_html
from generators.llm_writer import enhance_report_with_llm # Import LLM writer

# Import Config
import config # To check LLM provider status

# Import Delta Modules
from delta_analyzer import analyze_delta, load_audit_data
from generators.delta_report_writer import generate_delta_report

# Configure logging - reduce verbosity
# Create console handler with a higher log level
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
# Create formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)

# Get the root logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)
# Clear any existing handlers to avoid duplication
for handler in logger.handlers[:]:
    logger.removeHandler(handler)
# Add handlers to logger
logger.addHandler(console_handler)

# Suppress verbose Azure SDK logging
for azure_logger in ['azure', 'azure.core', 'azure.identity', 'msrest', 'msal']:
    logging.getLogger(azure_logger).setLevel(logging.ERROR)

# Define output directory relative to the script location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_BASE_DIR = os.path.join(SCRIPT_DIR, "outputs")
DATA_DIR = os.path.join(OUTPUT_BASE_DIR, "data")
REPORT_DIR = os.path.join(OUTPUT_BASE_DIR, "reports") # For consistency
DIAGRAM_DIR = os.path.join(OUTPUT_BASE_DIR, "diagrams")

def get_formatted_timestamp():
    """Returns a timestamp string in the local timezone (respecting DST)"""
    # Get current time in the local timezone (including DST if applicable)
    local_time = datetime.now()
    return local_time.strftime("%Y%m%d_%H%M%S")

def get_subscriptions(credential):
    """Lists all accessible Azure subscriptions."""
    try:
        subscription_client = SubscriptionClient(credential)
        subscriptions = list(subscription_client.subscriptions.list())
        print(f"Found {len(subscriptions)} subscriptions.")
        logging.info(f"Found {len(subscriptions)} subscriptions.")
        return [{ "id": sub.subscription_id, "display_name": sub.display_name } for sub in subscriptions]
    except Exception as e:
        print(f"Failed to list subscriptions: {e}")
        logging.error(f"Failed to list subscriptions: {e}")
        return []

def select_subscriptions(subscriptions):
    """Interactive menu to select which subscriptions to audit."""
    if not subscriptions:
        print("No subscriptions found. Cannot continue.")
        return []
        
    print("\n=== Subscription Selection ===")
    print("Please select which subscriptions to audit:")
    print(" 0: All subscriptions")
    
    for i, sub in enumerate(subscriptions, 1):
        print(f" {i}: {sub['display_name']} ({sub['id']})")
    
    selected_indices = []
    valid_selection = False
    
    while not valid_selection:
        try:
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
        print(f"Successfully saved raw data to {filepath}")
        logging.info(f"Successfully saved raw data to {filepath}")
        return filepath
    except Exception as e:
        print(f"Failed to save raw data to {filepath}: {e}")
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
    
    args = parser.parse_args()
    
    # --- Handle Delta Comparison Mode ---
    if args.compare:
        timestamp1, timestamp2 = args.compare
        print(f"Running in Delta Comparison mode: Comparing {timestamp1} vs {timestamp2}")
        logging.info(f"Running in Delta Comparison mode: Comparing {timestamp1} vs {timestamp2}")

        # Construct file paths
        file1 = os.path.join(DATA_DIR, f"azure_audit_raw_data_{timestamp1}.json")
        file2 = os.path.join(DATA_DIR, f"azure_audit_raw_data_{timestamp2}.json")

        if not os.path.exists(file1):
            print(f"Comparison file not found: {file1}")
            logging.error(f"Comparison file not found: {file1}")
            return
        if not os.path.exists(file2):
            print(f"Comparison file not found: {file2}")
            logging.error(f"Comparison file not found: {file2}")
            return

        print(f"Loading data from {file1} and {file2}...")
        logging.info(f"Loading data from {file1} and {file2}...")
        data1 = load_audit_data(file1)
        data2 = load_audit_data(file2)
        
        if data1 and data2:
            print("Analyzing differences between the two audit files...")
            logging.info("Analyzing differences between the two audit files...")
            delta = analyze_delta(data1, data2)
            
            print("Generating delta report...")
            logging.info("Generating delta report...")
            delta_report_path = generate_delta_report(delta, timestamp1, timestamp2, OUTPUT_BASE_DIR)
            
            if delta_report_path:
                # Generate HTML version of the delta report
                print("Converting delta report to HTML...")
                logging.info("Converting delta report to HTML...")
                html_report_path = export_markdown_to_html(delta_report_path, REPORT_DIR, f"delta_{timestamp1}_vs_{timestamp2}")
                
                # Log paths to both reports for user convenience
                if html_report_path:
                    print(f"Delta reports generated:")
                    print(f"  - Markdown: {delta_report_path}")
                    print(f"  - HTML: {html_report_path}")
                    logging.info(f"Delta reports generated:")
                    logging.info(f"  - Markdown: {delta_report_path}")
                    logging.info(f"  - HTML: {html_report_path}")
                else:
                    print(f"Delta report generated: {delta_report_path}")
                    logging.info(f"Delta report generated: {delta_report_path}")
            else:
                print("Failed to generate delta report.")
                logging.error("Failed to generate delta report.")
        else:
            print("Failed to load data for comparison.")
            logging.error("Failed to load data for comparison.")

        print("Azure Documenter Delta Comparison finished.")
        logging.info("Azure Documenter Delta Comparison finished.")
        return # Exit after comparison
        
    # --- Normal Audit Mode (if --compare is not used) ---
    # Generate timestamp for this run (using local timezone)
    run_timestamp = get_formatted_timestamp()
    print(f"=== Starting Azure Documenter in {args.mode} mode ===")
    print(f"Run ID / Timestamp: {run_timestamp}")
    print(f"This timestamp can be used later with --compare to identify changes")
    logging.info(f"Starting Azure Documenter in {args.mode} mode (Run ID: {run_timestamp}).")

    # --- Authentication ---
    try:
        print("Authenticating to Azure...")
        credential = DefaultAzureCredential()
        credential.get_token("https://management.azure.com/.default")
        print("Successfully authenticated using DefaultAzureCredential.")
        logging.info("Successfully authenticated using DefaultAzureCredential.")
    except Exception as e:
        print(f"Authentication failed: {e}")
        print("Please ensure you are logged in via Azure CLI ('az login') or have environment variables set (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET).")
        logging.error(f"Authentication failed: {e}")
        logging.error("Please ensure you are logged in via Azure CLI ('az login') or have environment variables set (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET).")
        return

    # --- List Subscriptions ---
    print("Listing accessible subscriptions...")
    all_subscriptions = get_subscriptions(credential)
    if not all_subscriptions:
        print("No accessible subscriptions found or error occurred. Exiting.")
        logging.warning("No accessible subscriptions found or error occurred. Exiting.")
        return

    # --- Subscription Selection (if not using --all-subscriptions flag) ---
    if args.all_subscriptions:
        subscriptions = all_subscriptions
        print("Using all available subscriptions due to --all-subscriptions flag.")
    else:
        subscriptions = select_subscriptions(all_subscriptions)
        if not subscriptions:
            print("No subscriptions selected. Exiting.")
            return

    subscription_ids = [sub["id"] for sub in subscriptions]
    print(f"Processing {len(subscription_ids)} subscriptions.")
    # Only print the first 3 subscription IDs if many
    if len(subscription_ids) > 3:
        print(f"Processing subscriptions: {', '.join(subscription_ids[:3])}... and {len(subscription_ids)-3} more")
    else:
        print(f"Processing subscriptions: {', '.join(subscription_ids)}")
    logging.info(f"Processing subscriptions: {', '.join(subscription_ids)}")

    # --- Data Collection ---
    all_subscription_data = {}
    print(f"\n=== Starting Data Collection ===")
    total_subs = len(subscriptions)
    for idx, sub_info in enumerate(subscriptions, 1):
        sub_id = sub_info["id"]
        sub_display_name = sub_info["display_name"]
        print(f"\nCollecting data for subscription ({idx}/{total_subs}): {sub_display_name}")
        logging.info(f"--- Starting data collection for subscription: {sub_display_name} ({sub_id}) ---")

        subscription_data = {
            "subscription_info": sub_info,
            "resources": [],
            "networking": {},
            "security": {},
            "costs": {},
            "governance": {}
        }

        try:
            # Fetch data using imported functions - with progress indicators
            print("  • Resources...", end="", flush=True)
            subscription_data["resources"] = fetch_resources(credential, sub_id)
            print(f" ✓ ({len(subscription_data['resources'])} found)")
            
            print("  • Networking...", end="", flush=True)
            subscription_data["networking"] = fetch_networking_details(credential, sub_id)
            vnet_count = len(subscription_data["networking"].get("vnets", []))
            print(f" ✓ ({vnet_count} VNets)")
            
            print("  • Security...", end="", flush=True)
            subscription_data["security"] = fetch_security_details(credential, sub_id)
            print(" ✓")
            
            print("  • Costs...", end="", flush=True)
            subscription_data["costs"] = fetch_cost_details(credential, sub_id)
            print(" ✓")
            
            print("  • Governance...", end="", flush=True)
            subscription_data["governance"] = fetch_governance_details(credential, sub_id)
            policy_count = len(subscription_data["governance"].get("policy_states", []))
            print(f" ✓ ({policy_count} non-compliant policies)")

            all_subscription_data[sub_id] = subscription_data
            print(f"Completed data collection for subscription: {sub_display_name}")
            logging.info(f"--- Finished data collection for subscription: {sub_display_name} ({sub_id}) ---")

        except Exception as e:
            print(f"!!! Error processing subscription {sub_id}: {e}")
            logging.error(f"!!! Unexpected error processing subscription {sub_id}: {e}. Skipping to next subscription. !!!")
            all_subscription_data[sub_id] = {"subscription_info": sub_info, "error": str(e)}

    print("\nFinished collecting data for all subscriptions.")
    logging.info("Finished collecting data for all subscriptions.")

    # --- Save Raw Data (with timestamp) ---
    print("\n=== Generating Reports ===")
    print("Saving raw audit data...")
    logging.info("Saving raw audit data...")
    raw_data_filepath = save_raw_data(all_subscription_data, "azure_audit_raw_data", run_timestamp)
    if not raw_data_filepath:
        print("Failed to save raw data. Report generation might be incomplete.")
        logging.error("Failed to save raw data. Report generation might be incomplete.")

    # --- Report Generation (pass timestamp) ---
    print("Proceeding to report generation...")
    logging.info("Proceeding to report generation...")

    # Generate Diagrams (pass timestamp)
    print("Generating network diagrams...")
    logging.info("Generating diagrams...")
    generated_diagram_paths = generate_all_diagrams(all_subscription_data, DIAGRAM_DIR, run_timestamp)

    # Generate Markdown Report (pass timestamp)
    print("Generating Markdown report...")
    logging.info("Generating Markdown report...")
    markdown_report_filepath = generate_markdown_report(all_subscription_data, OUTPUT_BASE_DIR, generated_diagram_paths, run_timestamp)

    if markdown_report_filepath:
        # Generate HTML Report (from timestamped Markdown)
        print("Generating HTML report...")
        logging.info("Generating HTML report...")
        html_report_filepath = export_markdown_to_html(markdown_report_filepath, REPORT_DIR, run_timestamp)

        # --- Optional LLM Enhancement (Design Mode) (enhance timestamped Markdown) ---
        if args.mode == "Design" and config.LLM_PROVIDER:
            print(f"Enhancing report with LLM summaries...")
            logging.info(f"Design mode selected and {config.LLM_PROVIDER} configured. Enhancing report '{os.path.basename(markdown_report_filepath)}' with LLM summaries...")
            enhancement_success = enhance_report_with_llm(all_subscription_data, markdown_report_filepath)
            if enhancement_success:
                 print(f"Re-generating HTML report to include LLM enhancements...")
                 logging.info(f"Re-generating HTML report '{os.path.basename(html_report_filepath)}' to include LLM enhancements...")
                 export_markdown_to_html(markdown_report_filepath, REPORT_DIR, run_timestamp)
        elif args.mode == "Design":
            print("Design mode selected, but LLM provider is not configured. Skipping LLM enhancement.")
            logging.warning("Design mode selected, but LLM provider is not configured. Skipping LLM enhancement.")
        
        # Show report paths to user
        print("\n=== Azure Documenter Completed Successfully ===")
        print(f"Generated Reports:")
        print(f"  - Markdown: {markdown_report_filepath}")
        if html_report_filepath:
            print(f"  - HTML: {html_report_filepath}")
        print(f"  - Raw Data: {raw_data_filepath}")
        print(f"\nThis audit run's timestamp: {run_timestamp}")
        print(f"To compare with future audits, use:")
        print(f"  python azure_documenter/main.py --compare {run_timestamp} FUTURE_TIMESTAMP")
    else:
        print("Markdown report generation failed. Skipping HTML and LLM enhancement.")
        logging.error("Markdown report generation failed. Skipping HTML and LLM enhancement.")

    logging.info(f"Azure Documenter run finished (Run ID: {run_timestamp}).")

if __name__ == "__main__":
    main() 