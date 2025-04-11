# Filename: count_resources.py
import json
from collections import Counter
import sys
import os

def analyze_azure_resources(file_path):
    """Reads an Azure audit JSON file and counts resource types."""
    if not os.path.exists(file_path):
        print(f"Error: File not found at {os.path.abspath(file_path)}", file=sys.stderr)
        return None
        
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Handle potential BOM (Byte Order Mark) if present
            content = f.read()
            if content.startswith('\ufeff'):
                content = content[1:]
            data = json.loads(content)

        resource_counts = Counter()
        total_resources = 0
        missing_type_count = 0

        # The top level keys are subscription IDs
        for sub_id, sub_data in data.items():
            # Ensure sub_data is a dictionary and has the 'resources' key which is a list
            if isinstance(sub_data, dict) and "resources" in sub_data and isinstance(sub_data["resources"], list):
                for resource in sub_data["resources"]:
                    # Ensure resource is a dictionary and has the 'type' key
                    if isinstance(resource, dict) and "type" in resource and resource["type"]:
                        resource_counts[resource["type"]] += 1
                    else:
                        # Count resources where the 'type' field might be missing or empty
                        missing_type_count += 1 
                    total_resources += 1
            elif isinstance(sub_data, dict):
                # Subscription data exists but might be missing the 'resources' list
                # This could happen if a subscription has no resources or the fetcher failed for resources
                pass # You could add logging here if needed
            else:
                # Handle unexpected structure under a subscription ID
                print(f"Warning: Unexpected data structure found for subscription ID '{sub_id}'. Expected a dictionary.", file=sys.stderr)


        print(f"--- Analysis of {file_path} ---")
        print(f"Total resources processed (from 'resources' lists): {total_resources}")
        if missing_type_count > 0:
            print(f"Warning: {missing_type_count} resources were missing the 'type' field or had an empty type.")

        print("\nResource type counts (most common first):")
        if not resource_counts:
            print("No valid resource types found in the 'resources' lists.")
        else:
            # Sort by count descending
            for resource_type, count in resource_counts.most_common():
                print(f"- {resource_type}: {count}")

        return resource_counts

    except FileNotFoundError:
        # This case is handled by the initial os.path.exists check, but kept for robustness
        print(f"Error: File not found at {file_path}", file=sys.stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON in {file_path}: {e}", file=sys.stderr)
        # You might want to print the line number where the error occurred if possible
        # print(f"Error on line {e.lineno}, column {e.colno}: {e.msg}") 
        return None
    except Exception as e:
        print(f"An unexpected error occurred while processing {file_path}: {e}", file=sys.stderr)
        return None

if __name__ == "__main__":
    # Assumes the script is run from the workspace root C:/dev/azure-documenter-tool/
    file_to_analyze = "azure_documenter/outputs/data/azure_audit_raw_data_20250409_225736.json"
    
    # Verify the script's current working directory if needed
    # print(f"Current working directory: {os.getcwd()}")
    
    analyze_azure_resources(file_to_analyze)