import os
import logging
import pandas as pd # For CSV export
import datetime # Add datetime import for timezone-aware time

# Define output directories relative to the main script or a base path
REPORT_DIR = "reports"
DIAGRAM_DIR = "diagrams"
DATA_DIR = "data" # Reuse from main?

def generate_markdown_report(all_data, base_output_dir, diagram_paths={}, timestamp_str=""):
    """Generates a timestamped Markdown report from the collected Azure data.

    Args:
        all_data (dict): The aggregated data from all fetchers.
        base_output_dir (str): The base directory for outputs.
        diagram_paths (dict): A dictionary mapping subscription IDs to their generated diagram paths.
        timestamp_str (str): Timestamp string for filenames.

    Returns:
        str: The full path to the generated markdown file, or None if failed.
    """
    report_path = os.path.join(base_output_dir, REPORT_DIR)
    csv_path = os.path.join(base_output_dir, DATA_DIR)
    os.makedirs(report_path, exist_ok=True)
    os.makedirs(csv_path, exist_ok=True)

    # Prepare timestamp suffix for filenames
    time_suffix = f"_{timestamp_str}" if timestamp_str else ""

    md_content = []
    all_resources_list = [] # For CSV export

    # Try to determine tenant name from subscription data
    tenant_name = "Azure Tenant"
    for sub_id, sub_data in all_data.items():
        if "subscription_info" in sub_data and "tenant_domain" in sub_data["subscription_info"]:
            tenant_name = sub_data["subscription_info"]["tenant_domain"]
            break

    md_content.append(f"# Azure Infrastructure Audit Report for {tenant_name} ({timestamp_str})")
    md_content.append(f"Generated on: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    md_content.append(f"Run ID: `{timestamp_str}`")
    md_content.append("## Tenant Summary")
    md_content.append(f"- **Total Subscriptions Found:** {len(all_data)}")
    # Add more tenant-level summaries later (e.g., total cost, total resources)
    
    # Add a dedicated security section at the tenant level for critical information
    md_content.append("\n## Tenant-Wide Security Information")
    
    # --- List Global Admins and Privileged Accounts ---
    md_content.append("\n### Global Administrators and Privileged Accounts")
    
    # Collect all privileged roles from each subscription
    all_privileged_roles = []
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        security_data = data.get("security", {})
        privileged_users = security_data.get("privileged_accounts", [])
        if privileged_users:
            all_privileged_roles.extend(privileged_users)
    
    # Deduplicate by object_id to avoid showing the same user multiple times
    unique_privileged = {}
    for user in all_privileged_roles:
        object_id = user.get("object_id", "unknown")
        # Merge roles if the same user appears in multiple subscriptions
        if object_id in unique_privileged:
            # Add new roles not already in the list
            existing_roles = unique_privileged[object_id].get("role_names", [])
            new_roles = user.get("role_names", [])
            unique_privileged[object_id]["role_names"] = list(set(existing_roles + new_roles))
        else:
            unique_privileged[object_id] = user
    
    if unique_privileged:
        md_content.append("\n| Display Name | Principal Type | Role Names |")
        md_content.append("|---|---|---|")
        for user in unique_privileged.values():
            display_name = user.get("display_name", "Unknown")
            principal_type = user.get("principal_type", "Unknown")
            role_names = ", ".join(user.get("role_names", ["Unknown"]))
            md_content.append(f"| {display_name} | {principal_type} | {role_names} |")
    else:
        md_content.append("\n_No Global Administrators or Privileged Accounts found._")
    
    # --- List Policy Non-Compliance ---
    md_content.append("\n### Non-Compliant Policy States")
    
    # Collect all policy violations from each subscription
    all_policy_states = []
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        governance_data = data.get("governance", {})
        policy_states = governance_data.get("policy_states", [])
        if policy_states:
            # Add subscription context to each policy state
            for policy in policy_states:
                # Ensure policy is a dictionary
                if not isinstance(policy, dict):
                    logging.warning(f"Skipping non-dictionary policy state in subscription {sub_id}")
                    continue
                    
                policy["subscription_id"] = sub_id
                policy["subscription_name"] = data.get("subscription_info", {}).get("display_name", sub_id)
            all_policy_states.extend(policy_states)
    
    if all_policy_states:
        md_content.append("\n| Policy Name | Subscription | Resource Type | Resource | Compliance State |")
        md_content.append("|---|---|---|---|---|")
        try:
            for policy in sorted(all_policy_states, key=lambda x: (x.get("subscription_name", ""), x.get("policy_definition_name", ""))):
                policy_name = policy.get("policy_definition_name", "Unknown")
                sub_name = policy.get("subscription_name", "Unknown")
                resource_type = policy.get("resource_type", "Unknown")
                resource_name = policy.get("resource_name", "Unknown")
                compliance_state = policy.get("compliance_state", "Unknown")
                md_content.append(f"| {policy_name} | {sub_name} | {resource_type} | {resource_name} | {compliance_state} |")
        except Exception as e:
            logging.error(f"Error processing policy states: {e}")
            md_content.append("\n_Error processing policy states. See logs for details._")
    else:
        md_content.append("\n_No Non-Compliant Policy States found._")
    
    # --- List Security Advisories ---
    md_content.append("\n### Security Advisories")
    
    # Collect all security advisories from each subscription
    all_advisories = []
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        governance_data = data.get("governance", {})
        advisories = governance_data.get("advisor_recommendations", [])
        if advisories:
            # Add subscription context to each advisory
            for advisory in advisories:
                # Ensure advisory is a dictionary
                if not isinstance(advisory, dict):
                    logging.warning(f"Skipping non-dictionary advisory in subscription {sub_id}")
                    continue
                    
                advisory["subscription_id"] = sub_id
                advisory["subscription_name"] = data.get("subscription_info", {}).get("display_name", sub_id)
            all_advisories.extend(advisories)
    
    # Impact value mapping for sorting (handle string values like 'High', 'Medium', 'Low')
    def get_impact_value(advisory):
        impact = advisory.get("impact", "Low")
        # Handle both numeric and string impact values
        if isinstance(impact, (int, float)) or (isinstance(impact, str) and impact.isdigit()):
            try:
                return -int(impact)  # Negative to sort highest first
            except (ValueError, TypeError):
                pass  # Fall through to string handling if conversion fails
        
        # Map string impact values to numeric values for sorting
        if isinstance(impact, str):
            impact_map = {
                "high": -3,
                "medium": -2,
                "low": -1,
                "none": 0
            }
            # Default to lowest severity if unknown
            return impact_map.get(impact.lower(), 0)
        return 0  # Default for any other type
    
    if all_advisories:
        md_content.append("\n| Category | Impact | Title | Subscription | Resource |")
        md_content.append("|---|---|---|---|---|")
        try:
            # Sort with the new sorting function
            for advisory in sorted(all_advisories, key=lambda x: (x.get("category", ""), get_impact_value(x))):
                category = advisory.get("category", "Unknown")
                impact = advisory.get("impact", "Unknown")
                
                # Handle both string and dictionary formats for short_description
                short_description = advisory.get("short_description", "Unknown")
                if isinstance(short_description, dict):
                    # If it's a dictionary, try to get the solution
                    title = short_description.get("solution", "Unknown")
                else:
                    # If it's a string, use it directly
                    title = short_description
                    
                sub_name = advisory.get("subscription_name", "Unknown")
                resource = advisory.get("resource_id", "Unknown").split('/')[-1] if advisory.get("resource_id") else "Unknown"
                
                # Ensure all fields are strings before adding to markdown
                md_content.append(f"| {str(category)} | {str(impact)} | {str(title)} | {str(sub_name)} | {str(resource)} |")
        except Exception as e:
            logging.error(f"Error processing security advisories: {e}")
            md_content.append("\n_Error processing security advisories. See logs for details._")
    else:
        md_content.append("\n_No Security Advisories found._")

    # Add tenant-wide network diagram if available
    tenant_diagrams = diagram_paths.get("tenant_diagrams", {})
    tenant_network_diagram = tenant_diagrams.get("network_topology")
    if tenant_network_diagram:
        # Try to determine tenant name
        tenant_name = "Azure Tenant"
        for sub_id, sub_data in all_data.items():
            if "subscription_info" in sub_data and "tenant_domain" in sub_data["subscription_info"]:
                tenant_name = sub_data["subscription_info"]["tenant_domain"]
                break
                
        relative_diagram_path = os.path.join("..", tenant_network_diagram).replace("\\", "/")
        md_content.append("\n### Tenant-Wide Network Topology")
        md_content.append(f"![{tenant_name} - Network Topology]({relative_diagram_path})")
        md_content.append("\n_This diagram shows all Virtual Networks across subscriptions and their peering relationships._\n")

    for sub_id, data in all_data.items():
        if "error" in data:
            logging.warning(f"Skipping report section for subscription {sub_id} due to previous error: {data['error']}")
            md_content.append(f"\n---\n## Subscription: {sub_id} (Error)")
            md_content.append(f"**Error during data collection:** `{data['error']}`")
            continue

        sub_info = data.get("subscription_info", {})
        sub_display_name = sub_info.get("display_name", sub_id)
        logging.info(f"Generating Markdown section for: {sub_display_name}")

        md_content.append(f"\n---\n## Subscription: {sub_display_name} (`{sub_id}`)")

        # --- Resources Section ---
        resources = data.get("resources", [])
        md_content.append("\n### Resource Inventory")
        # Summary list first
        md_content.append(f"- **Total Resources:** {len(resources)}")
        # Now, the table (outside the list item)
        if resources:
            md_content.append("\n| Name | Type | Location | Resource Group | Tags |") # Add newline before table
            md_content.append("|---|---|---|---|---|")
            for res in sorted(resources, key=lambda x: (x['resource_group'], x['name'])):
                tags_str = ", ".join([f"`{k}={v}`" for k, v in res.get("tags", {}).items()]) if res.get("tags") else ""
                md_content.append(f"| {res['name']} | `{res['type']}` | {res['location']} | {res['resource_group']} | {tags_str} |")
                # Add to CSV list
                res_copy = res.copy()
                res_copy['subscription_id'] = sub_id
                res_copy['subscription_name'] = sub_display_name
                res_copy['tags_str'] = tags_str # Add flattened tags for easier CSV
                all_resources_list.append(res_copy)
        else:
            md_content.append("_No resources found or unable to fetch._")

        # --- Networking Section ---
        networking = data.get("networking", {})
        vnets = networking.get("vnets", [])
        subnets = networking.get("subnets", [])
        peerings = networking.get("peerings", [])
        nsgs = networking.get("nsgs", [])
        md_content.append("\n### Networking")
        # Networking summary list
        md_content.append(f"- **VNets:** {len(vnets)}")
        md_content.append(f"- **Subnets:** {len(subnets)}")
        md_content.append(f"- **VNet Peerings:** {len(peerings)}")
        md_content.append(f"- **NSGs:** {len(nsgs)}")

        # --- Insert Subscription-specific Diagram ---
        subscription_diagrams = diagram_paths.get("subscription_diagrams", {})
        sub_diagrams = subscription_diagrams.get(sub_id, {})
        vnet_diagram_path = sub_diagrams.get('vnet_topology')
        if vnet_diagram_path:
            # Ensure the path is relative to the report file for correct linking
            relative_diagram_path = os.path.join("..", vnet_diagram_path).replace("\\", "/") # Path relative to reports/ dir
            md_content.append(f"\n**VNet Topology Diagram**\n")
            md_content.append(f"![VNet Topology for {sub_display_name} ({timestamp_str})]({relative_diagram_path})")
            md_content.append("\n") # Add space after diagram
        else:
            md_content.append("\n_[Network Diagram Not Generated]_")

        # Networking Tables (ensure they are outside the summary list)
        # VNet Table
        if vnets:
            md_content.append("\n**Virtual Networks (VNets)**")
            md_content.append("\n| Name | Location | Resource Group | Address Space | Tags |") # Ensure newline before header
            md_content.append("|---|---|---|---|---|")
            for vnet in sorted(vnets, key=lambda x: x['name']):
                tags_str = ", ".join([f"`{k}={v}`" for k, v in vnet.get("tags", {}).items()]) if vnet.get("tags") else ""
                address_space_str = ", ".join(vnet.get("address_space", []))
                md_content.append(f"| {vnet['name']} | {vnet['location']} | {vnet['resource_group']} | `{address_space_str}` | {tags_str} |")

        # Subnet Table
        if subnets:
            md_content.append("\n**Subnets**")
            md_content.append("\n| Name | VNet Name | Resource Group | Address Prefix | NSG Attached | Route Table Attached |") # Ensure newline before header
            md_content.append("|---|---|---|---|---|---|")
            # Create a map for quick NSG/RouteTable name lookup if needed (complex here)
            for subnet in sorted(subnets, key=lambda x: (x['vnet_name'], x['name'])):
                nsg_name = f"`{subnet['nsg_id'].split('/')[-1]}`" if subnet.get("nsg_id") else "_None_"
                rt_name = f"`{subnet['route_table_id'].split('/')[-1]}`" if subnet.get("route_table_id") else "_None_"
                md_content.append(f"| {subnet['name']} | {subnet['vnet_name']} | {subnet['resource_group']} | `{subnet['address_prefix']}` | {nsg_name} | {rt_name} |")

        # VNet Peering Table
        if peerings:
            md_content.append("\n**VNet Peerings**")
            md_content.append("\n| Name | Local VNet | Remote VNet ID | State | Resource Group |") # Ensure newline before header
            md_content.append("|---|---|---|---|---|")
            for peering in sorted(peerings, key=lambda x: x['name']):
                # Shorten remote VNet ID for display if possible
                remote_vnet_display = peering.get("remote_vnet_id", "_N/A_")
                if remote_vnet_display != "_N/A_":
                    try:
                       remote_vnet_display = f".../{remote_vnet_display.split('/')[-3]}/.../{remote_vnet_display.split('/')[-1]}" # Show Sub/VNet name part
                    except:
                        pass # Keep full ID if parsing fails
                md_content.append(f"| {peering['name']} | `{peering['local_vnet_id'].split('/')[-1]}` | `{remote_vnet_display}` | {peering['peering_state']} | {peering['resource_group']} |")

        # NSG Table
        if nsgs:
            md_content.append("\n**Network Security Groups (NSGs)**")
            md_content.append("\n| Name | Location | Resource Group | Rules Count | Default Rules Count | Tags |") # Ensure newline before header
            md_content.append("|---|---|---|---|---|---|")
            for nsg in sorted(nsgs, key=lambda x: x['name']):
                tags_str = ", ".join([f"`{k}={v}`" for k, v in nsg.get("tags", {}).items()]) if nsg.get("tags") else ""
                md_content.append(f"| {nsg['name']} | {nsg['location']} | {nsg['resource_group']} | {nsg.get('rules_count', 0)} | {nsg.get('default_rules_count', 0)} | {tags_str} |")

        # --- Security Section ---
        security = data.get("security", {})
        rbac = security.get("role_assignments", [])
        score = security.get("security_score")
        md_content.append("\n### Security Posture")
        # Security summary list
        md_content.append(f"- **Role Assignments (RBAC):** {len(rbac)}")
        if score:
            # Format percentage nicely
            score_perc = score.get('percentage', 0)
            md_content.append(f"- **Security Score:** {score['current']} / {score['max']} ({score_perc:.1%})")
        else:
            md_content.append("- **Security Score:** _Not available or unable to fetch._")
        # Add RBAC details table later

        # --- Cost Section ---
        costs = data.get("costs", {})
        mtd_cost = costs.get("mtd_actual_cost")
        currency = costs.get("currency", "")
        md_content.append("\n### Costs (Month-to-Date)")
        # Cost summary list
        if mtd_cost is not None:
             md_content.append(f"- **Actual Cost (MTD):** {mtd_cost:.2f} {currency}")
        else:
             md_content.append("- **Actual Cost (MTD):** _Not available or unable to fetch._")

        # --- Governance Section ---
        governance = data.get("governance", {})
        policies = governance.get("policy_states", [])
        recommendations = governance.get("advisor_recommendations", [])
        md_content.append("\n### Governance")
        # Governance summary list
        md_content.append(f"- **Non-Compliant Policy States:** {len(policies)}")
        md_content.append(f"- **Advisor Recommendations:** {len(recommendations)}")
        # Add tables/details for policies and recommendations later

    # --- Save Markdown Report ---
    report_filename = f"azure_audit_report{time_suffix}.md"
    report_filepath = os.path.join(report_path, report_filename)
    markdown_saved = False
    try:
        with open(report_filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(md_content))
        logging.info(f"Successfully generated Markdown report: {report_filepath}")
        markdown_saved = True
    except Exception as e:
        logging.error(f"Failed to write Markdown report: {e}")

    # --- Save Resources CSV ---
    csv_filepath = None
    if all_resources_list:
        csv_filename = f"azure_resource_inventory{time_suffix}.csv"
        csv_filepath = os.path.join(csv_path, csv_filename)
        try:
            df = pd.DataFrame(all_resources_list)
            # Select and order columns for CSV clarity
            cols = ['subscription_id', 'subscription_name', 'resource_group', 'name', 'type', 'location', 'id', 'tags_str']
            # Add other columns if they exist, handle potential missing columns
            existing_cols = [c for c in cols if c in df.columns]
            df = df[existing_cols]
            df.to_csv(csv_filepath, index=False, encoding='utf-8')
            logging.info(f"Successfully generated Resource Inventory CSV: {csv_filepath}")
        except Exception as e:
            logging.error(f"Failed to write Resource Inventory CSV: {e}")
            csv_filepath = None

    # Return the Markdown report path if successful
    return report_filepath if markdown_saved else None 