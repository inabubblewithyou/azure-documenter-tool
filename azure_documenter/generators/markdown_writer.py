import os
import logging
import pandas as pd # For CSV export
import datetime # Add datetime import for timezone-aware time
import time # For local timezone name

# Define output directories relative to the main script or a base path
REPORT_DIR = "reports"
DIAGRAM_DIR = "diagrams"
DATA_DIR = "data" # Reuse from main?

# Global flag for silent mode
SILENT_MODE = False

def generate_markdown_report(all_data, base_output_dir, tenant_display_name, tenant_default_domain, document_version, diagram_paths={}, timestamp_str="", silent_mode=False):
    """Generates a timestamped Azure Audit Report in Markdown format.

    Args:
        all_data (dict): The aggregated data from all fetchers.
        base_output_dir (str): The base directory for outputs.
        tenant_display_name (str): The fetched display name of the tenant.
        tenant_default_domain (str): The fetched default domain of the tenant (used less in Audit).
        document_version (float): The version number for this document run (e.g., 1.0, 2.0).
        diagram_paths (dict): Dictionary mapping subscription IDs to their diagram file paths.
        timestamp_str (str): Timestamp string for filenames.
        silent_mode (bool): Whether to suppress console output.

    Returns:
        str: The full path to the generated markdown file, or None if failed.
    """
    global SILENT_MODE
    SILENT_MODE = silent_mode

    report_path_dir = os.path.join(base_output_dir, REPORT_DIR)
    os.makedirs(report_path_dir, exist_ok=True)

    # Prepare timestamp suffix for filenames
    time_suffix = f"_{timestamp_str}" if timestamp_str else ""
    # Include version in filename
    report_filename = f"Azure_Audit_Report_{tenant_display_name.replace(' ', '_')}{time_suffix}_v{document_version:.1f}.md"
    report_filepath = os.path.join(report_path_dir, report_filename)

    if not SILENT_MODE:
        print(f"Generating Markdown Audit Report: {report_filepath}")
    logging.info(f"Generating Markdown Audit Report: {report_filepath}")

    md_content = []
    all_resources_list = [] # For CSV export

    # --- Use passed-in tenant name for title --- 
    report_tenant_name = tenant_display_name if tenant_display_name and "(Tenant ID)" not in tenant_display_name else "Azure Environment"
    if not report_tenant_name: report_tenant_name = "Azure Environment" # Final fallback
    
    md_content.append(f"# Azure Infrastructure Audit Report for {report_tenant_name} ({timestamp_str})")
    md_content.append(f"Generated on: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    md_content.append(f"Run ID: `{timestamp_str}`")
    md_content.append("## Tenant Summary")
    md_content.append(f"- **Total Subscriptions Found:** {len(all_data)}")
    
    # Add more tenant-level summaries
    total_resources = 0
    resource_type_counts = {}
    total_vnets = 0
    total_subnets = 0
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
            
        # Count resources
        resources = data.get("resources", [])
        total_resources += len(resources)
        
        # Count resource types
        for res in resources:
            res_type = res.get("type", "Unknown")
            resource_type_counts[res_type] = resource_type_counts.get(res_type, 0) + 1
            
        # Count network resources    
        networking = data.get("networking", {})
        total_vnets += len(networking.get("vnets", []))
        total_subnets += len(networking.get("subnets", []))
    
    md_content.append(f"- **Total Resources:** {total_resources}")
    md_content.append(f"- **Total VNets:** {total_vnets}")
    md_content.append(f"- **Total Subnets:** {total_subnets}")
    
    # Add resource type breakdown
    if resource_type_counts:
        md_content.append("\n### Resource Type Breakdown")
        md_content.append("| Resource Type | Count |")
        md_content.append("|--------------|-------|")
        for res_type, count in sorted(resource_type_counts.items(), key=lambda x: x[1], reverse=True):
            md_content.append(f"| `{res_type}` | {count} |")
    
    # --- Load Balancing Strategy ---
    md_content.append("\n## Load Balancing Strategy")
    all_lbs = []
    all_ags = []
    all_fds = []
    all_tms = []
    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data:
            continue
        networking = data["networking"]
        all_lbs.extend(networking.get("load_balancers", []))
        all_ags.extend(networking.get("application_gateways", []))
        all_fds.extend(networking.get("front_doors", []))
        all_tms.extend(networking.get("traffic_manager_profiles", []))

    md_content.extend(_generate_lb_table(all_lbs))
    md_content.extend(_generate_ag_table(all_ags))
    md_content.extend(_generate_fd_table(all_fds))
    md_content.extend(_generate_tm_table(all_tms))

    # --- List Global Admins and Privileged Accounts ---
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
        
        # Group resources by type to provide better organization
        resources_by_type = {}
        for res in resources:
            res_type = res.get("type", "Unknown")
            if res_type not in resources_by_type:
                resources_by_type[res_type] = []
            resources_by_type[res_type].append(res)
        
        # Now, the table (outside the list item)
        if resources:
            md_content.append("\n| Name | Type | Location | Resource Group | Tags |")
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
            
            # Add detailed section for App Services with their configurations
            app_services = [res for res in resources if res.get("type") == "Microsoft.Web/sites" and "app_service_details" in res]
            if app_services:
                md_content.append("\n#### App Service Details")
                for app in app_services:
                    md_content.append(f"\n**{app['name']}** (Resource Group: {app['resource_group']})")
                    
                    app_details = app.get("app_service_details", {})
                    
                    # App Settings
                    config = app_details.get("configuration", {})
                    if config:
                        md_content.append("\n**Application Settings:**")
                        md_content.append("| Key | Value |")
                        md_content.append("|-----|-------|")
                        for key, value in config.items():
                            # Mask sensitive values
                            if any(secret_keyword in key.lower() for secret_keyword in ['key', 'secret', 'password', 'pwd', 'token', 'connection']):
                                masked_value = "********"
                                md_content.append(f"| {key} | {masked_value} |")
                            else:
                                # Truncate values if they're too long
                                display_value = str(value)
                                if len(display_value) > 50:
                                    display_value = display_value[:47] + "..."
                                md_content.append(f"| {key} | {display_value} |")
                    
                    # Connection Strings (masked)
                    conn_strings = app_details.get("connection_strings", {})
                    if conn_strings:
                        md_content.append("\n**Connection Strings:**")
                        md_content.append("| Name | Type |")
                        md_content.append("|------|------|")
                        for name, details in conn_strings.items():
                            conn_type = details.get("type", "Unknown") if isinstance(details, dict) else "Unknown"
                            md_content.append(f"| {name} | {conn_type} |")
                    
                    # Auth Settings
                    auth_settings = app_details.get("auth_settings", {})
                    if auth_settings and isinstance(auth_settings, dict) and auth_settings:
                        md_content.append("\n**Authentication Settings:**")
                        auth_enabled = auth_settings.get("enabled", False)
                        md_content.append(f"- **Auth Enabled:** {auth_enabled}")
                        if auth_enabled:
                            providers = []
                            if auth_settings.get("microsoft_account_client_id"):
                                providers.append("Microsoft")
                            if auth_settings.get("google_client_id"):
                                providers.append("Google")
                            if auth_settings.get("facebook_client_id"):
                                providers.append("Facebook")
                            if auth_settings.get("twitter_consumer_key"):
                                providers.append("Twitter")
                            if auth_settings.get("aad_client_id"):
                                providers.append("Azure AD")
                            
                            if providers:
                                md_content.append(f"- **Providers:** {', '.join(providers)}")
            
            # Add detailed section for networking resources if needed
            # ... add more specialized sections for specific resource types
            
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
        csv_filename = f"azure_resource_inventory_{timestamp_str}.csv"
        csv_filepath = os.path.join(report_path_dir, csv_filename)
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

# --- Helper functions for generating tables ---

def _generate_lb_table(lbs):
    content = ["\n### Azure Load Balancers"]
    if not lbs:
        content.append("\n_No Azure Load Balancers found._")
        return content
    
    content.append("\n| Name | Resource Group | Location | SKU | Frontend IPs | Backend Pools | Rules |")
    content.append("|---|---|---|---|---|---|---|")
    for lb in sorted(lbs, key=lambda x: x.get("name", "")):
        name = lb.get("name", "Unknown")
        rg = lb.get("resource_group", "Unknown")
        loc = lb.get("location", "Unknown")
        sku = lb.get("sku", "Unknown")
        frontends = lb.get("frontend_ip_configurations_count", 0)
        backends = lb.get("backend_address_pools_count", 0)
        rules = lb.get("load_balancing_rules_count", 0)
        content.append(f"| {name} | {rg} | {loc} | {sku} | {frontends} | {backends} | {rules} |")
    return content

def _generate_ag_table(ags):
    content = ["\n### Application Gateways"]
    if not ags:
        content.append("\n_No Application Gateways found._")
        return content
    
    content.append("\n| Name | Resource Group | Location | SKU Tier | WAF Policy | Frontend IPs | Backend Pools | HTTP Listeners |")
    content.append("|---|---|---|---|---|---|---|---|")
    for ag in sorted(ags, key=lambda x: x.get("name", "")):
        name = ag.get("name", "Unknown")
        rg = ag.get("resource_group", "Unknown")
        loc = ag.get("location", "Unknown")
        sku = ag.get("sku", "Unknown") # Often a dict like {'name': 'WAF_v2', 'tier': 'WAF_v2'}
        sku_tier = sku.get("tier", "Unknown") if isinstance(sku, dict) else sku # Extract tier if possible
        waf_policy = ag.get("waf_policy_name", "N/A")
        frontends = ag.get("frontend_ip_configurations_count", 0)
        backends = ag.get("backend_address_pools_count", 0)
        listeners = ag.get("http_listeners_count", 0)
        content.append(f"| {name} | {rg} | {loc} | {sku_tier} | {waf_policy} | {frontends} | {backends} | {listeners} |")
    return content

def _generate_fd_table(fds):
    content = ["\n### Azure Front Doors (Standard/Premium)"]
    if not fds:
        content.append("\n_No Azure Front Doors (Standard/Premium) found._")
        return content
    
    content.append("\n| Name | Resource Group | Location | Provisioning State | Frontend Endpoints | Routing Rules |")
    content.append("|---|---|---|---|---|---|")
    for fd in sorted(fds, key=lambda x: x.get("name", "")):
        name = fd.get("name", "Unknown")
        rg = fd.get("resource_group", "Unknown")
        loc = fd.get("location", "Unknown")
        state = fd.get("provisioning_state", "Unknown")
        frontends = fd.get("frontend_endpoints_count", 0)
        rules = fd.get("routing_rules_count", 0)
        content.append(f"| {name} | {rg} | {loc} | {state} | {frontends} | {rules} |")
    return content

def _generate_tm_table(tms):
    content = ["\n### Traffic Manager Profiles"]
    if not tms:
        content.append("\n_No Traffic Manager Profiles found._")
        return content
    
    content.append("\n| Name | Resource Group | Status | Routing Method | Relative DNS | Endpoints |")
    content.append("|---|---|---|---|---|---|")
    for tm in sorted(tms, key=lambda x: x.get("name", "")):
        name = tm.get("name", "Unknown")
        rg = tm.get("resource_group", "Unknown")
        status = tm.get("profile_status", "Unknown")
        routing = tm.get("routing_method", "Unknown")
        dns = tm.get("dns_config_relative_name", "N/A")
        endpoints = tm.get("endpoints_count", 0)
        content.append(f"| {name} | {rg} | {status} | {routing} | {dns}.trafficmanager.net | {endpoints} |")
    return content

# --- End Helper functions ---