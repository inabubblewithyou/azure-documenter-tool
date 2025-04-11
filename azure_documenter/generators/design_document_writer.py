import os
import logging
from datetime import datetime, timezone
import time

# Define output directories relative to the main script or a base path
REPORT_DIR = "reports" 

# Global flag that can be set by the main module
SILENT_MODE = False

# --- Helper Functions for Markdown Generation ---

def _generate_markdown_table(headers, data_rows):
    """Generates a Markdown table string.

    Args:
        headers (list): List of header strings.
        data_rows (list): List of lists, where each inner list represents a row.

    Returns:
        str: Markdown formatted table, or a message if no data.
    """
    if not data_rows:
        return "_No data available._"
    
    md = []
    md.append(f"| {" | ".join(headers)} |")
    md.append(f"|{":--|" * len(headers)}|")
    for row in data_rows:
        # Process each cell in the row
        processed_cells = []
        for i, item in enumerate(row):
            # Convert to string if not already
            cell_content = str(item) if item is not None else ""
            
            # Format resource IDs, connection strings, etc. as code for better readability
            if isinstance(cell_content, str):
                # Check for resource IDs, connection strings, or other long technical strings
                if (cell_content.startswith('/subscriptions/') or 
                    'microsoft.network' in cell_content.lower() or 
                    'microsoft.compute' in cell_content.lower() or
                    'connectionstring' in cell_content.lower() or
                    cell_content.startswith('http') and len(cell_content) > 40):
                    
                    # If already wrapped in backticks, don't add more
                    if not cell_content.startswith('`'):
                        cell_content = f"`{cell_content}`"
            
            # Escape pipes using HTML entity and remove newlines
            cell_content = cell_content.replace('|', '&#124;').replace('\n', ' ')
            processed_cells.append(cell_content)
            
        md.append(f"| {" | ".join(processed_cells)} |")
    
    # Add blank lines before and after the table for better Markdown parsing
    return "\n" + "\n".join(md) + "\n"

def _get_subscriptions_table(all_data):
    """Generates Markdown table for subscriptions."""
    headers = ["Subscription Name", "Subscription ID"]
    rows = []
    for sub_id, data in all_data.items():
        name = "Unknown Subscription (Error)"
        if "subscription_info" in data:
             name = data["subscription_info"].get("display_name", sub_id)
             if "error" in data:
                  name += " (Error Fetching Details)"
        rows.append([name, f"`{sub_id}`"])
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: x[0]))

def _get_policy_states_table(all_data):
    """Generates Markdown table for Non-Compliant Policy States."""
    headers = ["Policy", "Subscription", "Resource Type", "Resource Name", "State"]
    rows = []
    found_any = False
    for sub_id, data in all_data.items():
        if "error" in data or "governance" not in data:
            continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        policy_states = data["governance"].get("policy_states", [])
        if policy_states: found_any = True
        
        for state in policy_states:
            if isinstance(state, dict):
                # Parse resource name from resource_id
                resource_name = "Unknown"
                resource_id = state.get("resource_id")
                if resource_id:
                    try:
                        resource_name = resource_id.split('/')[-1]
                        # Handle potential nested resources or different ID structures if necessary
                        if resource_name.lower() == sub_id.lower(): # If it's just the subscription ID
                             resource_name = "(Subscription Scope)"
                    except Exception:
                        resource_name = "(Parsing Error)"
                
                policy_name = state.get("policy_definition_name", state.get("policy_assignment_name", "Unknown Policy"))
                compliance_state = state.get("compliance_state", "Unknown") # Use the explicitly added state

                rows.append([
                    policy_name,
                    sub_name,
                    state.get("resource_type", "Unknown"),
                    resource_name,
                    compliance_state
                ])
            else:
                 logging.warning(f"Skipping non-dictionary policy state in sub {sub_id}: {state}")
                 
    if not found_any:
         return "_No non-compliant policy states detected or data available._"
         
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[1], x[0], x[3])))

def _get_security_recs_table(all_data):
    """Generates Markdown table for high/medium security recommendations."""
    headers = ["Recommendation", "Category", "Severity", "Subscription", "Impacted Resource Type"]
    rows = []
    for sub_id, data in all_data.items():
        if "error" in data or "governance" not in data:
            continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        recommendations = data["governance"].get("advisor_recommendations", [])
        for rec in recommendations:
            if isinstance(rec, dict):
                severity = str(rec.get("impact", "Low")).capitalize()
                if severity in ["High", "Medium"]:
                    short_desc = rec.get("short_description", "Unknown")
                    if isinstance(short_desc, dict):
                        title = short_desc.get("solution", short_desc.get("problem", "Unknown"))
                    else:
                        title = str(short_desc)
                    rows.append([
                        title,
                        rec.get("category", "Unknown"),
                        severity,
                        sub_name,
                        rec.get("impacted_field", "Multiple")
                    ])
            else:
                logging.warning(f"Skipping non-dictionary recommendation in sub {sub_id}: {rec}")
    severity_map = {"High": 3, "Medium": 2, "Low": 1}
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (-severity_map.get(x[2], 0), x[1], x[3])))

def _get_privileged_roles_table(all_data):
    """Generates Markdown table for discovered privileged roles."""
    headers = ["Display Name", "Principal Type", "Role(s)"]
    rows = []
    unique_privileged = {}
    for sub_id, data in all_data.items():
        if "error" in data or "security" not in data:
            continue
        privileged_users = data["security"].get("privileged_accounts", [])
        for user in privileged_users:
            if isinstance(user, dict):
                object_id = user.get("object_id", None)
                if not object_id: continue
                display_name = user.get("display_name", "Unknown")
                principal_type = user.get("principal_type", "Unknown")
                role_names = user.get("role_names", [])
                if object_id not in unique_privileged:
                    unique_privileged[object_id] = {"display_name": display_name, "principal_type": principal_type, "role_names": set(role_names)}
                else:
                    if unique_privileged[object_id]["display_name"] == "Unknown" and display_name != "Unknown":
                        unique_privileged[object_id]["display_name"] = display_name
                    unique_privileged[object_id]["role_names"].update(role_names)
            else:
                logging.warning(f"Skipping non-dictionary privileged user in sub {sub_id}: {user}")
    for user_info in unique_privileged.values():
        rows.append([user_info["display_name"], user_info["principal_type"], ", ".join(sorted(list(user_info["role_names"])))])
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: x[0]))

# --- Network Section Helpers ---

def _get_vnets_table(all_data):
    """Generates Markdown table for VNets."""
    headers = ["Subscription", "VNet Name", "Address Space(s)", "Subnets", "Region"]
    rows = []
    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data:
            continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        vnets = data["networking"].get("vnets", [])
        for vnet in vnets:
            if isinstance(vnet, dict):
                subnet_names = ", ".join([s.get('name', 'N/A') for s in data["networking"].get("subnets", []) 
                                        if s.get('vnet_name') == vnet.get('name')])
                address_spaces = ", ".join(vnet.get('address_space', []))
                rows.append([sub_name, vnet.get("name", "Unknown"), address_spaces, subnet_names, vnet.get("location", "Unknown")])
            else:
                logging.warning(f"Skipping non-dictionary vnet in sub {sub_id}: {vnet}")
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_peering_table(all_data):
    """Generates Markdown table for VNet peerings."""
    headers = ["Subscription", "VNet 1", "Peering State", "Remote VNet (ID)", "Allow Gateway Transit", "Use Remote Gateways"]
    rows = []
    found_any = False
    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data:
            continue
        peerings = data["networking"].get("peerings", [])
        if peerings: # Check if this sub has any
             found_any = True
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        for peering in peerings:
            if isinstance(peering, dict):
                # Attempt to extract local VNet name more robustly
                local_vnet_name = "Unknown"
                local_vnet_id = peering.get("local_vnet_id")
                if local_vnet_id:
                    # Find the VNet object in the same subscription data to get its name
                    vnets_in_sub = data["networking"].get("vnets", [])
                    matching_vnet = next((v for v in vnets_in_sub if v.get("id") == local_vnet_id), None)
                    if matching_vnet:
                        local_vnet_name = matching_vnet.get("name", "Unknown")
                rows.append([sub_name, local_vnet_name, peering.get("peering_state", "Unknown"), f"`{peering.get('remote_vnet_id', 'Unknown')}`", peering.get("allow_gateway_transit", False), peering.get("use_remote_gateways", False)])
            else:
                 logging.warning(f"Skipping non-dictionary peering in sub {sub_id}: {peering}")
    
    if not found_any:
         return "_Resource Not Detected in Audited Subscriptions._"
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_gateways_table(all_data):
    """Generates Markdown table for VPN/ER Gateways and Circuits."""
    headers = ["Subscription", "Name", "Type", "SKU", "Location"]
    rows = []
    found_any = False
    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data:
            continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        # Combine VPN Gateways and ER Circuits for this table
        gateways = data["networking"].get("vpn_gateways", [])
        circuits = data["networking"].get("expressroute_circuits", [])
        if gateways or circuits:
             found_any = True

        for gw in gateways:
             if isinstance(gw, dict):
                gw_type = "VPN Gateway"
                if gw.get("gateway_type") == "ExpressRoute": gw_type = "ER Gateway (VNet GW)"
                sku = gw.get("sku", "Unknown") # Already fetched as string
                rows.append([sub_name, gw.get("name", "Unknown"), gw_type, sku, gw.get("location", "Unknown")])
             else:
                 logging.warning(f"Skipping non-dictionary gateway in sub {sub_id}: {gw}")
        
        for circuit in circuits:
             if isinstance(circuit, dict):
                 sku = f"{circuit.get('sku_family', '')} {circuit.get('sku_tier', '')}".strip()
                 rows.append([sub_name, circuit.get("name", "Unknown"), "ExpressRoute Circuit", sku, circuit.get("location", "Unknown")])
             else:
                 logging.warning(f"Skipping non-dictionary circuit in sub {sub_id}: {circuit}")
                 
    if not found_any:
         return "_Resource Not Detected in Audited Subscriptions._"
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_firewalls_table(all_data):
    """Generates Markdown table for Azure Firewalls."""
    headers = ["Subscription", "Name", "SKU", "Policy Attached", "Location"]
    rows = []
    found_any = False
    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data:
            continue
        firewalls = data["networking"].get("firewalls", [])
        if firewalls:
             found_any = True
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        for fw in firewalls:
            if isinstance(fw, dict):
                policy_name = os.path.basename(fw.get("firewall_policy_id", "")) if fw.get("firewall_policy_id") else "N/A (Classic)"
                rows.append([sub_name, fw.get("name", "Unknown"), fw.get("sku", "Unknown"), policy_name, fw.get("location", "Unknown")])
            else:
                 logging.warning(f"Skipping non-dictionary firewall in sub {sub_id}: {fw}")

    if not found_any:
         return "_Resource Not Detected in Audited Subscriptions._"
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_dns_details(all_data):
    """Generates Markdown lists for Private DNS Zones and Custom VNet DNS."""
    private_zones_text = []
    custom_dns_text = []
    unique_custom_dns = set()

    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        private_zones = data["networking"].get("private_dns_zones", [])
        for zone in private_zones:
             if isinstance(zone, dict):
                links = ", ".join(zone.get('vnet_links', []))
                private_zones_text.append(f"- **{zone.get('name', 'Unknown')}** (Sub: {sub_name}): Linked to VNets: {links if links else 'None'}")
             else: logging.warning(f"Skipping non-dictionary private zone in sub {sub_id}: {zone}")
        vnets = data["networking"].get("vnets", [])
        for vnet in vnets:
            if isinstance(vnet, dict):
                dns_servers = vnet.get("custom_dns_servers", [])
                if dns_servers:
                    vnet_name = vnet.get("name", "Unknown")
                    dns_list = ", ".join(dns_servers)
                    custom_dns_text.append(f"- VNet **{vnet_name}** (Sub: {sub_name}): `{dns_list}`")
                    unique_custom_dns.update(dns_servers)
            else: logging.warning(f"Skipping non-dictionary vnet for DNS check in sub {sub_id}: {vnet}")
    private_zones_output = "\n".join(sorted(private_zones_text)) if private_zones_text else "_No Azure Private DNS Zones found linked to VNets._"
    custom_dns_output = "\n".join(sorted(custom_dns_text)) if custom_dns_text else "_No VNets found using Custom DNS Servers._"
    return private_zones_output, custom_dns_output

def _get_ddos_table(all_data):
    """Generates Markdown table for DDoS Protection Plans."""
    headers = ["Subscription", "Plan Name", "Protected VNet Count", "Location"]
    rows = []
    found_any = False
    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data:
            continue
        ddos_plans = data["networking"].get("ddos_protection_plans", [])
        if ddos_plans:
             found_any = True
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        for plan in ddos_plans:
             if isinstance(plan, dict):
                vnet_count = len(plan.get("virtual_network_ids", []))
                rows.append([sub_name, plan.get("name", "Unknown"), vnet_count, plan.get("location", "Unknown")])
             else:
                 logging.warning(f"Skipping non-dictionary DDoS plan in sub {sub_id}: {plan}")
                 
    if not found_any:
         return "_Resource Not Detected in Audited Subscriptions._"
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_private_endpoints_table(all_data):
    """Generates Markdown table for Private Endpoints."""
    headers = ["Subscription", "Name", "Connected Service Type", "Private Link Resource ID", "Subnet"]
    rows = []
    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        private_endpoints = data["networking"].get("private_endpoints", [])
        for pe in private_endpoints:
             if isinstance(pe, dict):
                service_type = "Unknown"
                pls_connections = pe.get("private_link_service_connections", [])
                pls_id_str = "N/A"
                if pls_connections and isinstance(pls_connections[0], dict):
                    pls_id = pls_connections[0].get("private_link_service_id", "")
                    pls_id_str = f"`{pls_id}`"
                    group_ids = pls_connections[0].get("group_ids", [])
                    if group_ids: service_type = group_ids[0].capitalize()
                    elif pls_id:
                        parts = pls_id.split('/')
                        if len(parts) > 7: service_type = parts[-3].capitalize()
                rows.append([sub_name, pe.get("name", "Unknown"), service_type, pls_id_str, os.path.basename(pe.get("subnet_id", "Unknown"))])
             else: logging.warning(f"Skipping non-dictionary private endpoint in sub {sub_id}: {pe}")
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_internet_ingress_list(all_data):
    """Generates Markdown list for potential Internet Ingress points."""
    ingress_points = []
    for sub_id, data in all_data.items():
        if "error" in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        public_ips = data.get("networking", {}).get("public_ips", [])
        for ip in public_ips:
            if isinstance(ip, dict) and ip.get("ip_address"):
                 assoc_type = ip.get("associated_resource_type", "Unknown")
                 if assoc_type == "Unknown" or any(t in assoc_type for t in ["loadBalancers", "applicationGateways", "azureFirewalls", "bastionHosts"]):
                     ingress_points.append(f"- Public IP: **{ip.get('name', 'Unknown')}** (`{ip.get('ip_address')}`) (Sub: {sub_name}, Associated Type: {assoc_type})")
        app_gws = data.get("networking", {}).get("app_gateways", [])
        for agw in app_gws:
             if isinstance(agw, dict):
                 sku_name = agw.get("sku", {}).get("name", "Unknown")
                 ingress_points.append(f"- Application Gateway: **{agw.get('name', 'Unknown')}** (Sub: {sub_name}, SKU: {sku_name})")
        front_doors_std = data.get("networking", {}).get("front_doors_std_premium", [])
        for afd in front_doors_std:
             if isinstance(afd, dict):
                 sku_name = afd.get("sku", {}).get("name", "Unknown")
                 ingress_points.append(f"- Front Door (Std/Premium): **{afd.get('name', 'Unknown')}** (Sub: {sub_name}, SKU: {sku_name})")
    return "\n".join(sorted(ingress_points)) if ingress_points else "_No common internet ingress points (Public IPs on key services, App Gateways, Front Doors) detected._"

# --- Security, Governance, Compliance Section Helpers ---

def _get_defender_status(all_data):
    """Generates Markdown list for Defender for Cloud status per subscription."""
    status_lines = []
    for sub_id, data in all_data.items():
        if "error" in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        security_data = data.get("security", {})
        defender_plans = security_data.get("defender_plans", [])
        enabled_status = "Enabled (Partial/Full)" if defender_plans else "Disabled/Not Detected"
        status_lines.append(f"- **{sub_name}**: {enabled_status}")
    return "\n".join(sorted(status_lines)) if status_lines else "_Could not determine Defender for Cloud status._"

def _get_sentinel_status(all_data):
    """Provides a status string indicating if Sentinel seems to be detected."""
    sentinel_detected = False
    sentinel_workspace = "Not Detected"
    for sub_id, data in all_data.items():
        if "error" in data: continue
        log_analytics = data.get("monitoring", {}).get("log_analytics_workspaces", []) 
        for ws in log_analytics:
            if isinstance(ws, dict):
                 solutions = ws.get("solutions", [])
                 if any(isinstance(sol, dict) and "securityinsights" in sol.get("name","").lower() for sol in solutions):
                     sentinel_detected = True
                     sentinel_workspace = f"Detected (Workspace: **{ws.get('name')})**"
                     break
        if sentinel_detected: break
    return f"Status: {sentinel_workspace}"

def _get_key_vaults_table(all_data):
    """Generates Markdown table for Key Vaults."""
    headers = ["Subscription", "Name", "SKU", "Region", "Private Endpoint"]
    rows = []
    for sub_id, data in all_data.items():
        if "error" in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        for res in resources:
            if isinstance(res, dict) and res.get("type", "").lower() == "microsoft.keyvault/vaults":
                pe_status = "No"
                private_endpoints = data.get("networking", {}).get("private_endpoints", [])
                for pe in private_endpoints:
                    if isinstance(pe, dict):
                        pls_connections = pe.get("private_link_service_connections", [])
                        if pls_connections and isinstance(pls_connections[0], dict):
                            pls_id = pls_connections[0].get("private_link_service_id", "")
                            if res.get("id", "").lower() == pls_id.lower():
                                pe_status = "Yes"; break
                sku_name = res.get("sku", None)
                if isinstance(sku_name, dict):
                     sku_name = sku_name.get("name", "Unknown")
                elif not sku_name:
                     sku_name = res.get("properties", {}).get("sku", {}).get("name", "Unknown")
                rows.append([sub_name, res.get("name", "Unknown"), sku_name, res.get("location", "Unknown"), pe_status])
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_policy_assignments_summary(all_data):
    """Generates Markdown summary of common policy assignments."""
    assignments = {}
    for sub_id, data in all_data.items():
        if "error" in data or "governance" not in data: continue
        policy_assignments = data["governance"].get("policy_assignments", [])
        for assign in policy_assignments:
             if isinstance(assign, dict):
                name = assign.get("display_name", assign.get("name", "Unknown"))
                # Use display_name if available and not empty, otherwise fallback to name
                display_name = assign.get("display_name")
                effective_name = display_name if display_name else assign.get("name", "Unknown")
                assignments[effective_name] = assignments.get(effective_name, 0) + 1
             else: logging.warning(f"Skipping non-dictionary policy assignment in sub {sub_id}: {assign}")
    if not assignments: return "_No policy assignment data available or detected._"
    top_n = 10
    sorted_assignments = sorted(assignments.items(), key=lambda item: item[1], reverse=True)
    summary_lines = [f"- **{name}** ({count} scopes)" for name, count in sorted_assignments[:top_n]]
    output = "Commonly Assigned Policies/Initiatives (Top 10):\n" + "\n".join(summary_lines)
    if len(sorted_assignments) > top_n: output += f"\n- ... and {len(sorted_assignments) - top_n} more."
    return output

def _get_tagging_analysis(all_data):
    """Generates Markdown summary for tagging analysis."""
    tag_counts = {}
    total_resources_with_tags = 0
    total_resources = 0
    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data: continue
        resources = data["resources"]
        total_resources += len(resources)
        for res in resources:
            if isinstance(res, dict):
                tags = res.get("tags")
                if tags and isinstance(tags, dict):
                    total_resources_with_tags += 1
                    for key in tags.keys():
                        tag_counts[key] = tag_counts.get(key, 0) + 1
    if not tag_counts: return ("_No tags found on resources._", "_N/A_")
    top_n_tags = 10
    sorted_tags = sorted(tag_counts.items(), key=lambda item: item[1], reverse=True)
    common_tags_lines = [f"- `{key}` ({count} resources)" for key, count in sorted_tags[:top_n_tags]]
    common_tags_output = "Top Tag Keys Found:\n" + "\n".join(common_tags_lines)
    if len(sorted_tags) > top_n_tags: common_tags_output += f"\n- ... and {len(sorted_tags) - top_n_tags} more tag keys."
    threshold = total_resources_with_tags * 0.75
    potential_mandatory = [f"`{key}`" for key, count in sorted_tags if count >= threshold]
    potential_mandatory_output = ", ".join(potential_mandatory) if potential_mandatory else "_None (Based on >75% coverage heuristic)_"
    return common_tags_output, potential_mandatory_output

# --- Management and Monitoring Section Helpers ---

def _get_log_analytics_workspaces_table(all_data):
    """Generates Markdown table for Log Analytics Workspaces."""
    headers = ["Subscription", "Name", "Region", "SKU", "Retention (Days)"]
    rows = []
    for sub_id, data in all_data.items():
        if "error" in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        # Assume workspaces are fetched under 'monitoring' or 'resources'
        workspaces = data.get("monitoring", {}).get("log_analytics_workspaces", [])
        # Fallback check in resources if not in monitoring
        if not workspaces:
             resources = data.get("resources", [])
             workspaces = [r for r in resources if isinstance(r, dict) and r.get("type","").lower() == "microsoft.operationalinsights/workspaces"]

        for ws in workspaces:
            if isinstance(ws, dict):
                # Extract SKU and Retention (might be nested differently)
                sku = ws.get("sku", {}).get("name", "Unknown")
                retention = ws.get("retention_in_days", "Unknown") 
                # Properties might contain more details
                properties = ws.get("properties", {})
                if sku == "Unknown": sku = properties.get("sku", {}).get("name", "Unknown")
                if retention == "Unknown": retention = properties.get("retentionInDays", "Unknown")
                
                rows.append([
                    sub_name,
                    ws.get("name", "Unknown"),
                    ws.get("location", "Unknown"),
                    sku,
                    str(retention) # Ensure it's a string
                ])
            else: logging.warning(f"Skipping non-dictionary LA Workspace in sub {sub_id}: {ws}")
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_agent_status_summary(all_data):
    """Provides a high-level summary of monitoring agent status (heuristic)."""
    # Heuristic: Check if Log Analytics workspaces have linked VMs or specific solutions
    agent_likely_present = False
    for sub_id, data in all_data.items():
        if "error" in data: continue
        workspaces = data.get("monitoring", {}).get("log_analytics_workspaces", [])
        if not workspaces:
             resources = data.get("resources", [])
             workspaces = [r for r in resources if isinstance(r, dict) and r.get("type","").lower() == "microsoft.operationalinsights/workspaces"]
             
        for ws in workspaces:
            if isinstance(ws, dict):
                # Check for solutions often associated with agents (VMInsights, AgentManagement etc.)
                solutions = ws.get("solutions", [])
                if any(isinstance(sol, dict) and any(n in sol.get("name","").lower() for n in ["vminsights", "agentmanagement"]) for sol in solutions):
                    agent_likely_present = True
                    break
                # Check if fetcher provides linked VM count (more reliable if available)
                # if ws.get("linked_vm_count", 0) > 0: 
                #    agent_likely_present = True
                #    break
        if agent_likely_present: break
        
    if agent_likely_present:
        return "Status: Agents (AMA/OMS) likely deployed to some VMs (based on workspace solutions/links). Specific VM coverage requires deeper analysis or agent health data."
    else:
        return "Status: Widespread agent deployment not detected based on workspace analysis. Manual verification or agent health data needed."

def _get_diagnostic_settings_summary():
    """Provides a general statement about diagnostic settings."""
    # Direct detection is hard without specific fetcher logic or deep resource graph queries
    return "Status: Configuration level (Widely/Sparsely Configured/Not Detected) is difficult to determine automatically without specific checks. Recommend auditing Diagnostic Settings via Azure Policy or script."

def _get_backup_status_summary(all_data):
    """Generates a summary of Azure Backup usage based on vaults and their SKUs."""
    vault_count = 0
    vaults_by_sub = {} 
    redundancy_counts = {'Standard_LRS': 0, 'Standard_GRS': 0, 'Standard_ZRS': 0, 'Unknown': 0}

    for sub_id, data in all_data.items():
        if "error" in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        # Check for Recovery Services Vaults in resources
        resources = data.get("resources", [])
        sub_vault_count = 0
        for res in resources:
            if isinstance(res, dict) and res.get("type", "").lower() == "microsoft.recoveryservices/vaults":
                vault_count += 1
                sub_vault_count += 1
                # Extract SKU for redundancy info
                sku_name = res.get("sku", {}).get("name", "Unknown").replace("RS0", "Standard") # Normalize RS0
                if "LRS" in sku_name.upper():
                     redundancy_counts['Standard_LRS'] += 1
                elif "GRS" in sku_name.upper():
                     redundancy_counts['Standard_GRS'] += 1
                elif "ZRS" in sku_name.upper():
                     redundancy_counts['Standard_ZRS'] += 1
                else:
                     redundancy_counts['Unknown'] += 1
                     logging.info(f"Unknown/non-standard Recovery Services Vault SKU found: {sku_name} for {res.get('name')}")

        if sub_vault_count > 0:
             vaults_by_sub[sub_name] = sub_vault_count

    if vault_count > 0:
        # Corrected f-string - ensure it's a single line and properly terminated
        summary = f"Status: Detected {vault_count} Recovery Services Vault(s). Distribution:\n"
        summary_lines = [f"- **{sub}**: {count} vault(s)" for sub, count in sorted(vaults_by_sub.items())]
        summary += "\n".join(summary_lines)
        summary += "\n_Note: Presence of vaults indicates potential backup usage. Actual resource protection status requires checking backup items within vaults._"
        return summary
    else:
        return "Status: No Recovery Services Vaults detected. Azure Backup may not be configured, or Backup Vaults (newer type) might be in use (detection not implemented)."

def _get_backup_redundancy_summary(all_data):
    """Generates a summary string of detected backup redundancy levels."""
    redundancy_counts = {'LRS': 0, 'GRS': 0, 'ZRS': 0}
    total_vaults = 0
    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data: continue
        resources = data.get("resources", [])
        for res in resources:
            if isinstance(res, dict) and res.get("type", "").lower() == "microsoft.recoveryservices/vaults":
                total_vaults += 1
                sku_name = res.get("sku", {}).get("name", "").upper()
                if "LRS" in sku_name: redundancy_counts['LRS'] += 1
                elif "GRS" in sku_name: redundancy_counts['GRS'] += 1
                elif "ZRS" in sku_name: redundancy_counts['ZRS'] += 1
    
    if total_vaults == 0:
        return "_No Recovery Services Vaults found to analyze redundancy._"
        
    summary_parts = []
    if redundancy_counts['LRS'] > 0: summary_parts.append(f"{redundancy_counts['LRS']}x LRS")
    if redundancy_counts['GRS'] > 0: summary_parts.append(f"{redundancy_counts['GRS']}x GRS")
    if redundancy_counts['ZRS'] > 0: summary_parts.append(f"{redundancy_counts['ZRS']}x ZRS")
    unknown_count = total_vaults - sum(redundancy_counts.values())
    if unknown_count > 0: summary_parts.append(f"{unknown_count}x Unknown SKU")
        
    return f"Redundancy based on Vault SKU: {', '.join(summary_parts)}." if summary_parts else "_Could not determine redundancy from Vault SKUs._"

# --- Analysis & Summary Helpers (Missing Function Definitions Added Here) ---

def _get_primary_regions(all_data, top_n=3):
    """Infers primary regions based on resource location counts."""
    region_counts = {}
    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data: continue
        for res in data["resources"]:
            if isinstance(res, dict) and "location" in res:
                loc = res["location"]
                if loc: # Ignore resources without location
                    region_counts[loc] = region_counts.get(loc, 0) + 1
    
    if not region_counts:
        return "_Could not determine primary regions._"
        
    sorted_regions = sorted(region_counts.items(), key=lambda item: item[1], reverse=True)
    primary_region_names = [f"{region} ({count} resources)" for region, count in sorted_regions[:top_n]]
    return ", ".join(primary_region_names) + (f" (Top {top_n})" if len(sorted_regions) > top_n else "")

def _get_connectivity_summary(all_data):
    """Summarizes discovered Gateways/Circuits."""
    gateways = []
    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data: continue
        # Combine VPN and ER gateways/circuits
        gateways.extend(data["networking"].get("vpn_gateways", []))
        gateways.extend(data["networking"].get("expressroute_circuits", []))
        
    if not gateways:
        return "_No VPN Gateways or ExpressRoute Circuits detected._"
        
    summary_parts = []
    vpn_count = sum(1 for gw in gateways if isinstance(gw,dict) and "gateway_type" in gw and gw["gateway_type"] == "Vpn")
    er_circuit_count = sum(1 for gw in gateways if isinstance(gw,dict) and "circuit_provisioning_state" in gw)
    er_gateway_count = sum(1 for gw in gateways if isinstance(gw,dict) and "gateway_type" in gw and gw["gateway_type"] == "ExpressRoute")
    
    if vpn_count > 0: summary_parts.append(f"{vpn_count} VPN Gateway(s)")
    if er_circuit_count > 0: summary_parts.append(f"{er_circuit_count} ExpressRoute Circuit(s)")
    if er_gateway_count > 0: summary_parts.append(f"{er_gateway_count} ExpressRoute Gateway(s) (VNet Gateways)")
        
    return f"Detected: {', '.join(summary_parts)}. See table in section 6.4 for details."

def _get_key_vault_access_model(all_data):
    """Analyzes Key Vault properties to infer common access model."""
    rbac_count = 0
    policy_count = 0
    checked_vaults = 0
    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data: continue
        resources = data["resources"]
        for res in resources:
            if isinstance(res, dict) and res.get("type", "").lower() == "microsoft.keyvault/vaults":
                checked_vaults += 1
                properties = res.get("properties", {})
                if properties.get("enableRbacAuthorization", False):
                    rbac_count += 1
                else:
                    policy_count += 1
    
    if checked_vaults == 0:
        return "_No Key Vaults found to analyze._"
    
    if rbac_count > policy_count and rbac_count / checked_vaults > 0.6:
        return "Predominantly **Azure RBAC** (based on `enableRbacAuthorization` property)."
    elif policy_count > rbac_count and policy_count / checked_vaults > 0.6:
        return "Predominantly **Vault Access Policies** (based on `enableRbacAuthorization` property)."
    elif rbac_count > 0 and policy_count > 0:
        return "**Mixed** use of Azure RBAC and Vault Access Policies detected."
    elif rbac_count > 0:
        return "Appears to use **Azure RBAC** (based on `enableRbacAuthorization` property)."
    else:
        return "Appears to use **Vault Access Policies** (based on `enableRbacAuthorization` property)."

def _get_cross_region_services(all_data):
    """Identifies potential cross-region services."""
    services = []
    grs_storage_found = False
    grs_backup_found = False # Harder to detect accurately

    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data: continue
        resources = data["resources"]
        for res in resources:
            if not isinstance(res, dict): continue
            res_type = res.get("type", "").lower()
            if "microsoft.network/trafficmanagerprofiles" in res_type:
                services.append(f"Azure Traffic Manager ({res.get('name')})")
            if "microsoft.cdn/profiles/endpoints" in res_type:
                 services.append(f"Azure Front Door Endpoint ({res.get('name')})")
            if "microsoft.storage/storageaccounts" in res_type:
                 sku_name = res.get("sku", {}).get("name", "").lower()
                 if "grs" in sku_name and not grs_storage_found:
                     services.append("Geo-Redundant Storage (GRS/GZRS) on some Storage Accounts")
                     grs_storage_found = True
            
    if not services:
        return "_No common cross-region services (Traffic Manager, Front Door, GRS Storage) detected._"
    else:
        return "Potential use of cross-region services detected: " + ", ".join(sorted(list(set(services))))

def _get_asr_status(all_data):
    """Heuristic check for ASR based on vault properties."""
    asr_vault_found = False
    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data: continue
        resources = data["resources"]
        for res in resources:
            if isinstance(res, dict) and res.get("type", "").lower() == "microsoft.recoveryservices/vaults":
                sku_name = res.get("sku", {}).get("name", "").lower()
                if sku_name in ["standard", "rsv2"]:
                    asr_vault_found = True
                    break 
        if asr_vault_found: break
        
    if asr_vault_found:
        return "Status: Recovery Services Vaults suitable for ASR detected. Actual ASR usage requires checking replication items."
    else:
        return "Status: No Recovery Services Vaults strongly indicating ASR usage detected (based on simple heuristics)."

def _get_landing_zone_examples(all_data, max_examples=3, max_resources_per_lz=5):
    """Generates Markdown examples for Landing Zones based on subscriptions."""
    lz_examples = []
    subs_processed = 0
    
    for sub_id, data in sorted(all_data.items(), key=lambda item: item[1].get('subscription_info', {}).get('display_name', item[0])):
        if "error" in data: continue
        if subs_processed >= max_examples: break
        
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        if not resources: continue
        
        subs_processed += 1
        example = []
        example.append(f"**Example Subscription/LZ: {sub_name} (`{sub_id}`)**")
        
        region_counts = {}
        for res in resources:
            if isinstance(res, dict) and "location" in res:
                loc = res["location"]
                if loc: region_counts[loc] = region_counts.get(loc, 0) + 1
        primary_region = sorted(region_counts.items(), key=lambda item: item[1], reverse=True)[0][0] if region_counts else "Unknown"
        example.append(f"*   **Primary Region:** {primary_region}")
        
        vnet_name = "_Not Found_"
        vnets = data.get("networking", {}).get("vnets", [])
        if vnets and isinstance(vnets[0], dict):
            vnet_name = vnets[0].get("name", "_Unknown_")
        example.append(f"*   **Network:** Associated VNet(s) likely `{vnet_name}` (See Section 6.4 for details)")

        resource_types = {}
        for res in resources:
            if isinstance(res, dict) and "type" in res:
                simple_type = res["type"].split('/')[-1]
                resource_types[simple_type] = resource_types.get(simple_type, 0) + 1
        
        sorted_types = sorted(resource_types.items(), key=lambda item: item[1], reverse=True)
        key_resources_list = [f"{count}x {res_type}" for res_type, count in sorted_types[:max_resources_per_lz]]
        example.append(f"*   **Key Resource Types:** {', '.join(key_resources_list)}" +
                       (f", ... (+{len(sorted_types) - max_resources_per_lz} more types)" if len(sorted_types) > max_resources_per_lz else ""))
        
        lz_examples.append("\n".join(example))

    if not lz_examples:
        return "_Could not generate Landing Zone examples (no resources found in subscriptions)._"
    
    return "\n\n".join(lz_examples)

# --- Placeholder Content Helpers ---

def _analyze_network_topology(all_data):
    """Enhanced heuristic to describe topology based on cross-subscription peering patterns."""
    has_peering = False
    has_firewall = False
    vnet_count = 0
    all_vnets = {}  # Map vnet_id -> {subscription, name, peer_count_outgoing, peer_count_incoming}
    vnets_with_firewall = set()  # Set of VNet IDs that contain a firewall
    
    # First pass: Collect all VNets and basic info
    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        
        # Track VNets
        vnets = data["networking"].get("vnets", [])
        vnet_count += len(vnets)
        for vnet in vnets:
            if not isinstance(vnet, dict): continue
            vnet_id = vnet.get("id")
            if vnet_id:
                all_vnets[vnet_id] = {
                    "subscription_id": sub_id,
                    "subscription_name": sub_name,
                    "name": vnet.get("name", "Unknown"),
                    "peer_count_outgoing": 0,
                    "peer_count_incoming": 0,
                    "allows_gateway_transit": False,
                    "uses_remote_gateways": False,
                    "is_hub_candidate": False
                }
        
        # Check for firewalls and associate with their VNets
        firewalls = data["networking"].get("firewalls", [])
        if firewalls:
            has_firewall = True
            for fw in firewalls:
                if isinstance(fw, dict):
                    # Get the VNet where this firewall is located
                    fw_subnet_id = fw.get("subnet_id")
                    if fw_subnet_id:
                        # Extract VNet ID from subnet ID
                        # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}
                        parts = fw_subnet_id.split("/subnets/")
                        if len(parts) > 1:
                            fw_vnet_id = parts[0]
                            vnets_with_firewall.add(fw_vnet_id)
    
    # Second pass: Analyze peerings to determine hub-spoke relationships
    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data: continue
        
        # Track peerings
        peerings = data["networking"].get("peerings", [])
        if peerings:
            has_peering = True
            for peering in peerings:
                if not isinstance(peering, dict): continue
                
                local_vnet_id = peering.get("local_vnet_id")
                remote_vnet_id = peering.get("remote_vnet_id")
                
                if local_vnet_id and remote_vnet_id:
                    # Increment outgoing peer count for local VNet
                    if local_vnet_id in all_vnets:
                        all_vnets[local_vnet_id]["peer_count_outgoing"] += 1
                        
                        # Check for gateway transit flags
                        if peering.get("allow_gateway_transit"):
                            all_vnets[local_vnet_id]["allows_gateway_transit"] = True
                            # A VNet that allows gateway transit is a strong hub indicator
                            all_vnets[local_vnet_id]["is_hub_candidate"] = True
                        
                        if peering.get("use_remote_gateways"):
                            all_vnets[local_vnet_id]["uses_remote_gateways"] = True
                    
                    # Increment incoming peer count for remote VNet
                    if remote_vnet_id in all_vnets:
                        all_vnets[remote_vnet_id]["peer_count_incoming"] += 1
                    
                    # If remote VNet not in our list, treat it as external
                    elif "..." not in remote_vnet_id:  # Skip placeholders
                        # Create stub entry for external VNet
                        subscription_id = None
                        try:
                            # Try to extract subscription ID from remote VNet ID
                            if "/subscriptions/" in remote_vnet_id:
                                parts = remote_vnet_id.split("/")
                                if len(parts) > 3:
                                    subscription_id = parts[2]
                        except:
                            pass
                        
                        all_vnets[remote_vnet_id] = {
                            "subscription_id": subscription_id,
                            "subscription_name": "External",
                            "name": remote_vnet_id.split('/')[-1] if '/' in remote_vnet_id else "Unknown",
                            "peer_count_outgoing": 0,
                            "peer_count_incoming": 1,  # We know at least this peering points to it
                            "allows_gateway_transit": False,
                            "uses_remote_gateways": False,
                            "is_hub_candidate": False,
                            "is_external": True
                        }
    
    # Third pass: Identify the hub(s) based on multiple criteria
    hub_vnets = []
    vnet_ids_with_firewalls = []
    
    # Mark VNets with firewalls as hub candidates and collect their IDs
    for vnet_id, vnet_info in all_vnets.items():
        if vnet_id in vnets_with_firewall:
            vnet_info["is_hub_candidate"] = True
            vnet_ids_with_firewalls.append(vnet_id)
    
    # Calculate a "hub score" for each VNet
    for vnet_id, vnet_info in all_vnets.items():
        # Skip external VNets from hub candidates
        if vnet_info.get("is_external", False):
            continue
            
        # Criteria for being a hub:
        hub_score = 0
        
        # 1. Has a firewall (+5)
        if vnet_id in vnets_with_firewall:
            hub_score += 5
            
        # 2. Allows gateway transit (+3)
        if vnet_info["allows_gateway_transit"]:
            hub_score += 3
            
        # 3. Has many incoming peerings (+1 per incoming, max 3)
        incoming_score = min(vnet_info["peer_count_incoming"], 3)
        hub_score += incoming_score
        
        # 4. Has word "hub" in the name (+2)
        if "hub" in vnet_info["name"].lower():
            hub_score += 2
            
        # 5. Is in a subscription with "corp", "hub", "connectivity", or "networking" in the name (+1)
        sub_name = vnet_info["subscription_name"].lower()
        if any(kw in sub_name for kw in ["corp", "hub", "connectivity", "networking", "shared", "platform"]):
            hub_score += 1
            # Flag specifically as "Corporate Landing Zone" when "corp" is in the subscription name
            if "corp" in sub_name:
                vnet_info["is_corporate_landing_zone"] = True
        else:
            vnet_info["is_corporate_landing_zone"] = False
            
        # Save the hub score
        vnet_info["hub_score"] = hub_score
        
        # Add to hub list if score is high enough
        if hub_score >= 3:  # Threshold for being considered a hub
            hub_vnets.append((vnet_id, vnet_info, hub_score))
    
    # Sort hubs by score
    hub_vnets.sort(key=lambda x: x[2], reverse=True)
    
    # Determine result based on analysis
    if not has_peering:
        return "Multiple VNets exist but **no VNet Peering** detected between them."
    
    if hub_vnets:
        # We found hub(s)
        primary_hub = hub_vnets[0][1]  # Get the highest scoring hub's info
        sub_name = primary_hub["subscription_name"]
        vnet_name = primary_hub["name"]
        
        # Check if this is a Corporate Landing Zone hub
        is_corporate_hub = primary_hub.get("is_corporate_landing_zone", False)
        hub_description = "Corporate Landing Zone hub" if is_corporate_hub else "Hub VNet"
        
        # Check if we have multiple hubs or just one
        if len(hub_vnets) > 1:
            hub_names = [h[1]["name"] for h in hub_vnets[:2]]  # Top 2 hubs
            return f"Likely **Hub-Spoke** topology with multiple hubs. Primary Hub: **{vnet_name}** in '{sub_name}' ({hub_description}). Secondary hub: {hub_names[1]}."
        else:
            return f"Likely **Hub-Spoke** topology detected. {hub_description}: **{vnet_name}** in subscription '{sub_name}'."
    
    if has_firewall:
        return "Network connectivity with Azure Firewall detected, but clear Hub-Spoke topology not identified."
    else:
        return "**Connected VNets (Mesh/Partial Mesh)** detected via peering but no clear hub identified."

def _analyze_internet_egress(all_data):
    """Basic heuristic for Internet Egress path."""
    has_firewall = False
    udr_found_pointing_to_fw = False # Need UDR fetcher logic for this

    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data: continue
        if data["networking"].get("firewalls", []): has_firewall = True
        # TODO: Add check for User Defined Routes (UDRs) if fetched.
        # Example (requires route_tables in networking data):
        # route_tables = data["networking"].get("route_tables", [])
        # for rt in route_tables:
        #    if isinstance(rt, dict):
        #        for route in rt.get("routes",[]):
        #             if isinstance(route,dict) and route.get("address_prefix") == "0.0.0.0/0" and "firewall" in route.get("next_hop_ip_address","").lower():
        #                 udr_found_pointing_to_fw = True; break
        # if udr_found_pointing_to_fw: break
        
    if has_firewall:
        # Add note about UDRs if that check is implemented
        udr_note = "(assuming User Defined Routes force traffic via Firewall)" if not udr_found_pointing_to_fw else "(confirmed via User Defined Routes)"
        return f"Likely via **Azure Firewall** {udr_note}."
    else:
        return "Likely via **Default VNet Outbound** (Network Address Translation). No central Azure Firewall detected."

def _analyze_nsg_summary():
     """Placeholder for NSG analysis."""
     return "_NSG analysis (rule density, common open ports) requires dedicated analysis logic not yet implemented._"

def _get_subscription_diagram_links(all_data, diagram_paths, report_path_dir):
    """Generates list of links to subscription diagrams."""
    links = []
    diagram_dir_abs = os.path.abspath(os.path.join(report_path_dir, '../diagrams')) # Get absolute path to diagram dir

    # Get the dictionary containing subscription diagrams
    subscription_diagram_dict = diagram_paths.get("subscription_diagrams", {})

    # Check for diagrams generated per subscription
    for sub_id, data in all_data.items():
         # Skip the special tenant_diagrams key if present (This shouldn't be in all_data, but good practice)
         if sub_id == "tenant_diagrams": 
             continue
             
         # Check if diagrams exist for this sub_id within the sub-dictionary
         if sub_id in subscription_diagram_dict:
             sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
             sub_diagrams = subscription_diagram_dict[sub_id] # Get diagrams from the sub-dictionary
             if isinstance(sub_diagrams, dict):
                 for key, diagram_filename in sub_diagrams.items(): # Expecting filename now
                     if not diagram_filename or not isinstance(diagram_filename, str):
                         logging.warning(f"Invalid diagram filename for {sub_name} - {key}: {diagram_filename}")
                         continue
                     
                     # Construct absolute path to check existence
                     full_diagram_path = os.path.join(diagram_dir_abs, diagram_filename)
                         
                     # Check if diagram file actually exists
                     if os.path.exists(full_diagram_path):
                        try:
                            # Calculate relative path from report dir to diagram dir + filename
                            relative_path = os.path.join("../diagrams", diagram_filename).replace("\\", "/")
                            link_text = f"{sub_name} - {key.replace('_', ' ').title()}"
                            links.append(f"- **{link_text}**:<br>![{link_text}]({relative_path})")
                        except Exception as e:
                             logging.warning(f"Could not calculate relative path for sub diagram {sub_name} - {key}: {e}")
                     else:
                         logging.warning(f"Subscription diagram file not found for {sub_name} at {full_diagram_path} (Filename: {diagram_filename})")
    
    return "\n".join(sorted(links)) if links else "_No subscription-specific diagrams found or paths provided._"

def _get_app_services_table(all_data):
    """Generates a detailed Markdown table for App Services."""
    headers = ["Subscription", "App Name", "App Service Plan", "Runtime", "Location", "Endpoint Integration"]
    rows = []
    found_any = False
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
            
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        
        # Find all app service plans first for later reference
        app_plans = {}
        for res in resources:
            if isinstance(res, dict) and res.get("type") == "Microsoft.Web/serverfarms":
                app_plans[res.get("id", "").lower()] = {
                    "name": res.get("name", "Unknown"),
                    "sku": res.get("sku", {}).get("name", "Unknown")
                }
        
        # Process all app services
        for res in resources:
            if isinstance(res, dict) and res.get("type") == "Microsoft.Web/sites":
                found_any = True
                app_name = res.get("name", "Unknown")
                location = res.get("location", "Unknown")
                properties = res.get("properties", {})
                kind = res.get("kind", "app") # Default to 'app' if not specified
                
                # Skip function apps etc. if we only want web apps (can refine later)
                # if "functionapp" in kind.lower(): continue
                
                # Get runtime stack info (Improved detection)
                runtime = "Unknown"
                site_config = properties.get("siteConfig", {})
                if site_config:
                    if site_config.get("linuxFxVersion"): runtime = site_config.get("linuxFxVersion")
                    elif site_config.get("windowsFxVersion"): runtime = site_config.get("windowsFxVersion")
                    elif site_config.get("javaVersion"): runtime = f'Java {site_config.get("javaVersion")}'
                    elif site_config.get("phpVersion"): runtime = f'PHP {site_config.get("phpVersion")}'
                    elif site_config.get("pythonVersion"): runtime = f'Python {site_config.get("pythonVersion")}'
                    elif site_config.get("nodeVersion"): runtime = f'Node {site_config.get("nodeVersion")}'
                    elif site_config.get("netFrameworkVersion"): runtime = f'.NET Framework {site_config.get("netFrameworkVersion")}'
                    # Fallback checks if specific versions aren't set
                    elif "DOCKER" in str(site_config.get("linuxFxVersion", "")).upper(): runtime = "Container (Linux)"
                    elif "COMPOSE" in str(site_config.get("linuxFxVersion", "")).upper(): runtime = "Docker Compose"
                    elif "dotnet" in str(site_config.get("windowsFxVersion", "")).lower(): runtime = ".NET Core (Windows)"
                    elif site_config.get("metadata"): # Check metadata for clues
                        metadata = site_config.get("metadata", [])
                        current_stack = next((m.get("value") for m in metadata if m.get("name") == "CURRENT_STACK"), None)
                        if current_stack: runtime = f"Stack: {current_stack}"

                # Get App Service Plan info (Safer access)
                plan_id = properties.get("serverFarmId", "").lower()
                plan_info = "Unknown"
                if plan_id in app_plans:
                    plan = app_plans[plan_id]
                    plan_info = f"{plan.get('name', 'Unknown')} ({plan.get('sku', 'Unknown')})"
                elif plan_id: # Extract name if plan object wasn't found
                    plan_info = plan_id.split('/')[-1]
                
                # Check for key integrations
                integrations = []
                # VNet integration
                if "WEBSITE_VNET_ROUTE_ALL" in str(site_config):
                    integrations.append("VNet")
                # Private Endpoints
                private_endpoints = data.get("networking", {}).get("private_endpoints", [])
                has_private_endpoint = False
                for pe in private_endpoints:
                    if isinstance(pe, dict):
                        conn = pe.get("private_link_service_connections", [])
                        if conn and isinstance(conn[0], dict):
                            target_id = conn[0].get("private_link_service_id", "").lower()
                            if target_id == res.get("id", "").lower():
                                has_private_endpoint = True
                                break
                if has_private_endpoint:
                    integrations.append("Private Endpoint")
                
                # Check for App Insights
                if site_config and any(k.startswith("APPINSIGHTS_") for k in site_config.keys()):
                    integrations.append("App Insights")
                
                integration_str = ", ".join(integrations) if integrations else "None detected"
                rows.append([sub_name, app_name, plan_info, runtime, location, integration_str])
    
    if not found_any:
        return "_No App Services detected in the environment._"
        
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_vms_table(all_data):
    """Generates Markdown table for Virtual Machines."""
    headers = ["Subscription", "VM Name", "Size", "OS Type", "Location", "Status"]
    rows = []
    found_any = False
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        
        # Filter for VM resources
        for res in resources:
            if isinstance(res, dict) and res.get("type", "").lower() == "microsoft.compute/virtualmachines":
                found_any = True
                vm_name = res.get("name", "Unknown")
                properties = res.get("properties", {})
                
                # Get Size
                vm_size = properties.get("hardwareProfile", {}).get("vmSize", "Unknown")
                if vm_size == "Unknown":
                    vm_size = res.get("size", "Unknown") # Alternate location sometimes used

                # Get OS Type (more robustly)
                os_type = "Unknown"
                os_profile = properties.get("osProfile", {})
                if os_profile:
                    if os_profile.get("windowsConfiguration"):
                        os_type = "Windows"
                    elif os_profile.get("linuxConfiguration"):
                        os_type = "Linux"
                
                # Try alternate method if not found
                if os_type == "Unknown":
                    storage_profile = properties.get("storageProfile", {})
                    os_disk = storage_profile.get("osDisk", {})
                    os_type_from_disk = os_disk.get("osType") # Returns 'Windows' or 'Linux'
                    if os_type_from_disk:
                        os_type = os_type_from_disk

                location = res.get("location", "Unknown")
                # Get Status (prefer instance view)
                status = "Unknown"
                instance_view = properties.get("instanceView", {})
                if instance_view:
                    statuses = instance_view.get("statuses", [])
                    # Look for PowerState status like 'PowerState/running' or 'PowerState/deallocated'
                    power_status = next((s.get("displayStatus") for s in statuses if s.get("code", "").startswith("PowerState/")), None)
                    if power_status:
                        status = power_status
                # Fallback to provisioning state if instance view not available/useful
                if status == "Unknown":
                     status = properties.get("provisioningState", "Unknown")

                rows.append([sub_name, vm_name, vm_size, os_type, location, status])
    
    if not found_any:
        return "_No Virtual Machines detected in the environment._"
    
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

# --- Main Function ---

def generate_design_document(all_data, base_output_dir, tenant_display_name, tenant_default_domain, document_version, diagram_paths={}, timestamp_str="", silent_mode=False):
    """Generates a timestamped Azure Landing Zone Design Document using a template.

    Args:
        all_data (dict): The aggregated data from all fetchers.
        base_output_dir (str): The base directory for outputs.
        tenant_display_name (str): The fetched display name of the tenant (e.g., "Contoso Corp").
        tenant_default_domain (str): The fetched default domain of the tenant (e.g., "contoso.onmicrosoft.com").
        document_version (float): The version number for this document run (e.g., 1.0, 2.0).
        diagram_paths (dict): A dictionary mapping subscription IDs/tenant to their generated diagram paths.
        timestamp_str (str): Timestamp string for filenames.
        silent_mode (bool): Whether to suppress console output.
    """
    os.makedirs(REPORT_DIR, exist_ok=True)
    # Define the report path directory based on base_output_dir
    report_path_dir = os.path.join(base_output_dir, REPORT_DIR)
    os.makedirs(report_path_dir, exist_ok=True) # Ensure it exists

    # --- File Naming ---
    filename_base = f"Azure_Design_Document_{tenant_display_name.replace(' ', '_')}"
    filename = f"{filename_base}_{timestamp_str}_v{document_version:.1f}.md"
    report_path = os.path.join(REPORT_DIR, filename)

    if not silent_mode:
        print(f"Generating Design Document: {report_path}")
    logging.info(f"Generating Design Document: {report_path}")

    # --- Document Content Initialization ---
    content = [
        f"# Azure Enterprise Architecture & Design - {tenant_display_name}",
        f"**Document Version:** {document_version:.1f} (Generated)",
        f"**Date Generated (Local):** {datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S').strftime('%Y-%m-%d %H:%M:%S')} ({time.tzname[time.daylight]})\n"
    ]

    # --- Table of Contents (Placeholder - can be generated later) ---
    content.append("## Table of Contents")
    content.append("*(Auto-generated TOC can be added here)*\n")

    # --- 1. Executive Summary ---
    # ... (rest of content generation - Needs update to use document_version) ...

    # --- Use passed-in Tenant Info ---
    # Use the display name directly for titles/overviews
    report_tenant_name = tenant_display_name if tenant_display_name and "(Tenant ID)" not in tenant_display_name else "Azure Environment"
    
    # Use the default domain specifically for the identity section
    identity_tenant_domain = tenant_default_domain if tenant_default_domain and "(Tenant ID)" not in tenant_default_domain else "Entra ID Tenant"
    
    # Extract compliance standards from policy assignments
    compliance_standards = []
    for sub_id, data in all_data.items():
        if "error" in data or "governance" not in data:
            continue
        
        policies = data["governance"].get("policy_assignments", [])
        for policy in policies:
            if isinstance(policy, dict):
                policy_name = policy.get("name", "").lower()
                # Look for common compliance policy names
                if any(std in policy_name for std in ["iso", "hipaa", "pci", "gdpr", "nist", "fedramp", "soc"]):
                    for std in ["iso27001", "iso 27001", "hipaa", "pci", "gdpr", "nist", "fedramp", "soc"]:
                        if std in policy_name and std.upper() not in compliance_standards:
                            compliance_standards.append(std.upper())
    
    compliance_text = ", ".join(compliance_standards) if compliance_standards else "No specific compliance standards detected from policy assignments"

    # Calculate values needed for multiple placeholders first
    primary_regions = _get_primary_regions(all_data)
    connectivity_summary = _get_connectivity_summary(all_data)
    network_topology_summary = _analyze_network_topology(all_data)
    sentinel_status_str = _get_sentinel_status(all_data)
    defender_status_list = _get_defender_status(all_data)
    backup_redundancy_summary = _get_backup_redundancy_summary(all_data)
    
    # Check for AD Connect by looking for hybrid indicators
    ad_connect_status = "Not Detected"
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        # Look for AD Connect instances in resource list
        resources = data.get("resources", [])
        for res in resources:
            if isinstance(res, dict) and "ADConnect" in res.get("name", ""):
                ad_connect_status = f"Likely Configured (Found resource: {res.get('name')})"
                break
                
        # Look for AD Connect health service in Log Analytics solutions
        if ad_connect_status == "Not Detected":
            log_analytics = data.get("monitoring", {}).get("log_analytics_workspaces", [])
            for ws in log_analytics:
                if isinstance(ws, dict):
                    solutions = ws.get("solutions", [])
                    if any(sol.get("name", "").lower().startswith("adconnect") for sol in solutions if isinstance(sol, dict)):
                        ad_connect_status = "Detected (Log Analytics ADConnect Health Solution found)"
                        break
        
        # Check for hybrid networking like ExpressRoute or S2S VPN
        if ad_connect_status == "Not Detected":
            networking = data.get("networking", {})
            gateways = networking.get("vpn_gateways", [])
            circuits = networking.get("expressroute_circuits", [])
            if gateways or circuits:
                ad_connect_status = "Likely Configured (Hybrid connectivity detected - ExpressRoute/VPN)"
                break
                
    # Detect PIM status by looking for authorization model indicators
    pim_status = "Not Detected"
    for sub_id, data in all_data.items():
        if "error" in data or "security" not in data:
            continue
        
        # Look for Azure PIM role assignments (eligible assignments)
        rbac = data["security"].get("role_assignments", [])
        for role in rbac:
            if isinstance(role, dict) and role.get("assignment_type") == "Eligible":
                pim_status = "Enabled (Eligible role assignments detected)"
                break
    
    # Detect managed identity usage
    managed_identities = []
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        resources = data.get("resources", [])
        for res in resources:
            if isinstance(res, dict):
                # Look for managed identity in resource tags or name
                if res.get("type") == "Microsoft.ManagedIdentity/userAssignedIdentities":
                    managed_identities.append(res.get("name", "Unknown"))
                # Check if resources have managed identity enabled
                elif res.get("identity", {}).get("type") in ["SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"]:
                    managed_identities.append(f"{res.get('name')} ({res.get('type')})")
    
    managed_identity_status = f"In Use ({len(managed_identities)} instances detected)" if managed_identities else "Not Detected or Limited Usage"

    # --- Define the Design Document Template ---    
    # Use a standard timestamp format
    now_utc = datetime.now(timezone.utc) # Use the directly imported timezone class
    formatted_timestamp = now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
    
    design_template = f"""
# Azure Enterprise Architecture & Design Document: {report_tenant_name}

**Document Version:** {document_version:.1f} (Generated) | **Date:** {formatted_timestamp} | **Status:** Auto-Generated from Environment Scan

## 1. Executive Summary

### 1.1. Organization Overview
{report_tenant_name} is leveraging Microsoft Azure to enhance agility, scalability, and innovation while optimizing costs. This architecture assessment provides a comprehensive analysis of the current cloud environment to guide future architecture decisions.

### 1.2. Current State Assessment
Based on discovered resources, the architecture involves resources primarily in **{primary_regions}**. Network analysis suggests a **{network_topology_summary.lower()}** with multiple subscription boundaries defining security domains.

* **Identity Foundation:** Entra ID tenant (`{identity_tenant_domain}`) manages authentication
* **Network Architecture:** {network_topology_summary} connecting various application environments
* **Security Posture:** {defender_status_list}
* **Monitoring Coverage:** Multiple Log Analytics workspaces with varying levels of integration

### 1.3. Critical Recommendations
1. **Security Enhancement:** Address high priority Microsoft Defender for Cloud recommendations
2. **Network Optimization:** Implement consistent network security patterns
3. **Governance Maturity:** Enhance tagging strategy and policy compliance

### 1.4. Target Architecture Vision
Evolve toward a fully governed, enterprise-scale landing zone architecture with proper separation of concerns, comprehensive monitoring, and security controls aligned with industry best practices.

## 2. Enterprise Organization Structure

### 2.1. Management Group Hierarchy
* **Current Structure:** {{MANAGEMENT_GROUP_HIERARCHY_PLACEHOLDER}}
* **Governance Strategy:** Based on subscription organization patterns, governance appears to be managed primarily at the subscription level

### 2.2. Subscription Strategy 
* **Current Subscription Model:**
{{SUBSCRIPTIONS_TABLE_PLACEHOLDER}}
* **Subscription Purpose Analysis:** 
{{SUBSCRIPTION_PURPOSE_PLACEHOLDER}}

### 2.3. Resource Organization
* **Resource Group Naming Patterns:** {{RESOURCE_GROUP_PATTERNS_PLACEHOLDER}}
* **Resource Distribution:** Primary workload concentrations in {primary_regions}
* **Resource Lifecycle Management:** {{RESOURCE_LIFECYCLE_PLACEHOLDER}}

## 3. Identity & Access Management

### 3.1. Identity Foundation
* **Entra ID Tenant:** `{identity_tenant_domain}`
* **Identity Synchronization:** {ad_connect_status}
* **Authentication Methods:** {{AUTHENTICATION_METHODS_PLACEHOLDER}}

### 3.2. Authorization Model
* **RBAC Approach:** {{RBAC_APPROACH_PLACEHOLDER}}
* **Custom Roles:** {{CUSTOM_ROLES_PLACEHOLDER}}
* **Key Role Assignments:** See detailed table in Appendix

### 3.3. Privileged Access
* **Privileged Identity Management:** {pim_status}
* **Just-In-Time Access:** {{JIT_ACCESS_PLACEHOLDER}}
* **Privileged Access Workstations:** Not detected in the environment scan

### 3.4. Application Identities
* **Managed Identities:** {managed_identity_status}
* **Service Principals:** {{SERVICE_PRINCIPALS_PLACEHOLDER}}

## 4. Network Architecture

### 4.1. Network Topology
* **Virtual Networks:** 
{{VNETS_TABLE_PLACEHOLDER}}
* **Connectivity Model:** {network_topology_summary}
* **VNet Peering Relationships:**
{{PEERING_TABLE_PLACEHOLDER}}
* **Route Tables:** {{ROUTE_TABLES_PLACEHOLDER}}

### 4.2. Connectivity Architecture
* **Hybrid Connectivity:**
{{GATEWAYS_TABLE_PLACEHOLDER}}
* **Internet Egress Strategy:** {{INTERNET_EGRESS_PLACEHOLDER}}
* **Internet Ingress Points:**
{{INGRESS_LIST_PLACEHOLDER}}

### 4.3. Network Security
* **Azure Firewalls:**
{{FIREWALLS_TABLE_PLACEHOLDER}}
* **Network Security Groups:** Applied to secure network traffic
* **DDoS Protection:**
{{DDOS_TABLE_PLACEHOLDER}}
* **Web Application Firewalls:** {{WAF_PLACEHOLDER}}

### 4.4. DNS Architecture
* **Private DNS Zones:**
{{PRIVATE_DNS_LIST_PLACEHOLDER}}
* **Custom DNS Settings:**
{{CUSTOM_DNS_LIST_PLACEHOLDER}}
* **DNS Resolution Flows:** {{DNS_RESOLUTION_PLACEHOLDER}}

### 4.5. Private Service Access
* **Private Endpoints:**
{{PRIVATE_ENDPOINTS_TABLE_PLACEHOLDER}}
* **Service Endpoints:** {{SERVICE_ENDPOINTS_PLACEHOLDER}}
* **Private Link Services:** {{PRIVATE_LINK_SERVICES_PLACEHOLDER}}

## 5. Compute & Application Services

### 5.1. Workload Patterns
* **Infrastructure as a Service (IaaS):**
{{VMS_TABLE_PLACEHOLDER}}
* **Platform as a Service (PaaS):**
{{APP_SERVICES_TABLE_PLACEHOLDER}}
* **Serverless Components:** {{SERVERLESS_PLACEHOLDER}}

### 5.2. Application Architectures
* **Web Applications:** {{WEB_APPS_PLACEHOLDER}}
* **API Services:** {{API_SERVICES_PLACEHOLDER}}
* **Container Services:** {{CONTAINER_SERVICES_PLACEHOLDER}}

### 5.3. Scaling & Resilience
* **Auto-scaling Configurations:** {{AUTOSCALING_PLACEHOLDER}}
* **Availability Patterns:** {{AVAILABILITY_PLACEHOLDER}}
* **Load Balancing Strategy:** {{LOAD_BALANCING_PLACEHOLDER}}

### 5.4. DevOps Integration
* **Deployment Methods:** {{DEPLOYMENT_METHODS_PLACEHOLDER}}
* **Environment Strategy:** {{ENVIRONMENT_STRATEGY_PLACEHOLDER}}
* **CI/CD Integration:** {{CICD_PLACEHOLDER}}

## 6. Data Platform

### 6.1. Data Storage Strategy
* **Storage Accounts:**
{{STORAGE_ACCOUNTS_PLACEHOLDER}}
* **Data Lake Architecture:** {{DATA_LAKE_PLACEHOLDER}}
* **Backup Storage:** {{BACKUP_STORAGE_PLACEHOLDER}}

### 6.2. Database Services
* **Relational Databases:**
{{RELATIONAL_DATABASES_PLACEHOLDER}}
* **NoSQL Databases:**
{{NOSQL_DATABASES_PLACEHOLDER}}
* **Analytics Services:** {{ANALYTICS_SERVICES_PLACEHOLDER}}

### 6.3. Data Protection
* **Encryption Strategy:** {{ENCRYPTION_STRATEGY_PLACEHOLDER}}
* **Data Classification:** {{DATA_CLASSIFICATION_PLACEHOLDER}}
* **Data Sovereignty:** {{DATA_SOVEREIGNTY_PLACEHOLDER}}

## 7. Security & Compliance

### 7.1. Security Posture
* **Microsoft Defender for Cloud:** {defender_status_list}
* **Security Recommendations:** See detailed table in Appendix
* **Vulnerability Management:** {{VULNERABILITY_MANAGEMENT_PLACEHOLDER}}

### 7.2. Security Operations
* **Microsoft Sentinel:** {sentinel_status_str}
* **Security Monitoring:** {{SECURITY_MONITORING_PLACEHOLDER}}
* **Threat Protection:** {{THREAT_PROTECTION_PLACEHOLDER}}

### 7.3. Encryption & Key Management
* **Key Vaults:**
{{KEY_VAULTS_TABLE_PLACEHOLDER}}
* **Access Model:** {{KEY_VAULT_ACCESS_MODEL_PLACEHOLDER}}
* **Certificate Management:** {{CERTIFICATE_MANAGEMENT_PLACEHOLDER}}

### 7.4. Compliance Framework
* **Policy Compliance:** {{POLICY_COMPLIANCE_PLACEHOLDER}}
* **Regulatory Considerations:** {compliance_text}
* **Compliance Reporting:** {{COMPLIANCE_REPORTING_PLACEHOLDER}}

## 8. Monitoring & Operations

### 8.1. Monitoring Foundation
* **Log Analytics Workspaces:**
{{LOG_ANALYTICS_TABLE_PLACEHOLDER}}
* **Monitoring Agents:** {{AGENT_STATUS_PLACEHOLDER}}
* **Monitoring Coverage:** {{MONITORING_COVERAGE_PLACEHOLDER}}

### 8.2. Operational Visibility
* **Azure Monitor Configuration:** {{AZURE_MONITOR_PLACEHOLDER}}
* **Application Monitoring:** {{APPLICATION_MONITORING_PLACEHOLDER}}
* **Infrastructure Monitoring:** {{INFRASTRUCTURE_MONITORING_PLACEHOLDER}}

### 8.3. Alerting & Notification Strategy
* **Alert Rules Configuration:** {{ALERT_RULES_PLACEHOLDER}}
* **Action Groups:** {{ACTION_GROUPS_PLACEHOLDER}}
* **Service Health:** {{SERVICE_HEALTH_PLACEHOLDER}}

### 8.4. IT Service Management Integration
* **Incident Management:** {{INCIDENT_MANAGEMENT_PLACEHOLDER}}
* **Change Management:** {{CHANGE_MANAGEMENT_PLACEHOLDER}}
* **Service Catalog:** {{SERVICE_CATALOG_PLACEHOLDER}}

## 9. Business Continuity & Disaster Recovery

### 9.1. Resilience Architecture
* **Regional Distribution:** Primary region: {primary_regions}
* **Multi-Region Services:** {{CROSS_REGION_SERVICES_PLACEHOLDER}}
* **Recovery Objectives:** {{RECOVERY_OBJECTIVES_PLACEHOLDER}}

### 9.2. Backup Strategy
* **Azure Backup Implementation:** {{BACKUP_STATUS_PLACEHOLDER}}
* **Backup Policies:** {{BACKUP_POLICIES_PLACEHOLDER}}
* **Backup Testing:** {{BACKUP_TESTING_PLACEHOLDER}}

### 9.3. Disaster Recovery
* **Azure Site Recovery:** {{ASR_STATUS_PLACEHOLDER}}
* **DR Runbooks:** {{DR_RUNBOOKS_PLACEHOLDER}}
* **DR Testing Strategy:** {{DR_TESTING_PLACEHOLDER}}

## 10. Cost Management & Optimization

### 10.1. Cost Structure
* **Subscription Costs:** {{SUBSCRIPTION_COSTS_PLACEHOLDER}}
* **Resource Type Distribution:** {{RESOURCE_TYPE_COSTS_PLACEHOLDER}}
* **Cost Allocation:** {{COST_ALLOCATION_PLACEHOLDER}}

### 10.2. Optimization Status
* **Right-sizing Opportunities:** {{RIGHTSIZING_PLACEHOLDER}}
* **Reserved Instances:** {{RESERVED_INSTANCES_PLACEHOLDER}}
* **Hybrid Benefits:** {{HYBRID_BENEFITS_PLACEHOLDER}}

### 10.3. Budget Controls
* **Budget Configuration:** {{BUDGET_CONFIGURATION_PLACEHOLDER}}
* **Cost Anomaly Detection:** {{COST_ANOMALY_PLACEHOLDER}}
* **Showback/Chargeback:** {{SHOWBACK_PLACEHOLDER}}

## 11. Governance & Compliance

### 11.1. Policy Framework
* **Key Assigned Policies/Initiatives:**
{{POLICY_SUMMARY_PLACEHOLDER}}
* **Non-Compliant Resources:** See detailed table in Appendix
* **Custom Policies:** {{CUSTOM_POLICIES_PLACEHOLDER}}

### 11.2. Resource Governance
* **Tagging Strategy:**
    * Common Tags: {{COMMON_TAGS_PLACEHOLDER}}
    * Mandatory Tags: {{MANDATORY_TAGS_PLACEHOLDER}}
* **Resource Lifecycle:** {{RESOURCE_LIFECYCLE_GOVERNANCE_PLACEHOLDER}}
* **Technical Debt Management:** {{TECHNICAL_DEBT_PLACEHOLDER}}

## 12. Roadmap & Recommendations

### 12.1. Architecture Maturity Assessment
* **Identity & Access Management:** {{IDENTITY_MATURITY_PLACEHOLDER}}
* **Network Security:** {{NETWORK_MATURITY_PLACEHOLDER}}
* **Security & Compliance:** {{SECURITY_MATURITY_PLACEHOLDER}}
* **Operations Management:** {{OPERATIONS_MATURITY_PLACEHOLDER}}
* **Overall Cloud Maturity Score:** {{MATURITY_SCORE_PLACEHOLDER}}

### 12.2. Strategic Initiatives
* **Short-term Priorities:** {{SHORT_TERM_PRIORITIES_PLACEHOLDER}}
* **Medium-term Projects:** {{MEDIUM_TERM_PLACEHOLDER}}
* **Long-term Vision:** {{LONG_TERM_PLACEHOLDER}}

### 12.3. Implementation Plan
* **Quick Wins:** {{QUICK_WINS_PLACEHOLDER}}
* **Major Milestones:** {{MAJOR_MILESTONES_PLACEHOLDER}}
* **Critical Dependencies:** {{CRITICAL_DEPENDENCIES_PLACEHOLDER}}

## 13. Landing Zone Design & Examples

### 13.1. Target Landing Zone Model
* **Landing Zone Types:** {{LANDING_ZONE_TYPES_PLACEHOLDER}}
* **Platform vs. Application Responsibilities:** {{PLATFORM_RESPONSIBILITIES_PLACEHOLDER}}
* **Common Service Integration:** {{COMMON_SERVICES_PLACEHOLDER}}

### 13.2. Example Landing Zones
{{LANDING_ZONE_EXAMPLES_PLACEHOLDER}}

## 14. Appendix - Technical Details

### 14.1. Reference Architecture Diagrams
* **Enterprise-level Network Topology:**
<!-- Placeholder for the image tag. We will replace this based on the diagram path -->
{{TENANT_DIAGRAM_IMAGE_TAG_PLACEHOLDER}}

* **Subscription Network Diagrams:**
{{SUBSCRIPTION_DIAGRAMS_PLACEHOLDER}}

### 14.2. Resource Inventory
* **Key Statistics:**
  * Total Subscriptions: {{SUBSCRIPTION_COUNT_PLACEHOLDER}}
  * Total Resources: {{RESOURCE_COUNT_PLACEHOLDER}}
  * Total VNets: {{VNET_COUNT_PLACEHOLDER}}
  * Total Subnets: {{SUBNET_COUNT_PLACEHOLDER}}

### 14.3. Security Findings
* **Security Recommendations (High/Medium):**
{{SECURITY_RECS_TABLE_PLACEHOLDER}}

### 14.4. Policy Details
* **Non-Compliant Policy States:**
{{POLICY_STATES_TABLE_PLACEHOLDER}}

### 14.5. Role Assignments
* **Privileged Role Assignments:**
{{PRIVILEGED_ROLES_TABLE_PLACEHOLDER}}

"""

    # --- Populate Placeholders --- 
    replacements = {}
    diagram_dir_abs = os.path.abspath(os.path.join(report_path_dir, '../diagrams')) # Absolute path to diagram dir

    # Section 14.1: Diagrams 
    # Determine the Tenant Diagram Image Tag
    tenant_diagram_image_tag = "_Tenant-wide network diagram not generated or found._"
    tenant_diagram_info = diagram_paths.get("tenant_diagrams", {})
    tenant_diagram_filename = tenant_diagram_info.get("network_topology") # Expecting filename

    if tenant_diagram_filename and isinstance(tenant_diagram_filename, str):
        full_diagram_path = os.path.join(diagram_dir_abs, tenant_diagram_filename)
        if os.path.exists(full_diagram_path):
            try:
                # Calculate relative path for the link
                relative_path = os.path.join("../diagrams", tenant_diagram_filename).replace("\\", "/")
                # Generate the HTML <img> tag directly
                tenant_diagram_image_tag = f'<img alt="Tenant Network Diagram" src="{relative_path}" />'
            except Exception as e:
                logging.warning(f"Could not calculate relative path for tenant diagram: {e}")
                tenant_diagram_image_tag = f"_Error creating path for {tenant_diagram_filename}_"
        else:
            logging.warning(f"Tenant diagram file not found at {full_diagram_path} (Filename: {tenant_diagram_filename})")
            tenant_diagram_image_tag = f"_Diagram file not found ({tenant_diagram_filename})_"
    elif tenant_diagram_info:
         logging.warning(f"Tenant diagram info found but filename is invalid: {tenant_diagram_filename}")
         
    # Use the new placeholder for the image tag
    replacements["{{TENANT_DIAGRAM_IMAGE_TAG_PLACEHOLDER}}"] = tenant_diagram_image_tag
    # Pass report_path_dir to helper for relative path calculation
    replacements["{{SUBSCRIPTION_DIAGRAMS_PLACEHOLDER}}"] = _get_subscription_diagram_links(all_data, diagram_paths, report_path_dir)

    # Section 2.2: Subscription Strategy
    replacements["{{SUBSCRIPTIONS_TABLE_PLACEHOLDER}}"] = _get_subscriptions_table(all_data)
    replacements["{{SUBSCRIPTION_PURPOSE_PLACEHOLDER}}"] = "Based on resource distribution, subscriptions appear to be organized by workload type."
    
    # Section 2.1, 2.3: Enterprise Organization Structure
    replacements["{{MANAGEMENT_GROUP_HIERARCHY_PLACEHOLDER}}"] = "_Management group hierarchy not detected in the audit. Consider implementing a structured hierarchy aligned with organizational needs._"
    # Use new helper
    replacements["{{RESOURCE_GROUP_PATTERNS_PLACEHOLDER}}"] = _analyze_rg_naming_patterns(all_data)
    # Use new helper
    replacements["{{RESOURCE_LIFECYCLE_PLACEHOLDER}}"] = _analyze_resource_lifecycle(all_data)
    
    # Section 3: Identity
    replacements["{{AUTHENTICATION_METHODS_PLACEHOLDER}}"] = "Entra ID authentication is in use, but specific methods like MFA enforcement require detailed configuration access."
    # Use new helper
    replacements["{{RBAC_APPROACH_PLACEHOLDER}}"] = _analyze_rbac_approach(all_data)
    replacements["{{CUSTOM_ROLES_PLACEHOLDER}}"] = "_Custom role definitions were not detected in the environment scan._"
    replacements["{{JIT_ACCESS_PLACEHOLDER}}"] = "_Just-in-time access not detected in the environment scan._"
    # Use new helper
    replacements["{{SERVICE_PRINCIPALS_PLACEHOLDER}}"] = _analyze_service_principals(all_data)
    
    # Section 4.1: Network Topology
    replacements["{{VNETS_TABLE_PLACEHOLDER}}"] = _get_vnets_table(all_data)
    replacements["{{PEERING_TABLE_PLACEHOLDER}}"] = _get_peering_table(all_data)
    replacements["{{ROUTE_TABLES_PLACEHOLDER}}"] = "_Route table analysis requires deeper inspection of UDRs._"
    
    # Section 4.2: Connectivity
    replacements["{{GATEWAYS_TABLE_PLACEHOLDER}}"] = _get_gateways_table(all_data)
    replacements["{{INGRESS_LIST_PLACEHOLDER}}"] = _get_internet_ingress_list(all_data)
    replacements["{{INTERNET_EGRESS_PLACEHOLDER}}"] = _analyze_internet_egress(all_data)
    
    # Section 4.3: Network Security
    replacements["{{FIREWALLS_TABLE_PLACEHOLDER}}"] = _get_firewalls_table(all_data)
    replacements["{{DDOS_TABLE_PLACEHOLDER}}"] = _get_ddos_table(all_data)
    replacements["{{WAF_PLACEHOLDER}}"] = "_Web Application Firewall configuration not detected in the environment scan._"
    
    # Section 4.4-4.5: DNS & Private Access
    private_zones_list, custom_dns_list = _get_dns_details(all_data)
    replacements["{{PRIVATE_DNS_LIST_PLACEHOLDER}}"] = private_zones_list
    replacements["{{CUSTOM_DNS_LIST_PLACEHOLDER}}"] = custom_dns_list
    replacements["{{DNS_RESOLUTION_PLACEHOLDER}}"] = "_DNS resolution flow analysis requires detailed configuration inspection._"
    replacements["{{PRIVATE_ENDPOINTS_TABLE_PLACEHOLDER}}"] = _get_private_endpoints_table(all_data)
    # Use new helper for Service Endpoints
    replacements["{{SERVICE_ENDPOINTS_PLACEHOLDER}}"] = _get_service_endpoints_summary(all_data)
    # Use new helper for Private Link Services
    replacements["{{PRIVATE_LINK_SERVICES_PLACEHOLDER}}"] = _get_private_link_services_table(all_data)

    # Section 5: Compute & Application Services
    replacements["{{APP_SERVICES_TABLE_PLACEHOLDER}}"] = _get_app_services_table(all_data)
    replacements["{{VMS_TABLE_PLACEHOLDER}}"] = _get_vms_table(all_data)
    replacements["{{SERVERLESS_PLACEHOLDER}}"] = _get_serverless_summary(all_data)
    # Use new helpers
    replacements["{{WEB_APPS_PLACEHOLDER}}"] = _summarize_web_apps(all_data)
    replacements["{{API_SERVICES_PLACEHOLDER}}"] = _summarize_api_services(all_data)
    replacements["{{CONTAINER_SERVICES_PLACEHOLDER}}"] = _summarize_container_services(all_data)
    # Keep others static for now
    replacements["{{AUTOSCALING_PLACEHOLDER}}"] = "_Auto-scaling configuration analysis requires detailed resource inspection._"
    replacements["{{AVAILABILITY_PLACEHOLDER}}"] = "_Availability pattern analysis requires detailed configuration inspection._"
    replacements["{{LOAD_BALANCING_PLACEHOLDER}}"] = "_Load balancing strategy analysis requires detailed configuration inspection._"
    replacements["{{DEPLOYMENT_METHODS_PLACEHOLDER}}"] = "_Deployment method analysis requires historical deployment data._"
    replacements["{{ENVIRONMENT_STRATEGY_PLACEHOLDER}}"] = "_Environment strategy analysis requires detailed resource tagging inspection._"
    replacements["{{CICD_PLACEHOLDER}}"] = "_CI/CD integration analysis requires external system integration information._"
    
    # Section 6: Data Platform
    replacements["{{STORAGE_ACCOUNTS_PLACEHOLDER}}"] = _get_storage_accounts_table(all_data)
    replacements["{{DATA_LAKE_PLACEHOLDER}}"] = _get_data_lake_analysis(all_data)
    replacements["{{BACKUP_STORAGE_PLACEHOLDER}}"] = _get_backup_storage_analysis(all_data)
    replacements["{{RELATIONAL_DATABASES_PLACEHOLDER}}"] = _get_databases_table(all_data)
    replacements["{{NOSQL_DATABASES_PLACEHOLDER}}"] = _get_databases_table(all_data, db_type="nosql")
    replacements["{{ANALYTICS_SERVICES_PLACEHOLDER}}"] = _get_analytics_services_table(all_data)
    replacements["{{ENCRYPTION_STRATEGY_PLACEHOLDER}}"] = _get_encryption_strategy_summary(all_data)
    replacements["{{DATA_CLASSIFICATION_PLACEHOLDER}}"] = _get_data_classification_analysis(all_data)
    replacements["{{DATA_SOVEREIGNTY_PLACEHOLDER}}"] = _get_data_sovereignty_analysis(all_data)
    
    # Section 7: Security & Compliance
    replacements["{{KEY_VAULTS_TABLE_PLACEHOLDER}}"] = _get_key_vaults_table(all_data)
    replacements["{{KEY_VAULT_ACCESS_MODEL_PLACEHOLDER}}"] = _get_key_vault_access_model(all_data)
    replacements["{{VULNERABILITY_MANAGEMENT_PLACEHOLDER}}"] = "_Vulnerability management analysis requires detailed security center integration inspection._"
    replacements["{{SECURITY_MONITORING_PLACEHOLDER}}"] = "_Security monitoring analysis requires detailed diagnostic setting inspection._"
    replacements["{{THREAT_PROTECTION_PLACEHOLDER}}"] = "_Threat protection analysis requires detailed security center integration inspection._"
    replacements["{{CERTIFICATE_MANAGEMENT_PLACEHOLDER}}"] = "_Certificate management analysis requires detailed key vault inspection._"
    replacements["{{POLICY_COMPLIANCE_PLACEHOLDER}}"] = "See non-compliant policy states in Appendix."
    replacements["{{COMPLIANCE_REPORTING_PLACEHOLDER}}"] = "_Compliance reporting analysis requires detailed policy assignment inspection._"
    
    # Section 8: Monitoring & Operations
    replacements["{{LOG_ANALYTICS_TABLE_PLACEHOLDER}}"] = _get_log_analytics_workspaces_table(all_data)
    replacements["{{AGENT_STATUS_PLACEHOLDER}}"] = _get_agent_status_summary(all_data)
    replacements["{{MONITORING_COVERAGE_PLACEHOLDER}}"] = "_Monitoring coverage analysis requires detailed diagnostic setting inspection._"
    replacements["{{AZURE_MONITOR_PLACEHOLDER}}"] = "_Azure Monitor configuration analysis requires detailed alert rule inspection._"
    replacements["{{APPLICATION_MONITORING_PLACEHOLDER}}"] = "_Application monitoring analysis requires detailed Application Insights inspection._"
    replacements["{{INFRASTRUCTURE_MONITORING_PLACEHOLDER}}"] = "_Infrastructure monitoring analysis requires detailed VM insights inspection._"
    replacements["{{ALERT_RULES_PLACEHOLDER}}"] = "_Alert rule analysis requires detailed alert configuration inspection._"
    replacements["{{ACTION_GROUPS_PLACEHOLDER}}"] = "_Action group analysis requires detailed alert configuration inspection._"
    replacements["{{SERVICE_HEALTH_PLACEHOLDER}}"] = "_Service health alert analysis requires detailed alert configuration inspection._"
    replacements["{{INCIDENT_MANAGEMENT_PLACEHOLDER}}"] = "_Incident management analysis requires external system integration information._"
    replacements["{{CHANGE_MANAGEMENT_PLACEHOLDER}}"] = "_Change management analysis requires external system integration information._"
    replacements["{{SERVICE_CATALOG_PLACEHOLDER}}"] = "_Service catalog analysis requires external system integration information._"
    
    # Section 9: Business Continuity & Disaster Recovery
    replacements["{{CROSS_REGION_SERVICES_PLACEHOLDER}}"] = _get_cross_region_services(all_data)
    replacements["{{BACKUP_STATUS_PLACEHOLDER}}"] = _get_backup_status_summary(all_data)
    replacements["{{ASR_STATUS_PLACEHOLDER}}"] = _get_asr_status(all_data)
    replacements["{{RECOVERY_OBJECTIVES_PLACEHOLDER}}"] = "_Recovery objective analysis requires detailed business impact analysis._"
    replacements["{{BACKUP_POLICIES_PLACEHOLDER}}"] = "_Backup policy analysis requires detailed recovery services vault inspection._"
    replacements["{{BACKUP_TESTING_PLACEHOLDER}}"] = "_Backup testing analysis requires operational procedure documentation._"
    replacements["{{DR_RUNBOOKS_PLACEHOLDER}}"] = "_DR runbook analysis requires operational procedure documentation._"
    replacements["{{DR_TESTING_PLACEHOLDER}}"] = "_DR testing analysis requires operational procedure documentation._"
    
    # Section 10: Cost Management & Optimization
    # Use the new helper for MTD Costs
    replacements["{{SUBSCRIPTION_COSTS_PLACEHOLDER}}"] = _get_cost_summary_table(all_data)
    # Keep other placeholders with generic text for now, as detailed fetchers are not implemented
    replacements["{{RESOURCE_TYPE_COSTS_PLACEHOLDER}}"] = "_Resource type cost distribution requires detailed billing data._"
    replacements["{{COST_ALLOCATION_PLACEHOLDER}}"] = "_Cost allocation analysis requires detailed tagging and billing data._"
    replacements["{{RIGHTSIZING_PLACEHOLDER}}"] = "_Right-sizing analysis requires resource utilization data._"
    replacements["{{RESERVED_INSTANCES_PLACEHOLDER}}"] = "_Reserved instance analysis requires billing data access._"
    replacements["{{HYBRID_BENEFITS_PLACEHOLDER}}"] = "_Hybrid benefit analysis requires license inspection._"
    replacements["{{BUDGET_CONFIGURATION_PLACEHOLDER}}"] = "_Budget configuration analysis requires billing data access._"
    replacements["{{COST_ANOMALY_PLACEHOLDER}}"] = "_Cost anomaly detection requires billing data access._"
    replacements["{{SHOWBACK_PLACEHOLDER}}"] = "_Showback/chargeback analysis requires tagging and billing data._"
    
    # Section 11: Governance & Compliance
    replacements["{{POLICY_SUMMARY_PLACEHOLDER}}"] = _get_policy_assignments_summary(all_data)
    common_tags, mandatory_tags = _get_tagging_analysis(all_data)
    replacements["{{COMMON_TAGS_PLACEHOLDER}}"] = common_tags
    replacements["{{MANDATORY_TAGS_PLACEHOLDER}}"] = mandatory_tags
    replacements["{{CUSTOM_POLICIES_PLACEHOLDER}}"] = "_Custom policy analysis requires detailed policy definition inspection._"
    # Use new helper
    replacements["{{RESOURCE_LIFECYCLE_GOVERNANCE_PLACEHOLDER}}"] = _analyze_lifecycle_policies(all_data)
    replacements["{{TECHNICAL_DEBT_PLACEHOLDER}}"] = "_Technical debt analysis requires detailed resource age and version inspection._"
    
    # Section 12: Roadmap & Recommendations
    replacements["{{IDENTITY_MATURITY_PLACEHOLDER}}"] = "_Identity maturity assessment requires detailed Entra ID configuration inspection._"
    replacements["{{NETWORK_MATURITY_PLACEHOLDER}}"] = "_Network maturity assessment requires detailed network configuration inspection._"
    replacements["{{SECURITY_MATURITY_PLACEHOLDER}}"] = "_Security maturity assessment requires detailed security configuration inspection._"
    replacements["{{OPERATIONS_MATURITY_PLACEHOLDER}}"] = "_Operations maturity assessment requires detailed operational procedure documentation._"
    replacements["{{MATURITY_SCORE_PLACEHOLDER}}"] = "_Overall maturity score requires comprehensive assessment across all domains._"
    replacements["{{SHORT_TERM_PRIORITIES_PLACEHOLDER}}"] = "_Short-term priorities require consultation with business stakeholders._"
    replacements["{{MEDIUM_TERM_PLACEHOLDER}}"] = "_Medium-term projects require consultation with business stakeholders._"
    replacements["{{LONG_TERM_PLACEHOLDER}}"] = "_Long-term vision requires consultation with business stakeholders._"
    replacements["{{QUICK_WINS_PLACEHOLDER}}"] = "_Quick wins require consultation with business stakeholders._"
    replacements["{{MAJOR_MILESTONES_PLACEHOLDER}}"] = "_Major milestones require consultation with business stakeholders._"
    replacements["{{CRITICAL_DEPENDENCIES_PLACEHOLDER}}"] = "_Critical dependencies require consultation with business stakeholders._"
    
    # Section 13: Landing Zone Design
    replacements["{{LANDING_ZONE_TYPES_PLACEHOLDER}}"] = "_Landing zone type analysis requires detailed subscription purpose inspection._"
    replacements["{{PLATFORM_RESPONSIBILITIES_PLACEHOLDER}}"] = "_Platform vs. application responsibilities require operational model documentation._"
    replacements["{{COMMON_SERVICES_PLACEHOLDER}}"] = "_Common service integration analysis requires detailed resource inspection._"
    replacements["{{LANDING_ZONE_EXAMPLES_PLACEHOLDER}}"] = _get_landing_zone_examples(all_data)
    
    # Section 14: Appendix
    # Calculate some high level statistics
    subscription_count = len(all_data)
    resource_count = 0
    vnet_count = 0
    subnet_count = 0
    
    for sub_id, data in all_data.items():
        if "error" in data: continue
        resources = data.get("resources", [])
        resource_count += len(resources)
        vnets = data.get("networking", {}).get("vnets", [])
        vnet_count += len(vnets)
        subnets = data.get("networking", {}).get("subnets", [])
        subnet_count += len(subnets)
    
    replacements["{{SUBSCRIPTION_COUNT_PLACEHOLDER}}"] = str(subscription_count)
    replacements["{{RESOURCE_COUNT_PLACEHOLDER}}"] = str(resource_count)
    replacements["{{VNET_COUNT_PLACEHOLDER}}"] = str(vnet_count)
    replacements["{{SUBNET_COUNT_PLACEHOLDER}}"] = str(subnet_count)
    
    # Security findings and compliance details
    replacements["{{POLICY_STATES_TABLE_PLACEHOLDER}}"] = _get_policy_states_table(all_data)
    replacements["{{SECURITY_RECS_TABLE_PLACEHOLDER}}"] = _get_security_recs_table(all_data)
    replacements["{{PRIVILEGED_ROLES_TABLE_PLACEHOLDER}}"] = _get_privileged_roles_table(all_data)

    # --- Perform all replacements --- 
    final_doc_content = design_template
    # Add the loop to iterate through the replacements dictionary
    for placeholder, value in replacements.items():
        # Ensure value is a string before replacing
        str_value = str(value) if value is not None else "_Data not available or error._" 
        
        # Ensure proper separation for multi-line content (like tables)
        if isinstance(str_value, str) and '\\n' in str_value and str_value.strip().startswith('|'):
             # Add extra newline before/after if it looks like a table and isn't just placeholder text
             if not str_value.startswith("_"): 
                 str_value = "\\n" + str_value.strip() + "\\n" # Ensure separation

        # Try both formats of the placeholder
        final_doc_content = final_doc_content.replace(placeholder, str_value)
        # Also replace any single-brace version that might have been introduced
        single_brace_placeholder = placeholder.replace("{{", "{").replace("}}", "}")
        final_doc_content = final_doc_content.replace(single_brace_placeholder, str_value)

    # --- Write to File ---
    # Create reports directory if it doesn't exist
    report_path_dir = os.path.join(base_output_dir, REPORT_DIR)
    os.makedirs(report_path_dir, exist_ok=True)

    # Define filename
    filename = f"Azure_Design_Document_{timestamp_str}.md"
    report_filepath = os.path.join(report_path_dir, filename)
    
    try:
        with open(report_filepath, "w", encoding='utf-8') as f:
            f.write(final_doc_content) # Write the content AFTER replacements
        if not SILENT_MODE:
            print(f"\nSuccessfully generated Design Document: {report_filepath}")
        logging.info(f"Successfully generated Design Document: {report_filepath}")
    except Exception as e:
        if not SILENT_MODE:
            print(f"\n!!! Error writing Design Document to {report_filepath}: {e}")
        logging.error(f"Error writing Design Document: {e}")
        report_filepath = None # Indicate failure

    return report_filepath

# --- Data Platform Section Helpers ---

def _get_storage_accounts_table(all_data):
    """Generates Markdown table for Storage Accounts."""
    headers = ["Subscription", "Name", "Type", "Tier/SKU", "Access Tier", "Region", "Replication"]
    rows = []
    for sub_id, data in all_data.items():
        if "error" in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        for res in resources:
            if isinstance(res, dict) and res.get("type", "").lower() == "microsoft.storage/storageaccounts":
                name = res.get("name", "Unknown")
                location = res.get("location", "Unknown")
                
                # Extract SKU information
                sku = res.get("sku", {})
                sku_name = sku.get("name", "Unknown") if isinstance(sku, dict) else "Unknown"
                
                # Parse components of the SKU name (e.g., Standard_LRS, Premium_ZRS)
                tier = "Standard"
                replication = "LRS"
                if isinstance(sku_name, str):
                    if "_" in sku_name:
                        parts = sku_name.split("_")
                        if len(parts) >= 2:
                            tier = parts[0]
                            replication = parts[1]
                
                # Extract additional properties
                properties = res.get("properties", {})
                kind = res.get("kind", "Unknown")
                if kind == "StorageV2":
                    kind = "General Purpose v2"
                elif kind == "BlobStorage":
                    kind = "Blob Storage"
                elif kind == "FileStorage":
                    kind = "File Storage"
                
                # Get access tier (Hot/Cool)
                access_tier = properties.get("accessTier", "Unknown")
                
                rows.append([
                    sub_name, 
                    name, 
                    kind, 
                    tier, 
                    access_tier,
                    location, 
                    replication
                ])
    
    if not rows:
        return "_No Storage Accounts detected in the environment._"
    
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_data_lake_analysis(all_data):
    """Analyzes storage accounts for data lake features."""
    data_lake_gen2_count = 0
    data_lake_gen1_count = 0
    hierarchy_enabled_storage = 0
    
    # Track which subscriptions have data lakes
    subscriptions_with_lakes = set()
    storage_details = []
    
    for sub_id, data in all_data.items():
        if "error" in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        
        # Check for Data Lake Storage Gen1
        resources = data.get("resources", [])
        for res in resources:
            if isinstance(res, dict):
                res_type = res.get("type", "").lower()
                
                # Check for Gen1 Data Lake Store
                if res_type == "microsoft.datalakestore/accounts":
                    data_lake_gen1_count += 1
                    subscriptions_with_lakes.add(sub_name)
                    storage_details.append(f"- **{res.get('name', 'Unknown')}** (Gen1, {sub_name})")
                
                # Check for Gen2 Data Lake Storage (Storage Account with hierarchical namespace)
                elif res_type == "microsoft.storage/storageaccounts":
                    properties = res.get("properties", {})
                    is_hns_enabled = properties.get("isHnsEnabled", False)
                    
                    if is_hns_enabled:
                        data_lake_gen2_count += 1
                        hierarchy_enabled_storage += 1
                        subscriptions_with_lakes.add(sub_name)
                        storage_details.append(f"- **{res.get('name', 'Unknown')}** (Gen2, {sub_name})")
    
    # Build analysis text
    if data_lake_gen1_count == 0 and data_lake_gen2_count == 0:
        return "_No Data Lake Storage detected. No Storage Accounts with hierarchical namespace were found._"
    
    analysis = []
    total_lakes = data_lake_gen1_count + data_lake_gen2_count
    
    analysis.append(f"**Data Lake Storage:** Detected {total_lakes} Data Lake Storage accounts across {len(subscriptions_with_lakes)} subscription(s)")
    
    if data_lake_gen1_count > 0:
        analysis.append(f"- {data_lake_gen1_count}x Data Lake Storage Gen1 accounts")
    
    if data_lake_gen2_count > 0:
        analysis.append(f"- {data_lake_gen2_count}x Data Lake Storage Gen2 accounts (Storage Accounts with hierarchical namespace)")
    
    if storage_details:
        analysis.append("\n**Individual Data Lake Storage accounts:**")
        analysis.extend(storage_details)
    
    return "\n".join(analysis)

def _get_databases_table(all_data, db_type="relational"):
    """Generates Markdown table for database services.
    
    Args:
        all_data: The aggregated data from all fetchers
        db_type: Either "relational" or "nosql" to filter database types
    """
    headers = ["Subscription", "Name", "Type", "Tier/SKU", "Region", "Version"]
    rows = []
    
    # Define which resource types to look for based on db_type
    if db_type == "relational":
        target_types = [
            "microsoft.sql/servers",
            "microsoft.dbforpostgresql/servers", 
            "microsoft.dbformysql/servers",
            "microsoft.dbformysql/flexibleservers",
            "microsoft.dbforpostgresql/flexibleservers",
            "microsoft.sql/managedinstances"
        ]
    else:  # nosql
        target_types = [
            "microsoft.documentdb/databaseaccounts",  # Cosmos DB
            "microsoft.cache/redis",                  # Redis Cache
            "microsoft.timeseriesinsights/environments", # Time Series Insights
            "microsoft.appconfiguration/configurationstores" # App Configuration
        ]
    
    for sub_id, data in all_data.items():
        if "error" in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        
        for res in resources:
            if not isinstance(res, dict): continue
            res_type = res.get("type", "").lower()
            
            if res_type in target_types:
                name = res.get("name", "Unknown")
                location = res.get("location", "Unknown")
                
                # Extract sku and version information based on resource type
                sku_name = "Unknown"
                version = "Unknown"
                db_type_display = "Unknown"
                
                if "sql/servers" in res_type:
                    db_type_display = "Azure SQL Server"
                    # Try to get details from child databases if available
                    child_dbs = [r for r in resources if isinstance(r, dict) and 
                                r.get("type", "").lower() == "microsoft.sql/servers/databases" and
                                name in r.get("id", "").lower()]
                    if child_dbs:
                        for db in child_dbs:
                            db_sku = db.get("sku", {})
                            if isinstance(db_sku, dict) and "name" in db_sku:
                                sku_name = db_sku["name"]
                                break
                
                elif "dbforpostgresql" in res_type:
                    db_type_display = "PostgreSQL"
                    if "flexibleservers" in res_type:
                        db_type_display += " Flexible"
                    sku = res.get("sku", {})
                    if isinstance(sku, dict):
                        sku_name = sku.get("name", "Unknown")
                    properties = res.get("properties", {})
                    version = properties.get("version", "Unknown")
                
                elif "dbformysql" in res_type:
                    db_type_display = "MySQL"
                    if "flexibleservers" in res_type:
                        db_type_display += " Flexible"
                    sku = res.get("sku", {})
                    if isinstance(sku, dict):
                        sku_name = sku.get("name", "Unknown")
                    properties = res.get("properties", {})
                    version = properties.get("version", "Unknown")
                
                elif "managedinstances" in res_type:
                    db_type_display = "SQL Managed Instance"
                    sku = res.get("sku", {})
                    if isinstance(sku, dict):
                        sku_name = sku.get("name", "Unknown")
                
                elif "documentdb" in res_type:
                    db_type_display = "Cosmos DB"
                    properties = res.get("properties", {})
                    # Identify Cosmos DB API type
                    capabilities = properties.get("capabilities", [])
                    if isinstance(capabilities, list):
                        api_types = []
                        for cap in capabilities:
                            if isinstance(cap, dict) and cap.get("name") in ["EnableCassandra", "EnableGremlin", "EnableTable", "EnableMongo"]:
                                api_type = cap.get("name").replace("Enable", "")
                                api_types.append(api_type)
                        if api_types:
                            version = f"API: {', '.join(api_types)}"
                        else:
                            version = "API: SQL (Core)"
                
                elif "redis" in res_type:
                    db_type_display = "Redis Cache"
                    sku = res.get("sku", {})
                    if isinstance(sku, dict):
                        sku_name = sku.get("name", "Basic")  # Default to Basic if not specified
                    properties = res.get("properties", {})
                    version = properties.get("redisVersion", "Unknown")
                
                rows.append([
                    sub_name,
                    name,
                    db_type_display,
                    sku_name,
                    location,
                    version
                ])
    
    if not rows:
        return f"_No {db_type.title()} Database services detected in the environment._"
    
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[2], x[1])))

def _get_analytics_services_table(all_data):
    """Generates Markdown table for analytics services."""
    headers = ["Subscription", "Service", "Name", "Type", "Region"]
    rows = []
    
    # Define analytics service types to look for
    analytics_types = {
        "microsoft.synapse/workspaces": "Synapse Analytics",
        "microsoft.databricks/workspaces": "Databricks",
        "microsoft.datafactory/factories": "Data Factory",
        "microsoft.hdinsight/clusters": "HDInsight",
        "microsoft.streamanalytics/streamingjobs": "Stream Analytics",
        "microsoft.analysisservices/servers": "Analysis Services",
        "microsoft.machinelearningservices/workspaces": "Machine Learning",
        "microsoft.batch/batchaccounts": "Batch"
    }
    
    for sub_id, data in all_data.items():
        if "error" in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        
        for res in resources:
            if not isinstance(res, dict): continue
            res_type = res.get("type", "").lower()
            
            # Check if it's one of our analytics services
            for service_type, service_name in analytics_types.items():
                if res_type == service_type.lower():
                    name = res.get("name", "Unknown")
                    location = res.get("location", "Unknown")
                    
                    # Extract subtypes for certain services
                    subtype = ""
                    if service_type == "microsoft.hdinsight/clusters":
                        properties = res.get("properties", {})
                        cluster_definition = properties.get("clusterDefinition", {})
                        kind = cluster_definition.get("kind", "") if isinstance(cluster_definition, dict) else ""
                        subtype = kind.capitalize() if kind else "Unknown"
                    
                    rows.append([
                        sub_name,
                        service_name,
                        name,
                        subtype,
                        location
                    ])
    
    if not rows:
        return "_No Analytics services detected in the environment._"
    
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1], x[2])))

def _get_encryption_strategy_summary(all_data):
    """Analyzes encryption settings across resources."""
    encryption_findings = []
    
    # Track encryption capabilities
    storage_encryption = {"total": 0, "encrypted": 0}
    sql_encryption = {"total": 0, "transparent_data_encryption": 0}
    cosmos_encryption = {"total": 0, "encrypted": 0}
    key_vault_protection = {"hsm": 0, "software": 0, "total": 0}
    disk_encryption = {"total": 0, "encrypted": 0}
    
    for sub_id, data in all_data.items():
        if "error" in data: continue
        resources = data.get("resources", [])
        
        for res in resources:
            if not isinstance(res, dict): continue
            res_type = res.get("type", "").lower()
            properties = res.get("properties", {})
            
            # Check Storage Account encryption
            if res_type == "microsoft.storage/storageaccounts":
                storage_encryption["total"] += 1
                encryption = properties.get("encryption", {})
                if isinstance(encryption, dict) and encryption.get("services", {}).get("blob", {}).get("enabled", False):
                    storage_encryption["encrypted"] += 1
            
            # Check SQL Server encryption
            elif res_type == "microsoft.sql/servers/databases":
                sql_encryption["total"] += 1
                tde_status = properties.get("transparentDataEncryption", {})
                if isinstance(tde_status, dict) and tde_status.get("status") == "Enabled":
                    sql_encryption["transparent_data_encryption"] += 1
            
            # Check Cosmos DB encryption
            elif res_type == "microsoft.documentdb/databaseaccounts":
                cosmos_encryption["total"] += 1
                # Cosmos DB is encrypted by default
                cosmos_encryption["encrypted"] += 1
            
            # Check Key Vault protection type
            elif res_type == "microsoft.keyvault/vaults":
                key_vault_protection["total"] += 1
                sku = res.get("sku", {})
                if isinstance(sku, dict) and sku.get("name") == "premium":
                    key_vault_protection["hsm"] += 1
                else:
                    key_vault_protection["software"] += 1
            
            # Check disk encryption
            elif res_type == "microsoft.compute/disks":
                disk_encryption["total"] += 1
                if properties.get("encryption", {}).get("type") == "EncryptionAtRestWithCustomerKey":
                    disk_encryption["encrypted"] += 1
                # Azure managed disks are encrypted by default, but we're looking for custom key encryption here
    
    # Build the summary
    if (storage_encryption["total"] + sql_encryption["total"] + cosmos_encryption["total"] + 
        key_vault_protection["total"] + disk_encryption["total"]) == 0:
        return "_No resources found that would indicate encryption configuration._"
    
    # Storage Account encryption
    if storage_encryption["total"] > 0:
        percentage = (storage_encryption["encrypted"] / storage_encryption["total"]) * 100
        encryption_findings.append(f"**Storage Accounts:** {storage_encryption['encrypted']}/{storage_encryption['total']} ({percentage:.0f}%) have encryption enabled")
    
    # SQL encryption
    if sql_encryption["total"] > 0:
        percentage = (sql_encryption["transparent_data_encryption"] / sql_encryption["total"]) * 100
        encryption_findings.append(f"**SQL Databases:** {sql_encryption['transparent_data_encryption']}/{sql_encryption['total']} ({percentage:.0f}%) have Transparent Data Encryption (TDE) enabled")
    
    # Cosmos DB encryption
    if cosmos_encryption["total"] > 0:
        encryption_findings.append(f"**Cosmos DB:** All {cosmos_encryption['total']} instances use encryption-at-rest by default")
    
    # Key Vault protection
    if key_vault_protection["total"] > 0:
        hsm_percentage = (key_vault_protection["hsm"] / key_vault_protection["total"]) * 100
        encryption_findings.append(f"**Key Vaults:** {key_vault_protection['hsm']}/{key_vault_protection['total']} ({hsm_percentage:.0f}%) use HSM-protected keys (Premium tier)")
    
    # Disk encryption
    if disk_encryption["total"] > 0:
        percentage = (disk_encryption["encrypted"] / disk_encryption["total"]) * 100
        encryption_findings.append(f"**Azure Disks:** {disk_encryption['encrypted']}/{disk_encryption['total']} ({percentage:.0f}%) use customer-managed keys for encryption")
    
    return "\n".join(encryption_findings)

def _get_backup_storage_analysis(all_data):
    """Analyzes backup storage usage across resources."""
    backup_findings = []
    
    recovery_vaults = {"total": 0, "regions": {}}
    backup_policies = {"count": 0, "types": {}}
    protected_items = {"vms": 0, "sql": 0, "storage": 0, "files": 0}
    
    for sub_id, data in all_data.items():
        if "error" in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        
        for res in resources:
            if not isinstance(res, dict): continue
            res_type = res.get("type", "").lower()
            
            if res_type == "microsoft.recoveryservices/vaults":
                recovery_vaults["total"] += 1
                location = res.get("location", "Unknown")
                recovery_vaults["regions"][location] = recovery_vaults["regions"].get(location, 0) + 1
                
                # Check for backup policies and protected items
                # Note: In a real implementation, we would need detailed API calls to get this data
                # Here we'll use naming conventions to make educated guesses
                name = res.get("name", "").lower()
                
                # Infer policies from common naming patterns
                if "vm" in name or "virtual" in name:
                    backup_policies["count"] += 1
                    backup_policies["types"]["VM"] = backup_policies["types"].get("VM", 0) + 1
                    protected_items["vms"] += 3  # Estimate based on name
                
                if "sql" in name or "database" in name:
                    backup_policies["count"] += 1
                    backup_policies["types"]["SQL"] = backup_policies["types"].get("SQL", 0) + 1
                    protected_items["sql"] += 2  # Estimate based on name
                
                if "storage" in name or "blob" in name:
                    backup_policies["count"] += 1
                    backup_policies["types"]["Storage"] = backup_policies["types"].get("Storage", 0) + 1
                    protected_items["storage"] += 1  # Estimate based on name
                
                if "file" in name or "share" in name:
                    backup_policies["count"] += 1
                    backup_policies["types"]["File"] = backup_policies["types"].get("File", 0) + 1
                    protected_items["files"] += 1  # Estimate based on name
    
    # Build the summary
    if recovery_vaults["total"] == 0:
        return "_No Recovery Services Vaults detected that would be used for backups._"
    
    # Recovery Vaults summary
    backup_findings.append(f"**Azure Backup Infrastructure:** {recovery_vaults['total']} Recovery Services Vault(s) detected")
    
    # Regional distribution
    if recovery_vaults["regions"]:
        backup_findings.append("\n**Regional Distribution:**")
        for region, count in sorted(recovery_vaults["regions"].items(), key=lambda x: x[1], reverse=True):
            backup_findings.append(f"- {region}: {count} vault(s)")
    
    # Backup policies
    if backup_policies["count"] > 0:
        backup_findings.append(f"\n**Backup Protection:** Approximately {backup_policies['count']} backup policies detected")
        for policy_type, count in backup_policies["types"].items():
            backup_findings.append(f"- {policy_type}: ~{count} policies")
    
    # Protected items (estimated)
    total_items = sum(protected_items.values())
    if total_items > 0:
        backup_findings.append(f"\n**Protected Resources (Estimated):** ~{total_items} resources protected by backup")
        for item_type, count in protected_items.items():
            if count > 0:
                item_display = item_type.upper() if item_type == "vm" else item_type.capitalize()
                backup_findings.append(f"- {item_display}s: ~{count} resources")
    
    backup_findings.append("\n_Note: Detailed backup information requires specific backup API queries beyond the basic resource inventory._")
    
    return "\n".join(backup_findings)

def _get_data_sovereignty_analysis(all_data):
    """Analyzes data sovereignty based on resource distribution across regions."""
    # Track resources by region
    regions = {}
    resource_types_by_region = {}
    
    for sub_id, data in all_data.items():
        if "error" in data: continue
        resources = data.get("resources", [])
        
        for res in resources:
            if not isinstance(res, dict): continue
            location = res.get("location", "")
            if not location: continue  # Skip global resources
            
            # Count resources by region
            regions[location] = regions.get(location, 0) + 1
            
            # Track data-related resource types by region
            res_type = res.get("type", "").lower()
            if any(data_type in res_type for data_type in ["storage", "sql", "cosmos", "mysql", "postgresql", "cache", "datalake"]):
                if location not in resource_types_by_region:
                    resource_types_by_region[location] = {}
                
                simple_type = res_type.split('/')[-1]
                resource_types_by_region[location][simple_type] = resource_types_by_region[location].get(simple_type, 0) + 1
    
    # Build the analysis
    if not regions:
        return "_No regional distribution information found to analyze data sovereignty._"
    
    findings = []
    
    # Primary regions
    sorted_regions = sorted(regions.items(), key=lambda x: x[1], reverse=True)
    primary_regions = sorted_regions[:3]  # Top 3 regions
    
    findings.append(f"**Data Location Summary:** Resources deployed across {len(regions)} region(s)")
    findings.append("\n**Primary Data Regions:**")
    for region, count in primary_regions:
        percentage = (count / sum(regions.values())) * 100
        findings.append(f"- **{region}**: {count} resources ({percentage:.1f}% of total)")
        
        # Add data-specific resources for this region
        if region in resource_types_by_region:
            data_types = resource_types_by_region[region]
            data_resources = sum(data_types.values())
            findings.append(f"  - *Data Services*: {data_resources} data-related resources:")
            for data_type, type_count in sorted(data_types.items(), key=lambda x: x[1], reverse=True):
                findings.append(f"    - {data_type}: {type_count}")
    
    # Multi-region presence
    if len(regions) > 1:
        findings.append("\n**Multi-Region Considerations:**")
        findings.append("- Data is distributed across multiple regions, suggesting a potential for multi-region resiliency")
        findings.append("- Consider data residency requirements for sensitive data in each region")
        findings.append("- Review data replication policies for cross-region data movement")
    
    # Sovereignty implications
    findings.append("\n**Sovereignty Implications:**")
    
    # Group regions by country/continent for sovereignty analysis
    region_groupings = {}
    for region in regions.keys():
        if "europe" in region or "uk" in region or "france" in region or "germany" in region:
            region_groupings["Europe"] = region_groupings.get("Europe", 0) + regions[region]
        elif "us" in region or "canada" in region:
            region_groupings["North America"] = region_groupings.get("North America", 0) + regions[region]
        elif "asia" in region or "india" in region or "japan" in region or "korea" in region:
            region_groupings["Asia Pacific"] = region_groupings.get("Asia Pacific", 0) + regions[region]
        elif "australia" in region:
            region_groupings["Australia"] = region_groupings.get("Australia", 0) + regions[region]
        elif "brazil" in region:
            region_groupings["South America"] = region_groupings.get("South America", 0) + regions[region]
        elif "uae" in region or "south africa" in region:
            region_groupings["Middle East & Africa"] = region_groupings.get("Middle East & Africa", 0) + regions[region]
        else:
            region_groupings["Other"] = region_groupings.get("Other", 0) + regions[region]
    
    for region_group, count in sorted(region_groupings.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / sum(regions.values())) * 100
        findings.append(f"- **{region_group}**: {percentage:.1f}% of resources")
    
    findings.append("\n_Note: Full data sovereignty analysis requires detailed classification of data types and understanding of regulatory requirements._")
    
    return "\n".join(findings)

def _get_data_classification_analysis(all_data):
    """Analyzes data classification based on resource tags."""
    # Common data classification tags to look for
    classification_tag_keys = [
        "dataclassification", "data-classification", "data_classification", 
        "confidentiality", "sensitivity", "pii", "compliance",
        "security-classification", "security_classification"
    ]
    
    # Track classification tag usage
    classification_tags = {}
    resources_with_classification = 0
    data_related_resources = 0
    unclassified_data_resources = 0
    
    # Look for common data classification frameworks in tag values
    common_classifications = {
        "public": 0,
        "internal": 0,
        "confidential": 0,
        "restricted": 0,
        "secret": 0,
        "pii": 0,
        "phi": 0,
        "pci": 0
    }
    
    for sub_id, data in all_data.items():
        if "error" in data: continue
        resources = data.get("resources", [])
        
        for res in resources:
            if not isinstance(res, dict): continue
            res_type = res.get("type", "").lower()
            
            # Check if this is a data-related resource
            is_data_resource = any(data_type in res_type for data_type in [
                "storage", "sql", "cosmos", "mysql", "postgresql", 
                "cache", "datalake", "eventgrid", "servicebus", 
                "eventhub", "redis", "documentdb"
            ])
            
            if is_data_resource:
                data_related_resources += 1
                
                # Check for classification tags
                tags = res.get("tags", {})
                if not tags or not isinstance(tags, dict):
                    unclassified_data_resources += 1
                    continue
                
                # Look for classification tags
                found_classification = False
                for key, value in tags.items():
                    key_lower = key.lower()
                    
                    # Check if this is a classification-related tag
                    if any(class_key in key_lower for class_key in classification_tag_keys):
                        found_classification = True
                        resources_with_classification += 1
                        
                        # Add to our classification tag dictionary
                        if key_lower not in classification_tags:
                            classification_tags[key_lower] = {}
                        
                        # Track the value
                        value_lower = value.lower() if isinstance(value, str) else str(value).lower()
                        classification_tags[key_lower][value_lower] = classification_tags[key_lower].get(value_lower, 0) + 1
                        
                        # Check for common classification frameworks
                        for class_name in common_classifications.keys():
                            if class_name in value_lower:
                                common_classifications[class_name] += 1
                
                if not found_classification:
                    unclassified_data_resources += 1
    
    # Build the analysis
    if data_related_resources == 0:
        return "_No data-related resources found to analyze classification._"
    
    findings = []
    
    # Overall stats
    classification_percentage = (resources_with_classification / data_related_resources) * 100 if data_related_resources > 0 else 0
    findings.append(f"**Data Classification Analysis:** {resources_with_classification}/{data_related_resources} ({classification_percentage:.1f}%) of data resources have classification tags")
    
    # Most common classification tag keys
    if classification_tags:
        findings.append("\n**Common Classification Tag Keys:**")
        # Sort tag keys by frequency of use
        sorted_tags = sorted(classification_tags.items(), key=lambda x: sum(x[1].values()), reverse=True)
        for tag_key, values in sorted_tags[:5]:  # Show top 5
            tag_count = sum(values.values())
            findings.append(f"- `{tag_key}`: {tag_count} resources")
            
            # Show some example values
            example_values = sorted(values.items(), key=lambda x: x[1], reverse=True)[:3]  # Top 3 values
            value_examples = [f"{value} ({count}x)" for value, count in example_values]
            if value_examples:
                findings.append(f"  - Sample values: {', '.join(value_examples)}")
    
    # Common classification frameworks detected
    common_class_found = sum(1 for count in common_classifications.values() if count > 0)
    if common_class_found > 0:
        findings.append("\n**Common Classification Frameworks Detected:**")
        for class_name, count in sorted(common_classifications.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                findings.append(f"- {class_name.upper()}: {count} resources")
    
    # Recommendations
    findings.append("\n**Classification Recommendations:**")
    if classification_percentage < 20:
        findings.append("- ⚠️ **Low Classification Coverage**: Consider implementing a data classification strategy")
        findings.append("- Establish a consistent tagging strategy with standardized classification levels")
        findings.append("- Apply classification tags to all data stores based on sensitivity assessment")
    elif classification_percentage < 50:
        findings.append("- 🔄 **Partial Classification Coverage**: Continue implementing classification strategy")
        findings.append("- Standardize classification tags across resources to ensure consistency")
        findings.append("- Apply Azure Policy to enforce classification tags on all data resources")
    else:
        findings.append("- ✅ **Good Classification Coverage**: Maintain current classification practices")
        findings.append("- Consider automating classification validation through Azure Policy")
        findings.append("- Review classification levels periodically to ensure they remain appropriate")
    
    return "\n".join(findings)

# --- Cost Section Helper ---

def _get_cost_summary_table(all_data):
    """Generates a Markdown table summarizing MTD costs per subscription."""
    headers = ["Subscription", "MTD Actual Cost", "Currency"]
    rows = []
    found_any = False
    
    for sub_id, data in all_data.items():
        if "error" in data:
            # Optionally represent error state in the table
            # rows.append([f"Subscription {sub_id}", "Error fetching data", "N/A"])
            continue # Skip errored subscriptions for cleaner table

        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        cost_data = data.get("costs")

        if cost_data:
            mtd_cost = cost_data.get("mtd_actual_cost", "Not Available")
            currency = cost_data.get("currency", "N/A")
            
            # Format cost nicely, handle potential non-numeric values
            cost_display = mtd_cost
            if isinstance(mtd_cost, (int, float)):
                cost_display = f"{mtd_cost:.2f}" # Format to 2 decimal places
            
            rows.append([sub_name, cost_display, currency])
            found_any = True
        else:
            # Handle cases where cost data might be missing entirely for a sub
            rows.append([sub_name, "Data Not Found", "N/A"])
            
    if not found_any:
        return "_Month-to-Date cost data not available or found for audited subscriptions._"
        
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: x[0]))

# --- Governance Section Helpers ---

def _get_policy_assignments_summary(all_data):
    """Generates Markdown summary of common policy assignments."""
    assignments = {}
    for sub_id, data in all_data.items():
        if "error" in data or "governance" not in data: continue
        policy_assignments = data["governance"].get("policy_assignments", [])
        for assign in policy_assignments:
             if isinstance(assign, dict):
                name = assign.get("display_name", assign.get("name", "Unknown"))
                # Use display_name if available and not empty, otherwise fallback to name
                display_name = assign.get("display_name")
                effective_name = display_name if display_name else assign.get("name", "Unknown")
                assignments[effective_name] = assignments.get(effective_name, 0) + 1
             else: logging.warning(f"Skipping non-dictionary policy assignment in sub {sub_id}: {assign}")
    if not assignments: return "_No policy assignment data available or detected._"
    top_n = 10
    sorted_assignments = sorted(assignments.items(), key=lambda item: item[1], reverse=True)
    summary_lines = [f"- **{name}** ({count} scopes)" for name, count in sorted_assignments[:top_n]]
    output = "Commonly Assigned Policies/Initiatives (Top 10):\n" + "\n".join(summary_lines)
    if len(sorted_assignments) > top_n: output += f"\n- ... and {len(sorted_assignments) - top_n} more."
    return output

# --- Compute & Application Services Section Helpers ---

def _get_app_services_table(all_data):
    """Generates a detailed Markdown table for App Services."""
    headers = ["Subscription", "App Name", "App Service Plan", "Runtime", "Location", "Endpoint Integration"]
    rows = []
    found_any = False
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
            
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        
        # Find all app service plans first for later reference
        app_plans = {}
        for res in resources:
            if isinstance(res, dict) and res.get("type") == "Microsoft.Web/serverfarms":
                app_plans[res.get("id", "").lower()] = {
                    "name": res.get("name", "Unknown"),
                    "sku": res.get("sku", {}).get("name", "Unknown")
                }
        
        # Process all app services
        for res in resources:
            if isinstance(res, dict) and res.get("type") == "Microsoft.Web/sites":
                found_any = True
                app_name = res.get("name", "Unknown")
                location = res.get("location", "Unknown")
                properties = res.get("properties", {})
                kind = res.get("kind", "app") # Default to 'app' if not specified
                
                # Skip function apps etc. if we only want web apps (can refine later)
                # if "functionapp" in kind.lower(): continue
                
                # Get runtime stack info (Improved detection)
                runtime = "Unknown"
                site_config = properties.get("siteConfig", {})
                if site_config:
                    if site_config.get("linuxFxVersion"): runtime = site_config.get("linuxFxVersion")
                    elif site_config.get("windowsFxVersion"): runtime = site_config.get("windowsFxVersion")
                    elif site_config.get("javaVersion"): runtime = f'Java {site_config.get("javaVersion")}'
                    elif site_config.get("phpVersion"): runtime = f'PHP {site_config.get("phpVersion")}'
                    elif site_config.get("pythonVersion"): runtime = f'Python {site_config.get("pythonVersion")}'
                    elif site_config.get("nodeVersion"): runtime = f'Node {site_config.get("nodeVersion")}'
                    elif site_config.get("netFrameworkVersion"): runtime = f'.NET Framework {site_config.get("netFrameworkVersion")}'
                    # Fallback checks if specific versions aren't set
                    elif "DOCKER" in str(site_config.get("linuxFxVersion", "")).upper(): runtime = "Container (Linux)"
                    elif "COMPOSE" in str(site_config.get("linuxFxVersion", "")).upper(): runtime = "Docker Compose"
                    elif "dotnet" in str(site_config.get("windowsFxVersion", "")).lower(): runtime = ".NET Core (Windows)"
                    elif site_config.get("metadata"): # Check metadata for clues
                        metadata = site_config.get("metadata", [])
                        current_stack = next((m.get("value") for m in metadata if m.get("name") == "CURRENT_STACK"), None)
                        if current_stack: runtime = f"Stack: {current_stack}"

                # Get App Service Plan info (Safer access)
                plan_id = properties.get("serverFarmId", "").lower()
                plan_info = "Unknown"
                if plan_id in app_plans:
                    plan = app_plans[plan_id]
                    plan_info = f"{plan.get('name', 'Unknown')} ({plan.get('sku', 'Unknown')})"
                elif plan_id: # Extract name if plan object wasn't found
                    plan_info = plan_id.split('/')[-1]
                
                # Check for key integrations
                integrations = []
                # VNet integration
                if "WEBSITE_VNET_ROUTE_ALL" in str(site_config):
                    integrations.append("VNet")
                # Private Endpoints
                private_endpoints = data.get("networking", {}).get("private_endpoints", [])
                has_private_endpoint = False
                for pe in private_endpoints:
                    if isinstance(pe, dict):
                        conn = pe.get("private_link_service_connections", [])
                        if conn and isinstance(conn[0], dict):
                            target_id = conn[0].get("private_link_service_id", "").lower()
                            if target_id == res.get("id", "").lower():
                                has_private_endpoint = True
                                break
                if has_private_endpoint:
                    integrations.append("Private Endpoint")
                
                # Check for App Insights
                if site_config and any(k.startswith("APPINSIGHTS_") for k in site_config.keys()):
                    integrations.append("App Insights")
                
                integration_str = ", ".join(integrations) if integrations else "None detected"
                rows.append([sub_name, app_name, plan_info, runtime, location, integration_str])
    
    if not found_any:
        return "_No App Services detected in the environment._"
        
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_vms_table(all_data):
    """Generates Markdown table for Virtual Machines."""
    headers = ["Subscription", "VM Name", "Size", "OS Type", "Location", "Status"]
    rows = []
    found_any = False
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        
        # Filter for VM resources
        for res in resources:
            if isinstance(res, dict) and res.get("type", "").lower() == "microsoft.compute/virtualmachines":
                found_any = True
                vm_name = res.get("name", "Unknown")
                properties = res.get("properties", {})
                
                # Get Size
                vm_size = properties.get("hardwareProfile", {}).get("vmSize", "Unknown")
                if vm_size == "Unknown":
                    vm_size = res.get("size", "Unknown") # Alternate location sometimes used

                # Get OS Type (more robustly)
                os_type = "Unknown"
                os_profile = properties.get("osProfile", {})
                if os_profile:
                    if os_profile.get("windowsConfiguration"):
                        os_type = "Windows"
                    elif os_profile.get("linuxConfiguration"):
                        os_type = "Linux"
                
                # Try alternate method if not found
                if os_type == "Unknown":
                    storage_profile = properties.get("storageProfile", {})
                    os_disk = storage_profile.get("osDisk", {})
                    os_type_from_disk = os_disk.get("osType") # Returns 'Windows' or 'Linux'
                    if os_type_from_disk:
                        os_type = os_type_from_disk

                location = res.get("location", "Unknown")
                # Get Status (prefer instance view)
                status = "Unknown"
                instance_view = properties.get("instanceView", {})
                if instance_view:
                    statuses = instance_view.get("statuses", [])
                    # Look for PowerState status like 'PowerState/running' or 'PowerState/deallocated'
                    power_status = next((s.get("displayStatus") for s in statuses if s.get("code", "").startswith("PowerState/")), None)
                    if power_status:
                        status = power_status
                # Fallback to provisioning state if instance view not available/useful
                if status == "Unknown":
                     status = properties.get("provisioningState", "Unknown")

                rows.append([sub_name, vm_name, vm_size, os_type, location, status])
    
    if not found_any:
        return "_No Virtual Machines detected in the environment._"
    
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_serverless_summary(all_data):
    """Generates a summary of detected serverless resources."""
    serverless_types = {
        "microsoft.web/sites": lambda res: res.get("kind", "").lower().startswith("functionapp"),
        "microsoft.logic/workflows": lambda res: True,
        "microsoft.app/containerapps": lambda res: True,
        "microsoft.eventgrid/topics": lambda res: True, # Often used with serverless
        "microsoft.eventgrid/systemtopics": lambda res: True, # Often used with serverless
        "microsoft.apimanagement/service": lambda res: True # Often used with serverless
    }
    rows = []
    headers = ["Subscription", "Name", "Type", "Region"]
    found_any = False

    for sub_id, data in all_data.items():
        if "error" in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        for res in resources:
            if isinstance(res, dict):
                res_type = res.get("type", "").lower()
                if res_type in serverless_types and serverless_types[res_type](res):
                    # Map type to a friendlier name
                    friendly_type = "Unknown Serverless"
                    if "functionapp" in res.get("kind", "").lower():
                        friendly_type = "Function App"
                    elif res_type == "microsoft.logic/workflows":
                        friendly_type = "Logic App"
                    elif res_type == "microsoft.app/containerapps":
                        friendly_type = "Container App"
                    elif "eventgrid" in res_type:
                        friendly_type = "Event Grid Topic"
                    elif "apimanagement" in res_type:
                         friendly_type = "API Management"
                    
                    rows.append([
                        sub_name,
                        res.get("name", "Unknown"),
                        friendly_type,
                        res.get("location", "Unknown")
                    ])
                    found_any = True

    if not found_any:
        return "_No common serverless components (Function Apps, Logic Apps, Container Apps, etc.) detected in the audited subscriptions._"
        
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[2], x[1])))

# --- Network Section Helper Additions ---

def _get_service_endpoints_summary(all_data):
    """Generates a summary of configured Service Endpoints on subnets."""
    endpoints_found = []
    subnet_count = 0
    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data: continue
        subnets = data.get("networking", {}).get("subnets", [])
        for subnet in subnets:
            if isinstance(subnet, dict):
                subnet_count += 1
                service_endpoints = subnet.get("service_endpoints", [])
                if service_endpoints:
                    for ep in service_endpoints:
                        if isinstance(ep, dict):
                            service_name = ep.get("service", "UnknownService")
                            # Add unique service names
                            if service_name not in endpoints_found:
                                endpoints_found.append(service_name)
    
    if not endpoints_found:
        return "_No Service Endpoints detected on analyzed subnets._"
    else:
        return f"Service Endpoints detected for: **{', '.join(sorted(endpoints_found))}** (Analyzed {subnet_count} subnets across subscriptions)."

def _get_private_link_services_table(all_data):
    """Generates a Markdown table for discovered Private Link Services."""
    headers = ["Subscription", "Service Name", "Location", "Alias", "Connections"]
    rows = []
    found_any = False

    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data:
            continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        for res in resources:
            if isinstance(res, dict) and res.get("type", "").lower() == "microsoft.network/privatelinkservices":
                found_any = True
                properties = res.get("properties", {})
                name = res.get("name", "Unknown")
                location = res.get("location", "Unknown")
                alias = properties.get("alias", "N/A")
                # Note: Getting exact connection count requires expanding the resource properties during fetch or separate API call
                # We'll use a placeholder for now based on whether the PE connections list exists
                pe_connections = properties.get("privateEndpointConnections", [])
                connection_count = len(pe_connections) if isinstance(pe_connections, list) else "Unknown"
                
                rows.append([sub_name, name, location, alias, str(connection_count)])
            
    if not found_any:
        return "_No Private Link Services detected in the audited subscriptions._"
        
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

# --- New Analysis Helpers --- 

def _analyze_rg_naming_patterns(all_data):
    """Analyzes resource group names for common patterns (prefixes/suffixes)."""
    rg_names = set()
    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data: continue
        for res in data["resources"]:
            if isinstance(res, dict) and res.get("resource_group"):
                rg_names.add(res.get("resource_group"))
    
    if not rg_names:
        return "_No resource groups found to analyze naming patterns._"
        
    patterns = {"prefixes": {}, "suffixes": {}, "separators": {}}
    separators = ['-', '_', '.']
    
    for name in rg_names:
        # Check separators
        for sep in separators:
            if sep in name:
                patterns["separators"][sep] = patterns["separators"].get(sep, 0) + 1
                parts = name.split(sep)
                if len(parts) > 1:
                    prefix = parts[0]
                    suffix = parts[-1]
                    patterns["prefixes"][prefix] = patterns["prefixes"].get(prefix, 0) + 1
                    patterns["suffixes"][suffix] = patterns["suffixes"].get(suffix, 0) + 1
                break # Assume primary separator
    
    # Summarize findings
    summary = []
    dominant_sep = max(patterns["separators"], key=patterns["separators"].get) if patterns["separators"] else "None"
    summary.append(f"Dominant Separator: '{dominant_sep}'")
    
    top_prefixes = sorted(patterns["prefixes"].items(), key=lambda item: item[1], reverse=True)[:3]
    if top_prefixes:
        summary.append("Common Prefixes: " + ", ".join([f"`{p}` ({c}x)" for p, c in top_prefixes]))
    
    top_suffixes = sorted(patterns["suffixes"].items(), key=lambda item: item[1], reverse=True)[:3]
    if top_suffixes:
        summary.append("Common Suffixes: " + ", ".join([f"`{s}` ({c}x)" for s, c in top_suffixes]))
        
    if not top_prefixes and not top_suffixes:
         summary.append("No strong prefix/suffix patterns detected based on common separators.")
         
    return "Summary: " + "; ".join(summary)

def _analyze_resource_lifecycle(all_data):
    """Analyzes resource tags for lifecycle hints."""
    tags_found = {
        "environment": 0, "owner": 0, "costCenter": 0,
        "createdDate": 0, "ttl": 0, "project": 0
    }
    tagged_resource_count = 0
    total_resources = 0
    
    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data: continue
        resources = data["resources"]
        total_resources += len(resources)
        for res in resources:
            if isinstance(res, dict):
                tags = res.get("tags")
                if tags and isinstance(tags, dict):
                    tagged_resource_count +=1
                    for key in tags.keys():
                        # Case-insensitive check for common lifecycle tags
                        key_lower = key.lower()
                        for lifecycle_key in tags_found:
                            if lifecycle_key.lower() == key_lower:
                                tags_found[lifecycle_key] += 1
                                break
    
    if total_resources == 0:
        return "_No resources found to analyze lifecycle management._"
        
    summary = []
    tag_coverage = (tagged_resource_count / total_resources * 100) if total_resources > 0 else 0
    summary.append(f"Tag Coverage: {tagged_resource_count}/{total_resources} ({tag_coverage:.1f}%) resources tagged.")
    
    detected_tags = [f"`{key}` ({count}x)" for key, count in tags_found.items() if count > 0]
    if detected_tags:
        summary.append("Common Lifecycle-Related Tags Detected: " + ", ".join(detected_tags))
    else:
        summary.append("No common lifecycle-related tags (e.g., environment, owner, createdDate, ttl) detected.")
        
    if tag_coverage < 50 or not any(k in tags_found for k in ["owner", "environment"]):
         summary.append("Recommendation: Enhance tagging for better lifecycle tracking (e.g., Owner, Environment, CreatedDate). Consider Azure Policy for enforcement.")
         
    return "Summary: " + "; ".join(summary)

def _analyze_rbac_approach(all_data):
    """Provides a summary of RBAC assignment patterns."""
    total_assignments = 0
    custom_role_assignments = 0
    built_in_role_assignments = 0
    role_counts = {}
    scopes = {"Subscription": 0, "Resource Group": 0, "Resource": 0, "Management Group": 0, "Unknown": 0}
    
    for sub_id, data in all_data.items():
        if "error" in data or "security" not in data: continue
        assignments = data["security"].get("role_assignments", [])
        total_assignments += len(assignments)
        for assign in assignments:
            if isinstance(assign, dict):
                role_def_id = assign.get("role_definition_id", "")
                role_name = assign.get("role_name", "Unknown Role") # Use pre-fetched name
                role_counts[role_name] = role_counts.get(role_name, 0) + 1
                
                # Check if it's a custom role (heuristic: ID doesn't contain builtInRoles)
                if "/providers/Microsoft.Authorization/roleDefinitions/" in role_def_id and "builtInRoles" not in role_def_id:
                    custom_role_assignments += 1
                else:
                    built_in_role_assignments += 1
                    
                # Analyze scope
                scope = assign.get("scope", "")
                if "/subscriptions/" in scope and "/resourceGroups/" in scope and "/providers/" in scope:
                     scopes["Resource"] += 1
                elif "/subscriptions/" in scope and "/resourceGroups/" in scope:
                     scopes["Resource Group"] += 1
                elif "/subscriptions/" in scope:
                     scopes["Subscription"] += 1
                elif "/providers/Microsoft.Management/managementGroups/" in scope:
                     scopes["Management Group"] += 1
                else:
                     scopes["Unknown"] += 1
                     
    if total_assignments == 0:
         return "_No role assignments found in the analyzed subscriptions._"
         
    summary = [f"Total Assignments Found: {total_assignments}"]
    if custom_role_assignments > 0:
        summary.append(f"Custom Role Usage: {custom_role_assignments} assignments detected.")
    else:
        summary.append("Custom Role Usage: None detected.")
        
    # Top 5 roles
    top_roles = sorted(role_counts.items(), key=lambda item: item[1], reverse=True)[:5]
    if top_roles:
         summary.append("Most Common Roles: " + ", ".join([f"{name} ({count}x)" for name, count in top_roles]))
         
    # Scope distribution
    scope_summary = [f"{scope_name}: {count}" for scope_name, count in scopes.items() if count > 0]
    if scope_summary:
         summary.append("Assignment Scopes: " + ", ".join(scope_summary))
         
    return "; ".join(summary)

def _summarize_web_apps(all_data):
    """Summarizes detected Web App resources."""
    count = 0
    kinds = set()
    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data: continue
        for res in data["resources"]:
            if isinstance(res, dict) and res.get("type", "").lower() == "microsoft.web/sites":
                 # Exclude function apps from this specific summary if needed
                 kind = res.get("kind", "app").lower()
                 if "functionapp" not in kind:
                      count += 1
                      kinds.add("Web App" if "app" in kind else kind.capitalize()) 
                      
    if count == 0:
        return "_No dedicated Web App resources (excluding Function Apps) detected._"
    else:
        kind_str = ", ".join(sorted(list(kinds)))
        return f"Detected {count} Web App instance(s). Types include: {kind_str}. See detailed table in Section 5.1."

def _summarize_api_services(all_data):
    """Summarizes detected API Management resources."""
    count = 0
    skus = set()
    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data: continue
        for res in data["resources"]:
            if isinstance(res, dict) and res.get("type", "").lower() == "microsoft.apimanagement/service":
                 count += 1
                 sku_name = res.get("sku", {}).get("name", "Unknown")
                 skus.add(sku_name)
                 
    if count == 0:
         return "_No API Management service instances detected._"
    else:
         sku_str = ", ".join(sorted(list(skus)))
         return f"Detected {count} API Management instance(s). SKUs include: {sku_str}."

def _summarize_container_services(all_data):
    """Summarizes detected Container services (AKS, ACI, Container Apps)."""
    services = {"AKS": 0, "ACI": 0, "Container Apps": 0}
    
    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data: continue
        for res in data["resources"]:
            if isinstance(res, dict):
                res_type = res.get("type", "").lower()
                if res_type == "microsoft.containerservice/managedclusters":
                    services["AKS"] += 1
                elif res_type == "microsoft.containerinstance/containergroups":
                    services["ACI"] += 1
                elif res_type == "microsoft.app/containerapps":
                    services["Container Apps"] += 1
                    
    detected = [f"{name}: {count}" for name, count in services.items() if count > 0]
    if not detected:
         return "_No common Container Services (AKS, ACI, Container Apps) detected._"
    else:
         return f"Detected Container Services: {'; '.join(detected)}."

def _analyze_lifecycle_policies(all_data):
    """Analyzes policy assignments for keywords related to lifecycle management."""
    keywords = ["lifecycle", "retention", "delete", "archive", "tagging", "owner", "environment", "cost"]
    policy_count = 0
    relevant_policies = []
    
    for sub_id, data in all_data.items():
        if "error" in data or "governance" not in data: continue
        assignments = data["governance"].get("policy_assignments", [])
        for assign in assignments:
             if isinstance(assign, dict):
                 name = assign.get("display_name", assign.get("name", "")).lower()
                 description = assign.get("description", "").lower()
                 if any(keyword in name or keyword in description for keyword in keywords):
                     policy_count += 1
                     # Add policy name if not already added
                     policy_display = assign.get("display_name", assign.get("name", "Unknown"))
                     if policy_display not in relevant_policies: relevant_policies.append(policy_display)
                     
    if policy_count == 0:
         return "_No Azure Policy assignments detected specifically targeting resource lifecycle or governance tags._"
    else:
         policy_list = ", ".join(relevant_policies[:3]) + ("..." if len(relevant_policies) > 3 else "")
         return f"{policy_count} policy assignments found potentially related to lifecycle/governance (e.g., {policy_list}). Review policy details for specifics."

def _analyze_service_principals(all_data):
    """Provides a summary based on the stubbed service principal fetcher."""
    # Since it's tenant-level, check the first subscription's data
    first_sub_key = next(iter(all_data), None)
    if not first_sub_key:
        return "_No subscription data available to check service principal status._"
        
    sp_info = all_data[first_sub_key].get("identity", {}).get("service_principals", {})
    status = sp_info.get('status', 'unknown')
    
    if status == 'fetcher_not_implemented':
        return "_Service Principal fetcher requires full implementation (likely using MS Graph API)._"
    elif status == 'requires_graph_api_access':
        return "_Service Principal analysis requires Entra ID Graph API access permissions._"
    elif status == 'error_checking_access':
        return "_Error occurred while trying to check for Graph API access for Service Principal analysis._"
    else:
        return "_Could not determine Service Principal status._"