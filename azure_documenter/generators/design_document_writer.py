import os
import logging
from datetime import datetime, timezone
import time
import re



# Import helper functions
from .analysis_helpers import (
    _get_management_group_hierarchy_summary,
    _analyze_rg_naming_patterns,
    _analyze_resource_lifecycle,
    _analyze_ad_connect_status,
    _analyze_rbac_approach,
    _analyze_pim_status,
    _analyze_managed_identity_usage,
    _analyze_service_principals,
    _analyze_lifecycle_policies
)

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
    
    def truncate_cell(content, max_length=60):
        """Truncates cell content if it's too long."""
        if len(content) > max_length and not content.startswith('`'):
            return content[:max_length-3] + "..."
        return content
    
    def process_cell(content):
        """Processes a cell's content for better formatting."""
        if content is None:
            return ""
        
        # Convert to string
        content = str(content)
        
        # Handle resource IDs and technical strings
        if (content.startswith('/subscriptions/') or 
            'microsoft.' in content.lower() or 
            'connectionstring' in content.lower() or
            (content.startswith('http') and len(content) > 40)):
            
            # Extract meaningful part for display
            if content.startswith('/subscriptions/'):
                parts = content.split('/')
                if len(parts) > 4:
                    content = f"`.../{'/'.join(parts[-2:])}`"
            elif not content.startswith('`'):
                content = truncate_cell(content)
                if len(content) > 40:
                    content = f"`{content}`"
        else:
            content = truncate_cell(content)
        
        # Escape pipes and remove newlines
        return content.replace('|', '&#124;').replace('\n', ' ')
    
    # Process headers
    headers = [process_cell(h) for h in headers]
    
    md = []
    md.append(f"| {' | '.join(headers)} |")
    md.append(f"|{'|'.join(['---' for _ in headers])}|")
    
    # Process rows
    for row in data_rows:
        processed_cells = [process_cell(cell) for cell in row]
        md.append(f"| {' | '.join(processed_cells)} |")
    
    # Add blank lines and CSS class for table wrapping
    return "\n<div class='table-wrapper'>\n\n" + "\n".join(md) + "\n\n</div>\n"

def _get_subscriptions_table(subscription_data):
    """Generates Markdown table for subscriptions."""
    headers = ["Subscription Name", "Subscription ID"]
    rows = []
    for sub_id, data in subscription_data.items():
        # We expect data to be a dict here because main.py filtered it
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
    zones_by_type = {}  # Track zone types for summary

    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        private_zones = data["networking"].get("private_dns_zones", [])
        for zone in private_zones:
             if isinstance(zone, dict):
                zone_name = zone.get('name', 'Unknown')
                links = zone.get('vnet_links', [])
                links_str = ", ".join(links) if links else "None"
                private_zones_text.append(f"- **{zone_name}** (Sub: {sub_name}): Linked to VNets: {links_str}")
                
                # Track zone types for summary
                zone_type = zone_name.split('.', 1)[1] if '.' in zone_name else 'Other'
                zones_by_type[zone_type] = zones_by_type.get(zone_type, 0) + 1
                
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
    
    # Generate the output with context
    if private_zones_text:
        zones_summary = "\n\n**Private DNS Zones Summary:**"
        zones_summary += f"\n- Total Zones: {len(private_zones_text)}"
        if zones_by_type:
            zones_summary += "\n- Zone Types:"
            for zone_type, count in sorted(zones_by_type.items()):
                zones_summary += f"\n  - {zone_type}: {count} zone(s)"
        private_zones_output = "\n".join(sorted(private_zones_text)) + zones_summary
    else:
        private_zones_output = "_No Azure Private DNS Zones found. This is expected if you're not using Azure Private Link or if private endpoints are not required for your workload._"
    
    if custom_dns_text:
        custom_dns_output = "\n".join(sorted(custom_dns_text))
        if unique_custom_dns:
            custom_dns_output += f"\n\n**Unique DNS Servers:** {', '.join(sorted(unique_custom_dns))}"
    else:
        custom_dns_output = "_No VNets found using Custom DNS Servers. This is expected if you're using Azure-provided DNS or Private DNS Zones exclusively._"
    
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
    service_type_counts = {}  # Track counts of each service type
    
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
                
                # Track service type counts
                service_type_counts[service_type] = service_type_counts.get(service_type, 0) + 1
                
                rows.append([
                    sub_name,
                    pe.get("name", "Unknown"),
                    service_type,
                    pls_id_str,
                    os.path.basename(pe.get("subnet_id", "Unknown"))
                ])
             else: logging.warning(f"Skipping non-dictionary private endpoint in sub {sub_id}: {pe}")
    
    if not rows:
        return "_No Private Endpoints found. This is expected if you're not using Azure Private Link or if your services are accessible through other networking configurations._"
    
    table = _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))
    
    # Add summary section
    summary = ["\n\n**Private Endpoints Summary:**"]
    summary.append(f"- Total Private Endpoints: {len(rows)}")
    if service_type_counts:
        summary.append("- Service Types:")
        for service_type, count in sorted(service_type_counts.items()):
            summary.append(f"  - {service_type}: {count} endpoint(s)")
    
    return table + "\n".join(summary)

def _get_internet_ingress_list(all_data):
    """Generates Markdown list for potential Internet Ingress points."""
    ingress_points = []
    for sub_id, data in all_data.items():
        # Ensure data is a dictionary before processing
        if not isinstance(data, dict):
            logging.warning(f"Skipping entry in _get_internet_ingress_list as data is not a dict. Key: {sub_id}, Type: {type(data)}")
            continue
            
        # Original check for error key
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

def _get_waf_summary(subscription_data):
    """Generates a summary of Web Application Firewall usage."""
    waf_on_agw_count = 0
    waf_on_afd_count = 0 # Placeholder for Front Door WAF check if fetcher works
    standalone_waf_policies_count = 0
    waf_details = [] # To store details like policy names or AGW names

    for sub_id, data in subscription_data.items():
        if "error" in data or "networking" not in data:
            continue
            
        networking = data["networking"]
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)

        # Check Application Gateways for WAF
        app_gateways = networking.get("application_gateways", [])
        for agw in app_gateways:
            if isinstance(agw, dict):
                waf_config = agw.get("waf_configuration")
                if waf_config and waf_config.get("enabled"):
                    waf_on_agw_count += 1
                    mode = waf_config.get("firewall_mode", "Unknown")
                    waf_details.append(f"- App Gateway **{agw.get('name')}** (Sub: {sub_name}, Mode: {mode})")
                elif agw.get("firewall_policy_id"):
                    waf_on_agw_count += 1 # Counts AGW linked to a WAF Policy
                    policy_name = agw["firewall_policy_id"].split('/')[-1]
                    waf_details.append(f"- App Gateway **{agw.get('name')}** (Sub: {sub_name}, Policy: {policy_name})")

        # Check Front Doors for WAF (Needs specific key from fetcher)
        # Placeholder: Assuming fetcher returns a list under 'front_doors_std_premium'
        # and each item has a 'waf_policy_id' or similar.
        front_doors = networking.get("front_doors_std_premium", []) # Adjust key if needed
        for afd in front_doors:
            if isinstance(afd, dict) and afd.get("waf_policy_id"): # Check the actual key used by fetcher
                 waf_on_afd_count += 1
                 policy_name = afd["waf_policy_id"].split('/')[-1]
                 waf_details.append(f"- Front Door **{afd.get('name')}** (Sub: {sub_name}, Policy: {policy_name})")

        # Count standalone WAF Policies
        waf_policies = networking.get("waf_policies", [])
        standalone_waf_policies_count += len(waf_policies)
        for policy in waf_policies:
             # Avoid double-counting details if already listed via AGW/AFD link
             policy_name_short = policy.get('name')
             if policy_name_short and not any(policy_name_short in detail for detail in waf_details):
                  waf_details.append(f"- Standalone WAF Policy **{policy_name_short}** (Sub: {sub_name})")

    total_waf_instances = waf_on_agw_count + waf_on_afd_count

    if total_waf_instances == 0 and standalone_waf_policies_count == 0:
        return "_No Web Application Firewall usage detected on Application Gateways or Front Doors. No standalone WAF Policies found._"
    
    summary = []
    if total_waf_instances > 0:
        summary.append(f"WAF detected on **{total_waf_instances}** instance(s) ({waf_on_agw_count} App Gateway(s), {waf_on_afd_count} Front Door(s)).")
    if standalone_waf_policies_count > 0:
        summary.append(f"Found **{standalone_waf_policies_count}** standalone WAF Policy resource(s)." + (" Ensure they are linked to AGW/AFD/CDN." if total_waf_instances == 0 else ""))
        
    if waf_details:
        summary.append("\n**Details (Examples):**")
        summary.extend(waf_details[:5]) # Show first 5 examples
        if len(waf_details) > 5:
             summary.append(f"- ... and {len(waf_details) - 5} more")

    return "\n".join(summary)

# --- Security, Governance, Compliance Section Helpers ---

def _get_defender_status(all_data):
    """Generates Markdown list for Defender for Cloud status per subscription."""
    status_lines = []
    for sub_id, data in all_data.items():
        # Ensure data is a dictionary before processing
        if not isinstance(data, dict):
            logging.warning(f"Skipping entry in _get_defender_status as data is not a dict. Key: {sub_id}, Type: {type(data)}")
            continue 
            
        # Original check for error key within the dict
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
    headers = ["Subscription", "Name", "Region", "SKU", "Retention (Days)", "Solutions", "Linked Services"]
    rows = []
    for sub_id, data in all_data.items():
        if "error" in data: continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        workspaces = data.get("monitoring", {}).get("log_analytics_workspaces", [])
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
                
                # Get solutions and linked services
                solutions = properties.get("solutions", [])
                linked_services = properties.get("linked_services", [])
                
                # Format solutions and linked services for display
                solutions_str = ", ".join(sorted(set(s.get("product", s.get("name", "Unknown")) for s in solutions if isinstance(s, dict)))) or "None"
                linked_services_str = ", ".join(sorted(set(s.get("type", "Unknown").split("/")[-1] for s in linked_services if isinstance(s, dict)))) or "None"
                
                rows.append([
                    sub_name,
                    ws.get("name", "Unknown"),
                    ws.get("location", "Unknown"),
                    sku,
                    str(retention),
                    solutions_str,
                    linked_services_str
                ])
            else: logging.warning(f"Skipping non-dictionary LA Workspace in sub {sub_id}: {ws}")
    
    table = _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))
    
    # Add a summary section after the table
    summary = []
    total_workspaces = len(rows)
    if total_workspaces > 0:
        # Count workspaces with solutions
        workspaces_with_solutions = sum(1 for row in rows if row[5] != "None")
        # Count workspaces with linked services
        workspaces_with_links = sum(1 for row in rows if row[6] != "None")
        
        summary.append(f"\n\n**Summary:**")
        summary.append(f"- Total Workspaces: {total_workspaces}")
        if workspaces_with_solutions > 0:
            summary.append(f"- Workspaces with Solutions: {workspaces_with_solutions} ({(workspaces_with_solutions/total_workspaces)*100:.1f}%)")
        if workspaces_with_links > 0:
            summary.append(f"- Workspaces with Linked Services: {workspaces_with_links} ({(workspaces_with_links/total_workspaces)*100:.1f}%)")
    
    return table + "\n".join(summary) if summary else table

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
    """
    Analyzes the network topology across all subscriptions.
    Returns a string containing the analysis in markdown format.
    """
    sections = []
    
    try:
        # Add overview section
        sections.append("""
### Network Topology Overview
This section provides an analysis of the network architecture across all subscriptions, including VNets, peering, connectivity, and security components.
""")

        # Add VNets table
        sections.append("### Virtual Networks\n")
        vnets_table = _get_vnets_table(all_data)
        sections.append(vnets_table if vnets_table else "_No Virtual Networks found._\n")

        # Add Peering information
        sections.append("\n### VNet Peering\n")
        peering_table = _get_peering_table(all_data)
        sections.append(peering_table if peering_table else "_No VNet peering configurations found._\n")

        # Add Gateway information
        sections.append("\n### Network Gateways\n")
        gateways_table = _get_gateways_table(all_data)
        sections.append(gateways_table if gateways_table else "_No network gateways found._\n")

        # Add Firewall information
        sections.append("\n### Azure Firewalls\n")
        firewalls_table = _get_firewalls_table(all_data)
        sections.append(firewalls_table if firewalls_table else "_No Azure Firewalls found._\n")

        # Add DNS information
        sections.append("\n### DNS Configuration\n")
        dns_details = _get_dns_details(all_data)
        sections.append(dns_details if dns_details else "_No DNS configurations found._\n")

        # Add Private Endpoints
        sections.append("\n### Private Endpoints\n")
        private_endpoints = _get_private_endpoints_table(all_data)
        sections.append(private_endpoints if private_endpoints else "_No private endpoints found._\n")

        # Add Internet Ingress Points
        sections.append("\n### Internet Ingress Points\n")
        ingress_list = _get_internet_ingress_list(all_data)
        sections.append(ingress_list if ingress_list else "_No internet ingress points identified._\n")

        # Add Internet Egress Analysis
        sections.append("\n### Internet Egress Analysis\n")
        egress_analysis = _analyze_internet_egress(all_data)
        sections.append(egress_analysis if egress_analysis else "_No internet egress analysis available._\n")

        # Add Service Endpoints Summary
        sections.append("\n### Service Endpoints\n")
        endpoints_summary = _get_service_endpoints_summary(all_data)
        sections.append(endpoints_summary if endpoints_summary else "_No service endpoints configured._\n")

        # Add Private Link Services
        sections.append("\n### Private Link Services\n")
        private_links = _get_private_link_services_table(all_data)
        sections.append(private_links if private_links else "_No private link services found._\n")

        # Convert all sections to strings and join
        return "\n".join([str(section) for section in sections if section is not None])

    except Exception as e:
        logging.error(f"Error in network topology analysis: {str(e)}")
        return "_Error analyzing network topology._"

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
    """Generates markdown links for subscription-specific diagrams."""
    if not diagram_paths or "subscription_diagrams" not in diagram_paths:
        logging.warning("No diagram paths provided for subscription diagrams")
        return "_No subscription-specific diagrams available._"
    
    markdown = []
    for sub_id, diagrams in diagram_paths.get("subscription_diagrams", {}).items():
        sub_info = all_data.get(sub_id, {}).get("subscription_info", {})
        sub_name = sub_info.get("display_name", sub_id)
        
        if "vnet_topology" in diagrams:
            # Use relative path from markdown file to diagrams
            diagram_path = f"../diagrams/{diagrams['vnet_topology']}"
            # Ensure forward slashes for markdown compatibility
            diagram_path = diagram_path.replace("\\", "/")
            markdown.append(f"### {sub_name}\n")
            markdown.append(f'<img src="{diagram_path}" alt="Network Topology for {sub_name}" style="max-width: 100%; height: auto;"/>')
    
    return "\n\n".join(markdown) if markdown else "_No subscription-specific diagrams available._"

def _get_app_services_table(all_data):
    """Generates Markdown table for App Services."""
    headers = ["Subscription", "App Name", "Resource Group", "App Service Plan", "Runtime", "State", "URLs", "Security & Integration"]
    rows = []
    for sub_id, data in all_data.items():
        if "error" in data or "web_details" not in data:
            continue
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        
        # Create a map of App Service Plans first
        asp_map = {}
        for plan in data["web_details"].get("app_service_plans", {}).values():
            if isinstance(plan, dict):
                plan_name = plan.get("name", "Unknown")
                sku = plan.get("sku", {})
                asp_map[plan_name] = {
                    "tier": sku.get("tier", "Unknown"),
                    "size": sku.get("size", "Unknown"),
                    "capacity": sku.get("capacity", 1)
                }
        
        for app in data["web_details"].get("app_services", []):
            if not isinstance(app, dict):
                continue
                
            name = app.get("name", "Unknown")
            location = app.get("location", "Unknown")
            resource_group = app.get("resource_group", "Unknown")
            state = app.get("state", "Unknown")
            
            # Get App Service Plan details
            plan_name = os.path.basename(app.get("server_farm_id", "Unknown"))
            plan_details = asp_map.get(plan_name, {})
            plan_display = f"{plan_name} ({plan_details.get('tier', '')} {plan_details.get('size', '')})"
            
            # Get runtime details
            site_config = app.get("site_config", {})  # Changed back to site_config since that's what the fetcher returns
            runtime = "Unknown"
            if site_config:
                if site_config.get("linux_fx_version"):
                    runtime = site_config["linux_fx_version"]
                elif site_config.get("windows_fx_version"):
                    runtime = site_config["windows_fx_version"]
                elif site_config.get("java_version"):
                    runtime = f"Java {site_config['java_version']}"
                    if site_config.get("java_container"):
                        runtime += f" ({site_config['java_container']} {site_config.get('java_container_version', '')})"
                elif site_config.get("php_version"):
                    runtime = f"PHP {site_config['php_version']}"
                elif site_config.get("python_version"):
                    runtime = f"Python {site_config['python_version']}"
                elif site_config.get("node_version"):
                    runtime = f"Node {site_config['node_version']}"
                elif site_config.get("net_framework_version"):
                    runtime = f".NET {site_config['net_framework_version']}"
                elif site_config.get("current_stack"):
                    runtime = f"Stack: {site_config['current_stack']}"
                
                # Check if it's a container
                if runtime.startswith("DOCKER|"):
                    runtime = f"Container: {runtime.split('|')[1]}"
                elif runtime.startswith("COMPOSE|"):
                    runtime = "Docker Compose"
                    
                # Check if it's a function app
                if app.get("kind", "").lower().startswith("functionapp"):
                    runtime = f"Function App ({runtime})"
            
            # Get URLs
            host_names = app.get("host_names", [])
            urls = ", ".join([f"`{host}`" for host in host_names]) if host_names else "No URLs"
            
            # Get security and integration details
            security_features = []
            if app.get("https_only"):
                security_features.append("HTTPS Only")
            if app.get("virtual_network_subnet_id"):
                security_features.append("VNet Integration")
            if app.get("identity", {}).get("type"):
                security_features.append(f"MSI ({app['identity']['type']})")
            if any(setting.get("name") == "APPINSIGHTS_INSTRUMENTATIONKEY" 
                  for setting in app.get("app_settings", [])):
                security_features.append("App Insights")
            
            security_text = ", ".join(security_features) if security_features else "Basic"
            
            rows.append([
                sub_name,
                name,
                resource_group,
                plan_display,
                runtime,
                state,
                urls,
                security_text
            ])
    
    if not rows:
        return "_No App Services found in audited subscriptions._"
    
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[2], x[1])))  # Sort by subscription, resource group, name

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
                location = res.get("location", "Unknown")

                # --- Get Size ---
                # Prioritize the merged top-level key first
                vm_size = res.get("vmSize", "Unknown")
                # Fallback to nested properties if top-level key isn't present
                if vm_size == "Unknown":
                    vm_size = properties.get("hardwareProfile", {}).get("vmSize", "Unknown")

                # --- Get OS Type ---
                # Prioritize the merged top-level key first
                os_type = res.get("osType", "Unknown")
                # Fallback to nested properties if top-level key isn't present
                if os_type == "Unknown":
                    os_profile = properties.get("osProfile", {})
                    if os_profile:
                        if os_profile.get("windowsConfiguration"):
                            os_type = "Windows"
                        elif os_profile.get("linuxConfiguration"):
                            os_type = "Linux"
                    # Try alternate disk method if still unknown
                    if os_type == "Unknown": # Corrected indentation
                        storage_profile = properties.get("storageProfile", {})
                        os_disk = storage_profile.get("osDisk", {})
                        os_type_from_disk = os_disk.get("osType") # Corrected indentation
                        if os_type_from_disk:
                            os_type = os_type_from_disk

                # --- Get Status ---
                # Prioritize the merged top-level key first
                status = res.get("status", "Unknown")
                # Fallback to nested properties (instanceView) if top-level key isn't present
                if status == "Unknown":
                    instance_view = properties.get("instanceView", {})
                    if instance_view:
                        statuses = instance_view.get("statuses", [])
                        power_status = next((s.get("displayStatus") for s in statuses if s.get("code", "").startswith("PowerState/")), None)
                        if power_status:
                            status = power_status
                        # Fallback to provisioning state if still unknown
                    if status == "Unknown":
                        status = properties.get("provisioningState", "Unknown")

                rows.append([sub_name, vm_name, vm_size, os_type, location, status])
    
    if not found_any:
        return "_No Virtual Machines detected in the environment._"
    
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

# --- Data Aggregation & Analysis Helpers ---
# (These functions process the raw data into summaries/tables for the placeholders)

# Example: (Keep existing helper functions like _get_storage_accounts_table etc.)

# ... existing code ...

def _get_management_group_hierarchy_summary(mg_list):
    """Analyzes Management Group hierarchy for the design document.

    Args:
        mg_list (list): The list of management groups with parent_id relationships.
        
    Returns:
        str: Markdown-formatted summary of the MG hierarchy.
    """
    if not mg_list:
        return "_No Management Groups found in tenant._"
    
    # Start with simple list approach
    mg_summary = []
    for mg in mg_list:
        if isinstance(mg, dict):
            name = mg.get('name') or mg.get('display_name', 'Unknown')
            mg_id = mg.get('id', 'Unknown ID')
            parent = mg.get('parent_name', 'Root')
            if parent != 'Root':
                mg_summary.append(f"- **{name}** (`{mg_id}`) ← *Child of {parent}*")
            else:
                mg_summary.append(f"- **{name}** (`{mg_id}`) ← *Root Level*")
    
    if not mg_summary:
        return "_Management Group data format not compatible with analysis._"
    
    return "\n".join(mg_summary)

def _analyze_rg_naming_patterns(all_data):
    """Analyzes Resource Group naming patterns from all subscriptions.
    
    Args:
        all_data (dict): Dictionary of subscription data from fetchers.
        
    Returns:
        str: Markdown-formatted summary of detected patterns.
    """
    if not all_data:
        return "_No subscription data available for resource group analysis._"
    
    # Collect all resource group names
    all_rgs = []
    for sub_id, data in all_data.items():
        if "error" in data or "resource_groups" not in data:
            continue
        rgs = data.get("resource_groups", [])
        for rg in rgs:
            if isinstance(rg, dict) and "name" in rg:
                all_rgs.append(rg["name"])
    
    if not all_rgs:
        return "_No resource groups found in the environment._"
    
    # Analyze patterns - look for common prefixes
    prefix_counts = {}
    for rg_name in all_rgs:
        parts = rg_name.split('-')
        if len(parts) > 1:
            prefix = parts[0].lower()
            prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1
    
    # Find the top 3 most common prefixes
    sorted_prefixes = sorted(prefix_counts.items(), key=lambda x: x[1], reverse=True)
    
    if not sorted_prefixes:
        return "_No common patterns detected in resource group names._"
    
    # Create summary
    prefix_summary = []
    for prefix, count in sorted_prefixes[:3]:
        percentage = (count / len(all_rgs)) * 100
        prefix_summary.append(f"- Prefix `{prefix}-`: {count} groups ({percentage:.1f}% of total)")
    
    if prefix_summary:
        pattern_text = "\n".join(prefix_summary)
        return f"Common patterns detected in {len(all_rgs)} resource groups:\n{pattern_text}"
    else:
        return "_No clear naming patterns detected across resource groups._"

def _analyze_resource_lifecycle(all_data):
    """Analyzes resource lifecycle patterns from the collected data.
    
    Args:
        all_data (dict): Dictionary of subscription data from fetchers.
        
    Returns:
        str: Markdown-formatted summary of lifecycle patterns.
    """
    if not all_data:
        return "_No subscription data available for resource lifecycle analysis._"
    
    # Check for lifecycle-related tags
    lifecycle_tags = ["environment", "env", "stage", "lifecycle", "expiration", "ttl", "expires"]
    tag_counts = {tag: 0 for tag in lifecycle_tags}
    
    # Track resources with expirations or lifecycle indicators
    total_resources_with_tags = 0
    total_resources = 0
    
    # Look for resources with lifecycle policies or retention settings
    storage_with_lifecycle = 0
    total_storage = 0
    key_vaults_soft_delete = 0
    total_key_vaults = 0
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        # Check for tagged resources
        for resource_type in ["virtual_machines", "storage_accounts", "app_services", "key_vaults"]:
            if resource_type in data:
                resources = data.get(resource_type, [])
                total_resources += len(resources)
                
                for resource in resources:
                    if not isinstance(resource, dict):
                        continue
                    
                    # Count resources with lifecycle tags
                    tags = resource.get("tags", {})
                    if tags:
                        for tag_name in tags:
                            if tag_name.lower() in lifecycle_tags:
                                tag_counts[tag_name.lower()] += 1
                                total_resources_with_tags += 1
                                break
                    
                    # Count storage accounts with lifecycle management
                    if resource_type == "storage_accounts":
                        total_storage += 1
                        if resource.get("has_lifecycle_policy", False):
                            storage_with_lifecycle += 1
                    
                    # Count Key Vaults with soft-delete enabled
                    if resource_type == "key_vaults":
                        total_key_vaults += 1
                        if resource.get("soft_delete_enabled", False):
                            key_vaults_soft_delete += 1
    
    if total_resources == 0:
        return "_No resources found for lifecycle analysis._"
    
    # Create summary
    lifecycle_summary = []
    
    # Add tag usage
    if total_resources_with_tags > 0:
        tag_percentage = (total_resources_with_tags / total_resources) * 100
        lifecycle_summary.append(f"- **{tag_percentage:.1f}%** of resources have lifecycle-related tags")
        
        # Add most common tags
        sorted_tags = sorted([(tag, count) for tag, count in tag_counts.items() if count > 0], 
                           key=lambda x: x[1], reverse=True)
        if sorted_tags:
            top_tags = [f"`{tag}` ({count} resources)" for tag, count in sorted_tags[:3]]
            lifecycle_summary.append(f"- Most common lifecycle tags: {', '.join(top_tags)}")
    else:
        lifecycle_summary.append("- No lifecycle-related tags detected on resources")
    
    # Add storage lifecycle stats
    if total_storage > 0:
        storage_percentage = (storage_with_lifecycle / total_storage) * 100
        lifecycle_summary.append(f"- **{storage_percentage:.1f}%** of Storage Accounts have blob lifecycle management")
    
    # Add Key Vault soft-delete stats
    if total_key_vaults > 0:
        kv_percentage = (key_vaults_soft_delete / total_key_vaults) * 100
        lifecycle_summary.append(f"- **{kv_percentage:.1f}%** of Key Vaults have soft-delete protection")
    
    if lifecycle_summary:
        return "\n".join(lifecycle_summary)
    else:
        return "_No clear resource lifecycle patterns detected._"

def _analyze_ad_connect_status(all_data):
    """Analyzes the Azure AD Connect status based on detected hybrid identity components.
    
    Args:
        all_data (dict): Dictionary of subscription data from fetchers.
        
    Returns:
        str: Markdown-formatted summary of AD Connect status.
    """
    if not all_data:
        return "_No subscription data available for AD Connect analysis._"
    
    # Look for components that indicate AD Connect:
    # - Azure AD Connect Health service
    # - AD FS servers
    # - AD Domain Controllers
    ad_connect_indicators = {
        "ad_connect_health": False,
        "adfs_servers": 0,
        "domain_controllers": 0
    }
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        # Check for AD Connect Health extension or service
        if "virtual_machines" in data:
            vms = data.get("virtual_machines", [])
            for vm in vms:
                if not isinstance(vm, dict):
                    continue
                
                vm_name = vm.get("name", "").lower()
                vm_tags = vm.get("tags", {})
                
                # Check VM name or tags for indicators
                if "adfs" in vm_name or "ad-fs" in vm_name:
                    ad_connect_indicators["adfs_servers"] += 1
                
                if "dc" == vm_name[:2] or "domain" in vm_name:
                    ad_connect_indicators["domain_controllers"] += 1
                
                # Check for tags indicating AD Connect or domain controllers
                for tag_name, tag_value in vm_tags.items():
                    tag_value = str(tag_value).lower() if tag_value else ""
                    if "ad connect" in tag_value or "adconnect" in tag_value:
                        ad_connect_indicators["ad_connect_health"] = True
                    if "domain" in tag_value and "controller" in tag_value:
                        ad_connect_indicators["domain_controllers"] += 1
    
    # Make a determination based on indicators
    if ad_connect_indicators["ad_connect_health"]:
        return "Azure AD Connect detected in environment"
    elif ad_connect_indicators["adfs_servers"] > 0:
        return f"Possible AD FS deployment detected ({ad_connect_indicators['adfs_servers']} potential servers)"
    elif ad_connect_indicators["domain_controllers"] > 0:
        return f"Possible hybrid identity with {ad_connect_indicators['domain_controllers']} potential domain controllers"
    else:
        return "No clear indicators of Azure AD Connect deployment (cloud-only identity likely)"

def _analyze_rbac_approach(all_data):
    """Analyzes RBAC patterns from the collected role assignments.
    
    Args:
        all_data (dict): Dictionary of subscription data from fetchers.
        
    Returns:
        str: Markdown-formatted summary of RBAC approach.
    """
    if not all_data:
        return "_No subscription data available for RBAC analysis._"
    
    # Analyze role assignments
    role_assignment_counts = {
        "built_in": 0,
        "custom": 0,
        "user": 0,
        "group": 0,
        "service_principal": 0,
        "managed_identity": 0,
        "subscription": 0,
        "resource_group": 0,
        "resource": 0
    }
    
    common_roles = {}
    
    for sub_id, data in all_data.items():
        if "error" in data or "security" not in data:
            continue
        
        role_assignments = data["security"].get("role_assignments", [])
        for assignment in role_assignments:
            if not isinstance(assignment, dict):
                continue
            
            # Count by role type
            if assignment.get("role_definition_id", "").startswith("/providers/Microsoft.Authorization/roleDefinitions/"):
                role_assignment_counts["built_in"] += 1
            else:
                role_assignment_counts["custom"] += 1
            
            # Count by principal type
            principal_type = assignment.get("principal_type", "").lower()
            if "user" in principal_type:
                role_assignment_counts["user"] += 1
            elif "group" in principal_type:
                role_assignment_counts["group"] += 1
            elif "service" in principal_type:
                role_assignment_counts["service_principal"] += 1
            elif "managed" in principal_type:
                role_assignment_counts["managed_identity"] += 1
            
            # Count by scope level
            scope = assignment.get("scope", "")
            if scope:
                if scope.count("/") <= 3:  # /subscriptions/{id}
                    role_assignment_counts["subscription"] += 1
                elif scope.count("/") <= 5:  # /subscriptions/{id}/resourceGroups/{name}
                    role_assignment_counts["resource_group"] += 1
                else:
                    role_assignment_counts["resource"] += 1
            
            # Track common roles
            role_name = assignment.get("role_definition_name", "Unknown")
            if role_name != "Unknown":
                common_roles[role_name] = common_roles.get(role_name, 0) + 1
    
    total_assignments = sum(role_assignment_counts.values())
    if total_assignments == 0:
        return "_No role assignments found for analysis._"
    
    # Create summary
    rbac_summary = []
    
    # Analyze overall approach
    if role_assignment_counts["group"] > role_assignment_counts["user"]:
        rbac_summary.append("**Group-based approach**: Majority of assignments are to Azure AD groups")
    else:
        rbac_summary.append("**Direct assignment approach**: Majority of assignments are directly to users")
    
    # Analyze custom vs built-in
    built_in_percentage = (role_assignment_counts["built_in"] / total_assignments) * 100
    rbac_summary.append(f"**{built_in_percentage:.1f}%** of roles are built-in (vs. custom)")
    
    # Analyze scope distribution
    if role_assignment_counts["resource_group"] > role_assignment_counts["subscription"] and role_assignment_counts["resource_group"] > role_assignment_counts["resource"]:
        rbac_summary.append("**Resource group-focused**: Most permissions granted at resource group level")
    elif role_assignment_counts["subscription"] > role_assignment_counts["resource_group"] and role_assignment_counts["subscription"] > role_assignment_counts["resource"]:
        rbac_summary.append("**Subscription-focused**: Most permissions granted at subscription level")
    else:
        rbac_summary.append("**Resource-focused**: Most permissions granted at individual resource level")
    
    # Add common roles
    sorted_roles = sorted(common_roles.items(), key=lambda x: x[1], reverse=True)
    if sorted_roles:
        top_roles = [f"'{role}'" for role, count in sorted_roles[:3]]
        rbac_summary.append(f"**Common roles**: {', '.join(top_roles)}")
    
    if rbac_summary:
        return "\n".join(rbac_summary)
    else:
        return "_No clear RBAC patterns detected._"

def _analyze_pim_status(all_data):
    """Analyzes whether Privileged Identity Management (PIM) appears to be in use.
    
    Args:
        all_data (dict): Dictionary of subscription data from fetchers.
        
    Returns:
        str: Markdown-formatted summary of PIM status.
    """
    if not all_data:
        return "_No subscription data available for PIM analysis._"
    
    # Look for PIM-eligible role assignments which would indicate PIM is in use
    pim_indicators = {
        "eligible_assignments": 0,
        "activated_assignments": 0
    }
    
    for sub_id, data in all_data.items():
        if "error" in data or "security" not in data:
            continue
        
        # Check for PIM eligible assignments
        role_assignments = data["security"].get("role_assignments", [])
        for assignment in role_assignments:
            if not isinstance(assignment, dict):
                continue
            
            # Check for PIM eligibility properties
            if assignment.get("pim_eligible", False):
                pim_indicators["eligible_assignments"] += 1
            
            if assignment.get("pim_activated", False):
                pim_indicators["activated_assignments"] += 1
    
    # Make a determination based on indicators
    if pim_indicators["eligible_assignments"] > 0 or pim_indicators["activated_assignments"] > 0:
        status = []
        if pim_indicators["eligible_assignments"] > 0:
            status.append(f"{pim_indicators['eligible_assignments']} eligible assignments")
        if pim_indicators["activated_assignments"] > 0:
            status.append(f"{pim_indicators['activated_assignments']} activated assignments")
        
        return f"Privileged Identity Management appears to be enabled ({', '.join(status)})"
    else:
        return "No indicators of Privileged Identity Management (PIM) usage detected"

def _analyze_managed_identity_usage(all_data):
    """Analyzes the usage patterns of managed identities in the environment.
    
    Args:
        all_data (dict): Dictionary of subscription data from fetchers.
        
    Returns:
        str: Markdown-formatted summary of managed identity usage.
    """
    if not all_data:
        return "_No subscription data available for managed identity analysis._"
    
    # Track managed identity counts by type and resource
    identity_counts = {
        "system_assigned": 0,
        "user_assigned": 0,
        "dual_mode": 0,  # Both system and user assigned
        "total_resources": 0
    }
    
    # Track which resource types use identities
    resource_type_counts = {}
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        # Check for managed identities on common resource types
        resource_types = [
            "virtual_machines", "app_services", "function_apps", 
            "logic_apps", "automation_accounts", "data_factories"
        ]
        
        for resource_type in resource_types:
            if resource_type not in data:
                continue
                
            resources = data.get(resource_type, [])
            for resource in resources:
                if not isinstance(resource, dict):
                    continue
                
                # Check for identity property
                identity = resource.get("identity", {})
                if not identity:
                    continue
                
                identity_counts["total_resources"] += 1
                
                # Count by identity type
                identity_type = identity.get("type", "").lower()
                if identity_type == "systemassigned":
                    identity_counts["system_assigned"] += 1
                elif identity_type == "userassigned":
                    identity_counts["user_assigned"] += 1
                elif identity_type == "systemassigned,userassigned":
                    identity_counts["dual_mode"] += 1
                
                # Track resource types
                display_type = resource_type.replace("_", " ").title()
                resource_type_counts[display_type] = resource_type_counts.get(display_type, 0) + 1
    
    total_identities = sum([identity_counts["system_assigned"], identity_counts["user_assigned"], identity_counts["dual_mode"]])
    if total_identities == 0:
        return "No managed identities detected in the environment"
    
    # Create summary
    identity_summary = []
    
    # Overall usage
    identity_summary.append(f"**{total_identities}** resources using managed identities")
    
    # Type breakdown
    system_percentage = (identity_counts["system_assigned"] / total_identities) * 100
    user_percentage = (identity_counts["user_assigned"] / total_identities) * 100
    dual_percentage = (identity_counts["dual_mode"] / total_identities) * 100
    
    identity_summary.append(f"- **{system_percentage:.1f}%** using system-assigned identities")
    identity_summary.append(f"- **{user_percentage:.1f}%** using user-assigned identities")
    identity_summary.append(f"- **{dual_percentage:.1f}%** using both types")
    
    # Resource type usage
    sorted_types = sorted(resource_type_counts.items(), key=lambda x: x[1], reverse=True)
    if sorted_types:
        type_list = [f"{name} ({count})" for name, count in sorted_types[:3]]
        identity_summary.append(f"- **Common resources**: {', '.join(type_list)}")
    
    if identity_summary:
        return "\n".join(identity_summary)
    else:
        return "_No clear managed identity usage patterns detected._"

def _analyze_service_principals(all_data):
    """Analyzes service principal usage patterns in the environment.
    
    Args:
        all_data (dict): Dictionary of subscription data from fetchers.
        
    Returns:
        str: Markdown-formatted summary of service principal usage.
    """
    if not all_data:
        return "_No subscription data available for service principal analysis._"
    
    # Track service principal assignments and usage
    sp_counts = {
        "total": 0,
        "with_roles": 0,
        "per_subscription": {}
    }
    
    # Track common roles assigned to service principals
    sp_roles = {}
    
    for sub_id, data in all_data.items():
        if "error" in data or "security" not in data:
            continue
        
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        sp_counts["per_subscription"][sub_name] = 0
        
        # Count service principals from role assignments
        role_assignments = data["security"].get("role_assignments", [])
        for assignment in role_assignments:
            if not isinstance(assignment, dict):
                continue
            
            principal_type = assignment.get("principal_type", "").lower()
            if "service" in principal_type:
                sp_counts["total"] += 1
                sp_counts["with_roles"] += 1
                sp_counts["per_subscription"][sub_name] += 1
                
                # Track roles assigned to service principals
                role_name = assignment.get("role_definition_name", "Unknown")
                if role_name != "Unknown":
                    sp_roles[role_name] = sp_roles.get(role_name, 0) + 1
    
    if sp_counts["total"] == 0:
        return "No service principals detected with role assignments"
    
    # Create summary
    sp_summary = []
    
    # Overall count
    sp_summary.append(f"**{sp_counts['total']}** service principals with Azure RBAC assignments")
    
    # Distribution across subscriptions
    active_subs = sum(1 for count in sp_counts["per_subscription"].values() if count > 0)
    total_subs = len(sp_counts["per_subscription"])
    sp_summary.append(f"- Service principals active in **{active_subs}** of {total_subs} subscriptions")
    
    # Common roles
    sorted_roles = sorted(sp_roles.items(), key=lambda x: x[1], reverse=True)
    if sorted_roles:
        role_list = [f"{role}" for role, count in sorted_roles[:3]]
        sp_summary.append(f"- **Common roles**: {', '.join(role_list)}")
    
    if sp_summary:
        return "\n".join(sp_summary)
    else:
        return "_No clear service principal usage patterns detected._"

# --- Placeholder Content Helpers (Additional) ---

def _get_service_endpoints_summary(all_data):
    """Generates Markdown summary for configured service endpoints."""
    service_endpoint_count = 0
    total_subnets = 0
    
    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data:
            continue
        
        # Count service endpoints in subnets
        subnets = data["networking"].get("subnets", [])
        total_subnets += len(subnets)
        for subnet in subnets:
            if isinstance(subnet, dict) and subnet.get("service_endpoints"):
                service_endpoint_count += 1
    
    if total_subnets == 0:
        return "_No subnet data available to analyze service endpoints._"
    
    service_endpoint_percentage = (service_endpoint_count / total_subnets) * 100 if total_subnets > 0 else 0
    
    return f"Approximately {service_endpoint_percentage:.1f}% of subnets have service endpoints configured. Detailed subnet-level analysis requires additional inspection."

def _get_private_link_services_table(all_data):
    """Generates Markdown table for Private Link Services."""
    headers = ["Subscription", "Name", "Location", "Load Balancer Frontend IP", "Visibility"]
    rows = []
    found_any = False
    
    for sub_id, data in all_data.items():
        if "error" in data or "networking" not in data:
            continue
        
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        private_link_services = data["networking"].get("private_link_services", [])
        
        if private_link_services:
            found_any = True
            
        for pls in private_link_services:
            if isinstance(pls, dict):
                # Extract frontend IP configurations if available
                frontend_ips = "N/A"
                if pls.get("frontend_ip_configurations"):
                    frontend_ips = ", ".join([ip.get("name", "Unknown") for ip in pls.get("frontend_ip_configurations", [])])
                
                # Determine visibility
                visibility = "Private"
                if pls.get("visibility", {}).get("subscriptions"):
                    visibility = f"Visible to {len(pls.get('visibility', {}).get('subscriptions', []))} subscription(s)"
                elif pls.get("auto_approval", {}).get("subscriptions"):
                    visibility = f"Auto-approved for {len(pls.get('auto_approval', {}).get('subscriptions', []))} subscription(s)"
                
                rows.append([
                    sub_name,
                    pls.get("name", "Unknown"),
                    pls.get("location", "Unknown"),
                    frontend_ips,
                    visibility
                ])
    
    if not found_any:
        return "_No Private Link Services detected in the environment._"
    
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_serverless_summary(all_data):
    """Generates summary of serverless components (Functions, Logic Apps, etc.)."""
    serverless_components = {
        "function_apps": 0,
        "logic_apps": 0,
        "event_grid_topics": 0,
        "event_hubs": 0
    }
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        resources = data.get("resources", [])
        for res in resources:
            if not isinstance(res, dict):
                continue
                
            res_type = res.get("type", "").lower()
            if "microsoft.web/sites" in res_type and "function" in res.get("kind", "").lower():
                serverless_components["function_apps"] += 1
            elif "microsoft.logic/workflows" in res_type:
                serverless_components["logic_apps"] += 1
            elif "microsoft.eventgrid/topics" in res_type:
                serverless_components["event_grid_topics"] += 1
            elif "microsoft.eventhub/namespaces" in res_type:
                serverless_components["event_hubs"] += 1
    
    # Create summary text
    summary_parts = []
    for component, count in serverless_components.items():
        if count > 0:
            name = component.replace("_", " ").title()
            summary_parts.append(f"**{name}**: {count}")
    
    if not summary_parts:
        return "_No serverless components detected in the environment._"
    
    return "Detected serverless components: " + ", ".join(summary_parts)

def _summarize_web_apps(all_data):
    """Summarizes web application architectures based on App Services and other components."""
    web_apps_count = 0
    hosting_patterns = {
        "windows": 0,
        "linux": 0,
        "container": 0,
        "static": 0
    }
    
    # Integration features
    features = {
        "vnet_integration": 0,
        "cdn": 0,
        "front_door": 0,
        "app_gateway": 0
    }
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        resources = data.get("resources", [])
        for res in resources:
            if not isinstance(res, dict):
                continue
                
            # Count Web Apps
            if res.get("type") == "Microsoft.Web/sites" and "functionapp" not in res.get("kind", "").lower():
                web_apps_count += 1
                
                # Determine hosting type
                kind = res.get("kind", "").lower()
                if "linux" in kind:
                    hosting_patterns["linux"] += 1
                elif "container" in kind:
                    hosting_patterns["container"] += 1
                elif "staticapp" in kind:
                    hosting_patterns["static"] += 1
                else:
                    hosting_patterns["windows"] += 1  # Default is Windows
                
                # Check for VNet integration
                properties = res.get("properties", {})
                if properties.get("virtualNetworkSubnetId") or "WEBSITE_VNET_ROUTE_ALL" in str(properties):
                    features["vnet_integration"] += 1
            
            # Check for CDN profiles that might be used with web apps
            elif "microsoft.cdn/profiles" in res.get("type", "").lower():
                features["cdn"] += 1
            
            # Check for Front Door profiles
            elif "microsoft.network/frontdoors" in res.get("type", "").lower():
                features["front_door"] += 1
            
            # Check for App Gateways
            elif "microsoft.network/applicationgateways" in res.get("type", "").lower():
                features["app_gateway"] += 1
    
    if web_apps_count == 0:
        return "_No web applications detected in the environment._"
    
    # Create summary text
    platform_summary = []
    for platform, count in hosting_patterns.items():
        if count > 0:
            percentage = (count / web_apps_count) * 100
            platform_summary.append(f"{platform.title()} ({percentage:.1f}%)")
    
    feature_summary = []
    for feature, count in features.items():
        if count > 0:
            feature_name = feature.replace("_", " ").title()
            feature_summary.append(f"{feature_name} ({count})")
    
    summary = f"**{web_apps_count}** web application(s) detected.\n"
    summary += f"- **Platforms**: {', '.join(platform_summary)}\n"
    if feature_summary:
        summary += f"- **Common features**: {', '.join(feature_summary)}"
    
    return summary

def _summarize_api_services(all_data):
    """Summarizes API Services (API Management, Functions, App Service APIs)."""
    api_components = {
        "api_management": 0,
        "api_apps": 0,
        "function_api": 0
    }
    
    apim_details = []
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        
        for res in resources:
            if not isinstance(res, dict):
                continue
                
            res_type = res.get("type", "").lower()
            
            # Check for API Management
            if "microsoft.apimanagement/service" in res_type:
                api_components["api_management"] += 1
                sku = res.get("sku", {}).get("name", "Unknown")
                apim_details.append(f"**{res.get('name', 'Unknown')}** ({sub_name}, SKU: {sku})")
            
            # Check for API Apps
            elif "microsoft.web/sites" in res_type:
                kind = res.get("kind", "").lower()
                if "api" in kind:
                    api_components["api_apps"] += 1
                elif "function" in kind:
                    # Functions are often used as APIs
                    api_components["function_api"] += 1
    
    # Create summary
    if sum(api_components.values()) == 0:
        return "_No dedicated API services detected in the environment._"
    
    summary = []
    
    if api_components["api_management"] > 0:
        summary.append(f"**API Management**: {api_components['api_management']} instance(s)")
        if apim_details:
            summary.append("  - " + "\n  - ".join(apim_details[:3]))
            if len(apim_details) > 3:
                summary.append(f"  - ... and {len(apim_details) - 3} more")
    
    if api_components["api_apps"] > 0:
        summary.append(f"**API Apps**: {api_components['api_apps']} app(s)")
    
    if api_components["function_api"] > 0:
        summary.append(f"**Function APIs**: {api_components['function_api']} function app(s) (potential APIs)")
    
    return "\n".join(summary)

def _summarize_container_services(all_data):
    """Summarizes container services (AKS, ACI, App Service containers)."""
    container_services = {
        "aks": 0,
        "container_instances": 0,
        "app_service_containers": 0
    }
    
    aks_details = []
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        
        for res in resources:
            if not isinstance(res, dict):
                continue
                
            res_type = res.get("type", "").lower()
            
            # Check for AKS clusters
            if "microsoft.containerservice/managedclusters" in res_type:
                container_services["aks"] += 1
                aks_details.append(f"**{res.get('name', 'Unknown')}** ({sub_name}, {res.get('location', 'Unknown')})")
            
            # Check for Container Instances
            elif "microsoft.containerinstance/containergroups" in res_type:
                container_services["container_instances"] += 1
            
            # Check for App Service containers
            elif "microsoft.web/sites" in res_type:
                kind = res.get("kind", "").lower()
                if "container" in kind:
                    container_services["app_service_containers"] += 1
    
    # Create summary
    if sum(container_services.values()) == 0:
        return "_No container services detected in the environment._"
    
    summary = []
    
    if container_services["aks"] > 0:
        summary.append(f"**AKS Clusters**: {container_services['aks']} cluster(s)")
        if aks_details:
            summary.append("  - " + "\n  - ".join(aks_details[:3]))
            if len(aks_details) > 3:
                summary.append(f"  - ... and {len(aks_details) - 3} more")
    
    if container_services["container_instances"] > 0:
        summary.append(f"**Container Instances**: {container_services['container_instances']} group(s)")
    
    if container_services["app_service_containers"] > 0:
        summary.append(f"**App Service Containers**: {container_services['app_service_containers']} app(s)")
    
    return "\n".join(summary)

def _get_autoscaling_summary(all_data):
    """Generates a summary of autoscaling configurations."""
    autoscale_counts = {
        "vm_scale_sets": 0,
        "app_service_plans": 0,
        "kubernetes": 0
    }
    
    # Track autoscale settings
    settings_count = 0
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        resources = data.get("resources", [])
        for res in resources:
            if not isinstance(res, dict):
                continue
                
            res_type = res.get("type", "").lower()
            
            # Count VM Scale Sets
            if "microsoft.compute/virtualmachinescalesets" in res_type:
                autoscale_counts["vm_scale_sets"] += 1
            
            # App Service Plans with autoscale
            elif "microsoft.web/serverfarms" in res_type:
                sku = res.get("sku", {}).get("tier", "").lower()
                # Only Standard and Premium tiers support autoscale
                if sku in ["standard", "premium", "premiumv2", "premiumv3", "isolated"]:
                    autoscale_counts["app_service_plans"] += 1
            
            # Kubernetes (AKS) with autoscaler
            elif "microsoft.containerservice/managedclusters" in res_type:
                properties = res.get("properties", {})
                if properties.get("agentPoolProfiles"):
                    for pool in properties.get("agentPoolProfiles", []):
                        if isinstance(pool, dict) and pool.get("enableAutoScaling", False):
                            autoscale_counts["kubernetes"] += 1
                            break
        
        # Check for autoscale settings from the scaling fetcher if available
        if "scaling" in data:
            autoscale_settings = data["scaling"].get("autoscale_settings", [])
            settings_count += len(autoscale_settings)
    
    # Create summary
    if sum(autoscale_counts.values()) == 0 and settings_count == 0:
        return "_No autoscaling configurations detected in the environment._"
    
    summary = []
    
    if settings_count > 0:
        summary.append(f"**{settings_count}** autoscale setting(s) configured")
    
    for resource_type, count in autoscale_counts.items():
        if count > 0:
            name = resource_type.replace("_", " ").title()
            summary.append(f"**{name}**: {count} resource(s) potentially using autoscale")
    
    return "\n".join(summary)

def _get_availability_summary(all_data):
    """Analyzes resource availability patterns (Availability Sets, Zones)."""
    # Initialize counters for various availability features
    availability_counts = {
        "vms_in_availability_sets": 0,
        "vms_in_availability_zones": 0,
        "zonal_storage_accounts": 0,
        "zonal_mysql": 0,
        "zonal_postgres": 0,
        "zonal_sql": 0,
        "zonal_aks": 0,
        "total_vms": 0
    }
    
    # Count resource groups with "dr" in name (potential DR resources)
    dr_resource_groups = set()
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        # Check for VM availability features from compute data
        compute_data = data.get("compute", [])
        if compute_data:
            availability_counts["total_vms"] += len(compute_data)
            
            for vm in compute_data:
                if isinstance(vm, dict):
                    # Check for availability zones
                    if vm.get("zones"):
                        availability_counts["vms_in_availability_zones"] += 1
                    
                    # Check for availability set
                    if vm.get("availability_set_id"):
                        availability_counts["vms_in_availability_sets"] += 1
        
        # If no compute data is available, check resources
        resources = data.get("resources", [])
        
        # Count VMs, fallback if compute fetcher not used
        if not compute_data:
            vms = [r for r in resources if isinstance(r, dict) and r.get("type") == "Microsoft.Compute/virtualMachines"]
            availability_counts["total_vms"] += len(vms)
        
        # Check for zonal/replicated resources
        for res in resources:
            if not isinstance(res, dict):
                continue
                
            res_type = res.get("type", "").lower()
            
            # Check for ZRS storage accounts
            if "microsoft.storage/storageaccounts" in res_type:
                sku = res.get("sku", {}).get("name", "").lower()
                if "zrs" in sku:
                    availability_counts["zonal_storage_accounts"] += 1
            
            # Check for zonal databases
            elif "microsoft.dbformysql/servers" in res_type:
                sku = res.get("sku", {}).get("tier", "").lower()
                if "zoneredundant" in sku or "memory" in sku:  # Memory Optimized often uses zones
                    availability_counts["zonal_mysql"] += 1
            
            elif "microsoft.dbforpostgresql/servers" in res_type:
                sku = res.get("sku", {}).get("tier", "").lower()
                if "zoneredundant" in sku or "memory" in sku:
                    availability_counts["zonal_postgres"] += 1
            
            elif "microsoft.sql/servers/databases" in res_type:
                sku = res.get("sku", {}).get("name", "").lower()
                # Premium and Business Critical tiers are zone redundant
                if "premium" in sku or "business" in sku or "critical" in sku:
                    availability_counts["zonal_sql"] += 1
            
            # Check for zonal AKS clusters
            elif "microsoft.containerservice/managedclusters" in res_type:
                if res.get("zones"):
                    availability_counts["zonal_aks"] += 1
        
        # Check for potential DR resource groups
        resource_groups = data.get("resource_groups", [])
        for rg in resource_groups:
            if isinstance(rg, dict) and rg.get("name"):
                rg_name = rg.get("name", "").lower()
                if "dr" in rg_name.split("-") or "disaster" in rg_name or "recovery" in rg_name:
                    dr_resource_groups.add(f"{rg.get('name')} (Sub: {data.get('subscription_info', {}).get('display_name', sub_id)})")
    
    # Create summary based on findings
    summary = []
    
    # VM availability analysis
    if availability_counts["total_vms"] > 0:
        vm_as_percentage = (availability_counts["vms_in_availability_sets"] / availability_counts["total_vms"]) * 100 if availability_counts["total_vms"] > 0 else 0
        vm_az_percentage = (availability_counts["vms_in_availability_zones"] / availability_counts["total_vms"]) * 100 if availability_counts["total_vms"] > 0 else 0
        
        summary.append(f"**Virtual Machines** ({availability_counts['total_vms']} total):")
        summary.append(f"- {vm_as_percentage:.1f}% in Availability Sets")
        summary.append(f"- {vm_az_percentage:.1f}% in Availability Zones")
    
    # Database availability
    db_summary = []
    if availability_counts["zonal_sql"] > 0:
        db_summary.append(f"{availability_counts['zonal_sql']} SQL Databases with zone redundancy")
    if availability_counts["zonal_mysql"] > 0:
        db_summary.append(f"{availability_counts['zonal_mysql']} MySQL Databases with zone redundancy")
    if availability_counts["zonal_postgres"] > 0:
        db_summary.append(f"{availability_counts['zonal_postgres']} PostgreSQL Databases with zone redundancy")
    
    if db_summary:
        summary.append("**Databases**:")
        for item in db_summary:
            summary.append(f"- {item}")
    
    # Storage availability
    if availability_counts["zonal_storage_accounts"] > 0:
        summary.append(f"**Storage**: {availability_counts['zonal_storage_accounts']} Storage Account(s) with ZRS/GZRS redundancy")
    
    # AKS zone redundancy
    if availability_counts["zonal_aks"] > 0:
        summary.append(f"**Kubernetes**: {availability_counts['zonal_aks']} AKS cluster(s) with zone redundancy")
    
    # DR resource groups
    if dr_resource_groups:
        summary.append("**Potential DR Resources**:")
        for rg in list(dr_resource_groups)[:3]:
            summary.append(f"- {rg}")
        if len(dr_resource_groups) > 3:
            summary.append(f"- ... and {len(dr_resource_groups) - 3} more")
    
    if not summary:
        return "_No clear availability patterns detected in the environment._"
    
    return "\n".join(summary)

def _get_load_balancing_summary(all_data):
    """Generates summary of load balancing resources."""
    # Initialize counters for load balancing resources
    lb_counts = {
        "load_balancers": 0,
        "application_gateways": 0,
        "front_doors": 0,
        "traffic_managers": 0
    }
    
    # Details for important load balancers
    lb_details = []
    appgw_details = []
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        networking = data.get("networking", {})
        
        # Check for load balancers in networking data
        if "load_balancers" in networking:
            load_balancers = networking.get("load_balancers", [])
            lb_counts["load_balancers"] += len(load_balancers)
            
            # Collect details for major load balancers
            for lb in load_balancers:
                if isinstance(lb, dict):
                    sku = lb.get("sku", {}).get("name", "Basic")
                    if sku.lower() == "standard":
                        backend_pools = len(lb.get("backend_address_pools", []))
                        lb_details.append(f"**{lb.get('name', 'Unknown')}** (Sub: {sub_name}, {backend_pools} backend pools)")
        
        # Check for App Gateways in networking data
        if "app_gateways" in networking:
            app_gateways = networking.get("app_gateways", [])
            lb_counts["application_gateways"] += len(app_gateways)
            
            # Collect details for App Gateways
            for gw in app_gateways:
                if isinstance(gw, dict):
                    sku = gw.get("sku", {}).get("name", "Standard")
                    tier = gw.get("sku", {}).get("tier", "Standard")
                    appgw_details.append(f"**{gw.get('name', 'Unknown')}** (Sub: {sub_name}, {tier} {sku})")
        
        # Fall back to resource checks if networking data is limited
        for res in resources:
            if not isinstance(res, dict):
                continue
                
            res_type = res.get("type", "").lower()
            
            # Check if we've already counted these from networking data
            if "load_balancers" not in networking and "microsoft.network/loadbalancers" in res_type:
                lb_counts["load_balancers"] += 1
            
            if "app_gateways" not in networking and "microsoft.network/applicationgateways" in res_type:
                lb_counts["application_gateways"] += 1
            
            # Check for Front Door instances
            if "microsoft.network/frontdoors" in res_type or "microsoft.cdn/profiles" in res_type and "frontdoor" in res.get("sku", {}).get("name", "").lower():
                lb_counts["front_doors"] += 1
            
            # Check for Traffic Manager profiles
            if "microsoft.network/trafficmanagerprofiles" in res_type:
                lb_counts["traffic_managers"] += 1
    
    # Create summary based on findings
    if sum(lb_counts.values()) == 0:
        return "_No load balancing resources detected in the environment._"
    
    summary = []
    
    # Overall stats
    summary.append(f"**Load Balancing Resources**:")
    for lb_type, count in lb_counts.items():
        if count > 0:
            name = lb_type.replace("_", " ").title()
            summary.append(f"- {name}: {count}")
    
    # Multi-region traffic management
    if lb_counts["front_doors"] > 0 or lb_counts["traffic_managers"] > 0:
        multi_region = []
        if lb_counts["front_doors"] > 0:
            multi_region.append(f"Azure Front Door ({lb_counts['front_doors']})")
        if lb_counts["traffic_managers"] > 0:
            multi_region.append(f"Traffic Manager ({lb_counts['traffic_managers']})")
        
        summary.append(f"**Multi-Region Traffic Management**: {', '.join(multi_region)}")
    
    # Application Delivery details
    if appgw_details:
        summary.append("**Application Delivery**:")
        for detail in appgw_details[:3]:
            summary.append(f"- {detail}")
        if len(appgw_details) > 3:
            summary.append(f"- ... and {len(appgw_details) - 3} more")
    
    # Network Load Balancer details
    if lb_details:
        summary.append("**Network Load Balancers**:")
        for detail in lb_details[:3]:
            summary.append(f"- {detail}")
        if len(lb_details) > 3:
            summary.append(f"- ... and {len(lb_details) - 3} more")
    
    return "\n".join(summary)

# --- Main Function ---

def generate_design_document(subscription_data, output_dir, tenant_name, tenant_domain, version, management_group_data=None, diagram_paths=None, timestamp_str=None, silent_mode=False):
    """Generates a comprehensive design document."""
    
    if not subscription_data:
        logging.error("No subscription data provided")
        return None

    try:
        # Initialize sections list
        doc_sections = []

        # Add Executive Summary
        doc_sections.append({
            "title": "Executive Summary",
            "content": f"""
# Azure Environment Design Document
Version: {version}
Generated: {timestamp_str if timestamp_str else datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Overview
This document provides a comprehensive overview of the Azure environment for tenant "{tenant_name}" ({tenant_domain}).
"""
        })

        # Add Subscription Overview
        doc_sections.append({
            "title": "Subscription Overview",
            "content": _get_subscriptions_table(subscription_data)
        })

        # Add Management Groups section if data available
        doc_sections.append({
            "title": "Management Groups",
            "content": _get_management_group_hierarchy_summary(management_group_data) if management_group_data else "_No management group data available._"
        })

        # Add Resource Organization
        doc_sections.append({
            "title": "Resource Organization",
            "content": _analyze_rg_naming_patterns(subscription_data)
        })

        # Add Network Architecture
        doc_sections.append({
            "title": "Network Architecture",
            "content": _analyze_network_topology(subscription_data)
        })

        # Add Network Diagrams if available
        if diagram_paths:
            doc_sections.append({
                "title": "Network Topology Diagrams",
                "content": _get_subscription_diagram_links(subscription_data, diagram_paths, output_dir)
            })

        # Add Identity & Access Management
        doc_sections.append({
            "title": "Identity & Access Management",
            "content": _analyze_rbac_approach(subscription_data)
        })

        # Add Data Platform
        doc_sections.append({
            "title": "Data Platform",
            "content": _get_data_platform_section(subscription_data)
        })

        # Add AI & Machine Learning Services
        ai_services_content = []
        ai_services_content.append("""
This section provides an overview of Azure AI and Machine Learning services deployed across the environment.

#### Overview
The following subsections detail the AI and Machine Learning services currently deployed, their configurations, and associated resources.
""")

        # Process each subscription's AI services
        for sub_id, data in subscription_data.items():
            if isinstance(data, dict) and "error" not in data:
                ai_summary = _get_ai_services_summary(data)
                if ai_summary and ai_summary != "_No AI services found in this subscription._":
                    ai_services_content.append(f"\n### Subscription: {sub_id}\n")
                    ai_services_content.append(ai_summary)

        if len(ai_services_content) == 1:  # Only has the overview text
            ai_services_content.append("\n_No AI services found across any subscriptions._")

        doc_sections.append({
            "title": "AI & Machine Learning Services",
            "content": "\n".join(ai_services_content)
        })

        # Add Security & Compliance
        doc_sections.append({
            "title": "Security & Compliance",
            "content": _get_security_section(subscription_data)
        })

        # Add Cost Analysis
        doc_sections.append({
            "title": "Cost Analysis",
            "content": _get_subscription_costs_table(subscription_data) + "\n\n" + _get_cost_optimization_summary(subscription_data)
        })

        # Generate the markdown content
        markdown_content = []
        for section in doc_sections:
            # Add section title
            markdown_content.append(f"## {section['title']}\n")
            # Add section content, ensuring it's a string
            content = section.get('content', '')
            if not isinstance(content, str):
                logging.warning(f"Non-string content found in section {section['title']}, converting to string")
                content = str(content)
            markdown_content.append(content)
            markdown_content.append("\n\n")  # Add spacing between sections

        # Write to file
        os.makedirs(output_dir, exist_ok=True)
        # Create a clean tenant name for the filename (replace spaces and special chars)
        clean_tenant_name = tenant_name.replace(" ", "_").replace("/", "_").replace("\\", "_")
        output_file = os.path.join(output_dir, f"Azure_Design_Document_{clean_tenant_name}_{timestamp_str}_v{version:.1f}.md")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(markdown_content))
        
        logging.info(f"Design document generated: {output_file}")
        return output_file

    except Exception as e:
        logging.error(f"Failed to generate design document: {str(e)}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        return None

# --- (Existing Data Aggregation & Analysis Helpers below this point remain unchanged) ---

# --- Data Aggregation & Analysis Helpers ---
# (These functions process the raw data into summaries/tables for the placeholders)

# Example: (Keep existing helper functions like _get_storage_accounts_table etc.)

# ... existing code ...

def _get_storage_accounts_table(all_data):
    """Generates Markdown table for Storage Accounts."""
    headers = ["Subscription", "Name", "SKU", "Access Tier", "Location", "Security"]
    rows = []
    found_any = False

    for sub_id, data in all_data.items():
        if "error" in data:
            continue
            
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        storage_data = data.get("storage", {})
        
        if not isinstance(storage_data, dict):
            continue
            
        for account in storage_data.get("storage_accounts", []):
            found_any = True
            
            # Get SKU details
            sku = account.get("sku", {})
            sku_name = sku.get("name", "Unknown")
            sku_tier = sku.get("tier", "Standard")
            
            # Build security features list
            security_features = []
            if account.get("enable_https_traffic_only"):
                security_features.append("HTTPS")
            if account.get("encryption", {}).get("key_source") == "Microsoft.Keyvault":
                security_features.append("CMK")
            
            # Check network rules
            network_rules = account.get("network_rule_set", {})
            if network_rules.get("default_action") == "Deny":
                security_features.append("Firewall")
            if network_rules.get("virtual_network_rules"):
                security_features.append("VNet")
            
            # Check private endpoints
            if account.get("private_endpoint_connections"):
                security_features.append("PE")
                
            # Check soft delete settings
            blob_props = account.get("blob_service_properties", {})
            if blob_props.get("delete_retention_policy", {}).get("enabled"):
                days = blob_props.get("delete_retention_policy", {}).get("days")
                security_features.append(f"Soft-Delete({days}d)")
            
            rows.append([
                sub_name,
                account.get("name", "Unknown"),
                f"{sku_tier} ({sku_name})",
                account.get("access_tier", "Unknown"),
                account.get("location", "Unknown"),
                ", ".join(security_features) if security_features else "Basic"
            ])

    if not found_any:
        return "_No Storage Accounts detected in the environment._"
        
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_data_lake_analysis(all_data):
    """Analyzes usage of Azure Data Lake Storage (ADLS Gen2)."""
    adls_count = 0
    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data: continue
        resources = data.get("resources", [])
        for res in resources:
            if isinstance(res, dict) and res.get("type", "").lower() == "microsoft.storage/storageaccounts":
                properties = res.get("properties", {})
                if properties.get("isHnsEnabled", False): # Key indicator for ADLS Gen2
                    adls_count += 1
                    
    if adls_count > 0:
        return f"Detected **{adls_count}** Storage Account(s) configured as Azure Data Lake Storage Gen2 (Hierarchical Namespace Enabled)."
    else:
        return "_No Azure Data Lake Storage Gen2 usage detected (based on Hierarchical Namespace status)._"

def _get_backup_storage_analysis(all_data):
    """Analyzes storage used by Azure Backup (Recovery Services Vaults)."""
    # Re-use the redundancy summary logic from monitoring section
    return _get_backup_redundancy_summary(all_data) or "_Backup storage analysis unavailable._"

def _get_databases_table(all_data, db_type="all"):
    """Generates Markdown table for databases (SQL DB, MySQL, PostgreSQL, Cosmos DB)."""
    headers = ["Subscription", "Name", "Type", "SKU/Tier", "Location", "Status"]
    rows = []
    found_any = False

    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        
        # Use the new database fetcher data
        db_data = data.get("database", {})
        if not isinstance(db_data, dict):
            continue

        # SQL Databases
        for server in db_data.get("sql_servers", []):
            server_name = server.get("name", "Unknown")
            for db in db_data.get("sql_databases", []):
                if db.get("server_name") == server_name:
                    found_any = True
                    is_relational = True
                    sku = db.get("sku", {})
                    sku_name = sku.get("name", "Unknown")
                    tier = sku.get("tier", "Unknown")
                    rows.append([
                        sub_name,
                        f"{server_name}/{db.get('name', 'Unknown')}",
                        "Azure SQL Database",
                        f"{tier} ({sku_name})",
                        db.get("location", "Unknown"),
                        db.get("status", "Unknown")
                    ])

        # SQL Elastic Pools
        for pool in db_data.get("sql_elastic_pools", []):
            found_any = True
            is_relational = True
            sku = pool.get("sku", {})
            rows.append([
                sub_name,
                f"{pool.get('server_name', 'Unknown')}/{pool.get('name', 'Unknown')}",
                "SQL Elastic Pool",
                f"{sku.get('tier', 'Unknown')} ({sku.get('name', 'Unknown')})",
                pool.get("location", "Unknown"),
                pool.get("state", "Unknown")
            ])

        # Cosmos DB
        for account in db_data.get("cosmos_accounts", []):
            found_any = True
            is_nosql = True
            consistency = account.get("consistency_policy", {}).get("default_consistency_level", "Unknown")
            locations = len(account.get("write_locations", [])) + len(account.get("read_locations", []))
            
            # Add the account itself
            rows.append([
                sub_name,
                account.get("name", "Unknown"),
                f"Cosmos DB Account ({account.get('kind', 'Unknown')})",
                f"Multi-region: {locations} regions",
                account.get("location", "Unknown"),
                f"Consistency: {consistency}"
            ])
            
            # Add each database under the account
            for db in db_data.get("cosmos_databases", []):
                if db.get("account_name") == account.get("name"):
                    throughput = db.get("throughput", "Unknown RU/s")
                    if db.get("auto_scale_settings"):
                        max_throughput = db.get("auto_scale_settings", {}).get("max_throughput", "Unknown")
                        throughput = f"Autoscale (max: {max_throughput} RU/s)"
                    
                    rows.append([
                        sub_name,
                        f"{account.get('name', 'Unknown')}/{db.get('name', 'Unknown')}",
                        "Cosmos DB Database",
                        throughput,
                        db.get("location", "Unknown"),
                        "Active"  # Cosmos DB databases are always active if visible
                    ])
    
    if not found_any or not rows:
        return f"_No {db_type.replace('all','').capitalize()} databases detected in the environment._"
    
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1], x[2])))

def _get_analytics_services_table(all_data):
    """Generates Markdown table for common Analytics Services (Synapse, Data Factory, Databricks)."""
    headers = ["Subscription", "Name", "Type", "Location"]
    rows = []
    found_any = False
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        resources = data.get("resources", [])
        
        for res in resources:
            if not isinstance(res, dict): continue
            res_type = res.get("type", "").lower()
            service_type = None
            
            if "microsoft.synapse/workspaces" in res_type:
                service_type = "Synapse Analytics Workspace"
            elif "microsoft.datafactory/factories" in res_type:
                service_type = "Data Factory"
            elif "microsoft.databricks/workspaces" in res_type:
                service_type = "Databricks Workspace"
            
            if service_type:
                found_any = True
                rows.append([
                    sub_name,
                    res.get("name", "Unknown"),
                    service_type,
                    res.get("location", "Unknown")
                ])
    
    if not found_any:
        return "_No common Azure Analytics services detected (Synapse, Data Factory, Databricks)._"
        
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: (x[0], x[1])))

def _get_encryption_strategy_summary(all_data):
    """Summarizes data encryption status based on common services."""
    summary_points = [] 
    checked_resources = {"storage": 0, "sql": 0, "kv": 0, "disk": 0}
    encrypted_resources = {"storage_https": 0, "sql_tde": 0, "kv_soft_delete": 0, "disk_ade_sse_cmk": 0}
    
    for sub_id, data in all_data.items():
        if "error" in data: continue
        resources = data.get("resources", [])
        for res in resources:
            if not isinstance(res, dict): continue
            res_type = res.get("type", "").lower()
            properties = res.get("properties", {})
            
            # Storage Accounts
            if "microsoft.storage/storageaccounts" in res_type:
                checked_resources["storage"] += 1
                if properties.get("supportsHttpsTrafficOnly", False):
                    encrypted_resources["storage_https"] += 1
                    
            # SQL Databases (TDE is default, check for explicit disable is complex)
            elif "microsoft.sql/servers/databases" in res_type:
                 checked_resources["sql"] += 1
                 # Assume TDE enabled unless evidence otherwise (hard to check)
                 encrypted_resources["sql_tde"] += 1 
                 
            # Key Vaults (Soft delete implies some level of protection)
            elif "microsoft.keyvault/vaults" in res_type:
                 checked_resources["kv"] += 1
                 if properties.get("enableSoftDelete", False):
                     encrypted_resources["kv_soft_delete"] += 1
                     
            # Managed Disks (Check encryption settings)
            elif "microsoft.compute/disks" in res_type:
                 checked_resources["disk"] += 1
                 encryption = properties.get("encryption", {})
                 # SSE with PMK is default, check for ADE or CMK
                 if encryption.get("type") in ["EncryptionAtRestWithPlatformKey", "EncryptionAtRestWithCustomerKey", "AzureDiskEncryption"]:
                     encrypted_resources["disk_ade_sse_cmk"] += 1
                     
    # Generate Summary
    if checked_resources["storage"] > 0:
        https_perc = (encrypted_resources["storage_https"] / checked_resources["storage"]) * 100 if checked_resources["storage"] > 0 else 0
        summary_points.append(f"- **Storage Accounts**: HTTPS traffic required on {https_perc:.1f}% (transit)")
    
    if checked_resources["sql"] > 0:
        # Note TDE is default
        summary_points.append(f"- **SQL Databases**: Transparent Data Encryption (TDE) enabled by default (at rest)")
        
    if checked_resources["disk"] > 0:
         disk_perc = (encrypted_resources["disk_ade_sse_cmk"] / checked_resources["disk"]) * 100 if checked_resources["disk"] > 0 else 0
         summary_points.append(f"- **Managed Disks**: {disk_perc:.1f}% using detected encryption (SSE-PMK/CMK or ADE) (at rest)")
         
    if checked_resources["kv"] > 0:
         kv_perc = (encrypted_resources["kv_soft_delete"] / checked_resources["kv"]) * 100 if checked_resources["kv"] > 0 else 0
         summary_points.append(f"- **Key Vaults**: Soft-delete enabled on {kv_perc:.1f}% (recovery)")
         
    if not summary_points:
         return "_Encryption status analysis unavailable or no relevant resources found._"
         
    return "Data Encryption Highlights (At Rest & Transit):\n" + "\n".join(summary_points)

def _get_data_classification_analysis(all_data):
    """Placeholder for data classification analysis."""
    # Requires analyzing SQL DB sensitivity labels or Purview scans
    return "_Data classification status (e.g., using SQL Sensitivity Labels or Purview) requires deeper analysis not yet implemented._"

def _get_data_sovereignty_analysis(all_data):
    """Analyzes resource locations to infer data sovereignty adherence."""
    region_counts = {}
    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data: continue
        for res in data["resources"]:
            if isinstance(res, dict) and "location" in res:
                loc = res["location"]
                if loc: region_counts[loc] = region_counts.get(loc, 0) + 1
    
    if not region_counts:
        return "_Could not analyze resource locations for data sovereignty._"
        
    # Simply list the top regions where resources reside
    sorted_regions = sorted(region_counts.items(), key=lambda item: item[1], reverse=True)
    primary_regions = [f"{region} ({count} resources)" for region, count in sorted_regions[:3]]
    return f"Resources primarily located in: {', '.join(primary_regions)}. Ensure these align with data sovereignty requirements."

def _get_subscription_costs_table(all_data):
    """Generates Markdown table for subscription costs."""
    headers = ["Subscription", "MTD Cost", "YTD Cost", "Forecast (30d)", "Currency"]
    rows = []
    
    for sub_id, data in all_data.items():
        if "error" in data or "costs" not in data:
            continue
            
        costs = data.get("costs", {})
        sub_name = data.get("subscription_info", {}).get("display_name", sub_id)
        currency = costs.get("currency", "N/A")
        
        mtd_cost = f"{costs.get('mtd_actual_cost', 'N/A'):,.2f}" if costs.get('mtd_actual_cost') is not None else "N/A"
        ytd_cost = f"{costs.get('ytd_actual_cost', 'N/A'):,.2f}" if costs.get('ytd_actual_cost') is not None else "N/A"
        forecast = f"{costs.get('forecast_cost', 'N/A'):,.2f}" if costs.get('forecast_cost') is not None else "N/A"
        
        rows.append([sub_name, mtd_cost, ytd_cost, forecast, currency])
    
    if not rows:
        return "_No cost data available. This may be due to insufficient permissions or no cost data for the current period._"
    
    return _generate_markdown_table(headers, sorted(rows, key=lambda x: float(x[1].replace(',', '')) if x[1] != 'N/A' else 0, reverse=True))

def _get_resource_type_costs(all_data):
    """Analyzes and summarizes costs by resource type."""
    resource_costs = {}
    total_cost = 0
    currency = None
    
    for sub_id, data in all_data.items():
        if "error" in data or "costs" not in data:
            continue
            
        costs = data.get("costs", {})
        if not currency:
            currency = costs.get("currency")
            
        for resource in costs.get("resource_costs", []):
            resource_type = resource.get("resource_type", "Unknown")
            cost = resource.get("cost", 0)
            resource_costs[resource_type] = resource_costs.get(resource_type, 0) + cost
            total_cost += cost
    
    if not resource_costs:
        return "_No resource cost data available._"
    
    # Sort by cost and get top resource types
    sorted_costs = sorted(resource_costs.items(), key=lambda x: x[1], reverse=True)
    top_resources = sorted_costs[:5]  # Get top 5 resource types
    
    summary = []
    summary.append("**Top Resource Types by Cost:**")
    for resource_type, cost in top_resources:
        percentage = (cost / total_cost * 100) if total_cost > 0 else 0
        summary.append(f"- {resource_type}: {cost:,.2f} {currency} ({percentage:.1f}%)")
    
    if len(sorted_costs) > 5:
        other_cost = sum(cost for _, cost in sorted_costs[5:])
        other_percentage = (other_cost / total_cost * 100) if total_cost > 0 else 0
        summary.append(f"- Others: {other_cost:,.2f} {currency} ({other_percentage:.1f}%)")
    
    return "\n".join(summary)

def _get_cost_allocation_summary(all_data):
    """Analyzes cost allocation based on tags and resource groups."""
    summary = []
    tagged_resources = 0
    total_resources = 0
    total_cost = 0
    cost_by_rg = {}
    
    for sub_id, data in all_data.items():
        if "error" in data or "costs" not in data:
            continue
            
        costs = data.get("costs", {})
        currency = costs.get("currency", "N/A")
        
        for resource in costs.get("resource_costs", []):
            total_resources += 1
            cost = resource.get("cost", 0)
            total_cost += cost
            
            # Extract resource group from resource ID
            resource_id = resource.get("resource_id", "")
            rg_name = resource_id.split('/')[4] if len(resource_id.split('/')) > 4 else "Unknown"
            cost_by_rg[rg_name] = cost_by_rg.get(rg_name, 0) + cost
    
    if not total_resources:
        return "_No cost allocation data available._"
    
    # Get top resource groups by cost
    sorted_rgs = sorted(cost_by_rg.items(), key=lambda x: x[1], reverse=True)[:5]
    
    summary.append("**Cost Allocation Summary:**")
    summary.append(f"- Total Monthly Cost: {total_cost:,.2f} {currency}")
    summary.append("\n**Top Resource Groups by Cost:**")
    for rg, cost in sorted_rgs:
        percentage = (cost / total_cost * 100) if total_cost > 0 else 0
        summary.append(f"- {rg}: {cost:,.2f} {currency} ({percentage:.1f}%)")
    
    return "\n".join(summary)

def _get_cost_optimization_summary(all_data):
    """Analyzes potential cost optimization opportunities."""
    summary = []
    vm_costs = {}
    storage_costs = {}
    currency = None
    
    for sub_id, data in all_data.items():
        if "error" in data or "costs" not in data:
            continue
            
        costs = data.get("costs", {})
        if not currency:
            currency = costs.get("currency")
            
        for resource in costs.get("resource_costs", []):
            resource_type = resource.get("resource_type", "").lower()
            cost = resource.get("cost", 0)
            
            if "virtualmachines" in resource_type:
                vm_costs[resource.get("resource_id")] = cost
            elif "storageaccounts" in resource_type:
                storage_costs[resource.get("resource_id")] = cost
    
    if not vm_costs and not storage_costs:
        return "_No cost optimization data available._"
    
    summary.append("**Cost Optimization Opportunities:**")
    
    # VM Cost Analysis
    if vm_costs:
        total_vm_cost = sum(vm_costs.values())
        summary.append(f"\n*Virtual Machine Costs:*")
        summary.append(f"- Total VM Cost: {total_vm_cost:,.2f} {currency}")
        if len(vm_costs) > 0:
            avg_vm_cost = total_vm_cost / len(vm_costs)
            summary.append(f"- Average Cost per VM: {avg_vm_cost:,.2f} {currency}")
            
            # Identify potentially oversized VMs (significantly above average)
            expensive_vms = [(vm, cost) for vm, cost in vm_costs.items() if cost > avg_vm_cost * 1.5]
            if expensive_vms:
                summary.append("- VMs to Review (Above 150% avg cost):")
                for vm, cost in sorted(expensive_vms, key=lambda x: x[1], reverse=True)[:3]:
                    vm_name = vm.split('/')[-1]
                    summary.append(f"  * {vm_name}: {cost:,.2f} {currency}")
    
    # Storage Cost Analysis
    if storage_costs:
        total_storage_cost = sum(storage_costs.values())
        summary.append(f"\n*Storage Costs:*")
        summary.append(f"- Total Storage Cost: {total_storage_cost:,.2f} {currency}")
        if len(storage_costs) > 0:
            avg_storage_cost = total_storage_cost / len(storage_costs)
            summary.append(f"- Average Cost per Storage Account: {avg_storage_cost:,.2f} {currency}")
    
    return "\n".join(summary)

# ... rest of the existing code ...

def _get_ai_services_summary(data):
    """
    Generates a summary of AI services for a subscription.
    """
    if not data or not isinstance(data, dict):
        return "_No AI services data available._"

    # Get AI services data
    ai_data = data.get("ai_services", {})
    if not ai_data or not isinstance(ai_data, dict):
        return "_No AI services found in this subscription._"

    sections = []
    
    # Cognitive Services
    cognitive_services = ai_data.get("cognitive_services", [])
    if cognitive_services and isinstance(cognitive_services, list):
        sections.append("#### Cognitive Services\n")
        headers = ["Name", "Type", "Location", "SKU"]
        rows = []
        for service in cognitive_services:
            if isinstance(service, dict):
                rows.append([
                    service.get("name", "N/A"),
                    service.get("type", "N/A"),
                    service.get("location", "N/A"),
                    service.get("sku", "N/A")
                ])
        if rows:
            sections.append(_generate_markdown_table(headers, sorted(rows, key=lambda x: x[0])))
            sections.append("\n")

    # Search Services
    search_services = ai_data.get("search_services", [])
    if search_services and isinstance(search_services, list):
        sections.append("#### Azure Search Services\n")
        headers = ["Name", "Location", "SKU", "Replicas", "Partitions"]
        rows = []
        for service in search_services:
            if isinstance(service, dict):
                rows.append([
                    service.get("name", "N/A"),
                    service.get("location", "N/A"),
                    service.get("sku", "N/A"),
                    str(service.get("replica_count", "N/A")),
                    str(service.get("partition_count", "N/A"))
                ])
        if rows:
            sections.append(_generate_markdown_table(headers, sorted(rows, key=lambda x: x[0])))
            sections.append("\n")

    # Bot Services
    bot_services = ai_data.get("bot_services", [])
    if bot_services and isinstance(bot_services, list):
        sections.append("#### Bot Services\n")
        headers = ["Name", "Location", "Kind", "SKU"]
        rows = []
        for service in bot_services:
            if isinstance(service, dict):
                rows.append([
                    service.get("name", "N/A"),
                    service.get("location", "N/A"),
                    service.get("kind", "N/A"),
                    service.get("sku", "N/A")
                ])
        if rows:
            sections.append(_generate_markdown_table(headers, sorted(rows, key=lambda x: x[0])))
            sections.append("\n")

    if not sections:
        return "_No AI services found in this subscription._"

    return "\n".join(sections)

def _get_data_platform_section(subscription_data):
    """
    Generates the Data Platform section of the design document.
    This section covers databases, storage accounts, data lakes, and analytics services.
    """
    sections = []
    
    sections.append("""
This section provides an overview of data platform services deployed across the environment, including databases, storage accounts, data lakes, and analytics services.

#### Overview
The following subsections detail the data platform components currently deployed, their configurations, and associated resources.
""")

    # Add Storage Accounts summary
    sections.append("### Storage Accounts\n")
    storage_table = _get_storage_accounts_table(subscription_data)
    sections.append(storage_table if storage_table else "_No storage accounts found._\n")

    # Add Database summary
    sections.append("\n### Databases\n")
    db_table = _get_databases_table(subscription_data)
    sections.append(db_table if db_table else "_No databases found._\n")

    # Add Analytics Services
    sections.append("\n### Analytics Services\n")
    analytics_table = _get_analytics_services_table(subscription_data)
    sections.append(analytics_table if analytics_table else "_No analytics services found._\n")

    # Add Data Lake Analysis
    sections.append("\n### Data Lake Storage\n")
    lake_analysis = _get_data_lake_analysis(subscription_data)
    sections.append(lake_analysis if lake_analysis else "_No data lake storage found._\n")

    # Add Data Classification and Sovereignty
    sections.append("\n### Data Governance\n")
    
    sections.append("#### Data Classification\n")
    classification = _get_data_classification_analysis(subscription_data)
    sections.append(classification if classification else "_No data classification information available._\n")
    
    sections.append("\n#### Data Sovereignty\n")
    sovereignty = _get_data_sovereignty_analysis(subscription_data)
    sections.append(sovereignty if sovereignty else "_No data sovereignty information available._\n")

    return "\n".join(sections)

def _get_security_section(subscription_data):
    """
    Generates the Security & Compliance section of the design document.
    This section covers security controls, compliance status, and security recommendations.
    """
    sections = []
    
    sections.append("""
This section provides an overview of security controls and compliance status across the environment, including Microsoft Defender for Cloud status, security recommendations, and key security controls.

#### Overview
The following subsections detail the security posture, controls, and compliance status of the environment.
""")

    # Add Defender for Cloud Status
    sections.append("### Microsoft Defender for Cloud Status\n")
    defender_status = _get_defender_status(subscription_data)
    sections.append(defender_status if defender_status else "_Microsoft Defender status information not available._\n")

    # Add Security Recommendations
    sections.append("\n### Security Recommendations\n")
    security_recs = _get_security_recs_table(subscription_data)
    sections.append(security_recs if security_recs else "_No security recommendations found._\n")

    # Add Key Vault Security
    sections.append("\n### Key Vault Security\n")
    kv_access = _get_key_vault_access_model(subscription_data)
    sections.append(kv_access if kv_access else "_No Key Vault access information available._\n")

    # Add Sentinel Status
    sections.append("\n### Microsoft Sentinel Status\n")
    sentinel_status = _get_sentinel_status(subscription_data)
    sections.append(sentinel_status if sentinel_status else "_Microsoft Sentinel status information not available._\n")

    # Add Identity Security
    sections.append("\n### Identity Security\n")
    
    sections.append("#### Privileged Access Management\n")
    pim_status = _analyze_pim_status(subscription_data)
    sections.append(pim_status if pim_status else "_No PIM information available._\n")
    
    sections.append("\n#### Service Principal Security\n")
    sp_analysis = _analyze_service_principals(subscription_data)
    sections.append(sp_analysis if sp_analysis else "_No service principal analysis available._\n")

    # Add Network Security
    sections.append("\n### Network Security\n")
    
    # Add Firewall Summary
    sections.append("#### Firewall Configuration\n")
    fw_table = _get_firewalls_table(subscription_data)
    sections.append(fw_table if fw_table else "_No Azure Firewalls found._\n")
    
    # Add WAF Summary
    sections.append("\n#### Web Application Firewall (WAF)\n")
    waf_summary = _get_waf_summary(subscription_data)
    sections.append(waf_summary if waf_summary else "_No WAF policies found._\n")
    
    # Add DDoS Protection
    sections.append("\n#### DDoS Protection\n")
    ddos_table = _get_ddos_table(subscription_data)
    sections.append(ddos_table if ddos_table else "_No DDoS protection plans found._\n")

    # Add Encryption Strategy
    sections.append("\n### Encryption Strategy\n")
    encryption_summary = _get_encryption_strategy_summary(subscription_data)
    sections.append(encryption_summary if encryption_summary else "_No encryption strategy information available._\n")

    return "\n".join(sections)