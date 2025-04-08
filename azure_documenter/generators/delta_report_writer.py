import os
import logging
import datetime

# Define output directories relative to the main script or a base path
REPORT_DIR = "reports"

def generate_delta_report(delta_data, timestamp1, timestamp2, base_output_dir):
    """Generates a Markdown report highlighting the differences between two audits.
    
    Args:
        delta_data (dict): The output from analyze_delta function
        timestamp1 (str): Timestamp of the "before" audit
        timestamp2 (str): Timestamp of the "after" audit
        base_output_dir (str): Base directory for outputs
        
    Returns:
        str: Path to the generated report file, or None if failed
    """
    report_path = os.path.join(base_output_dir, REPORT_DIR)
    os.makedirs(report_path, exist_ok=True)

    # Construct filename
    report_filename = f"delta_report_{timestamp1}_vs_{timestamp2}.md"
    report_filepath = os.path.join(report_path, report_filename)

    md_content = []
    md_content.append(f"# Azure Infrastructure Delta Report")
    md_content.append(f"Comparing audit run `{timestamp1}` (Before) vs. `{timestamp2}` (After)")
    md_content.append(f"Generated on: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")

    # --- Subscription Level Changes ---
    md_content.append("\n## Subscription Changes")
    added_subs = delta_data.get("subscriptions", {}).get("added", [])
    removed_subs = delta_data.get("subscriptions", {}).get("removed", [])
    if added_subs:
        md_content.append("\n**Added Subscriptions:**")
        for sub in added_subs:
            md_content.append(f"- `{sub.get('id')}` ({sub.get('display_name', 'N/A')}) ")
    if removed_subs:
        md_content.append("\n**Removed Subscriptions:**")
        for sub in removed_subs:
            md_content.append(f"- `{sub.get('id')}` ({sub.get('display_name', 'N/A')}) ")
    if not added_subs and not removed_subs:
        md_content.append("_No subscriptions added or removed._")

    # --- Detailed Subscription Deltas ---
    sub_details = delta_data.get("subscriptions", {}).get("details", {})
    for sub_id, details in sub_details.items():
        md_content.append(f"\n---\n## Delta for Subscription: `{sub_id}`")

        if details.get("error"):
            md_content.append(f"**Note:** {details['error']}")
            continue

        # --- Resource Delta ---
        res_delta = details.get("resources", {})
        res_added = res_delta.get("added", [])
        res_removed = res_delta.get("removed", [])
        res_modified = res_delta.get("modified", [])
        if res_added or res_removed or res_modified:
            md_content.append("\n### Resource Changes")
            md_content.append(f"**Summary:** +{len(res_added)} added, -{len(res_removed)} removed, ~{len(res_modified)} modified")
            
            if res_added:
                md_content.append("\n**Added Resources:**")
                md_content.append("\n| Name | Type | Location | Resource Group | ID |")
                md_content.append("|---|---|---|---|---|")
                for item in sorted(res_added, key=lambda x: x.get('name', 'N/A')):
                    md_content.append(f"| {item.get('name','N/A')} | `{item.get('type','N/A')}` | {item.get('location','N/A')} | {item.get('resource_group','N/A')} | `{item.get('id','N/A')}` |")
            
            if res_removed:
                md_content.append("\n**Removed Resources:**")
                md_content.append("\n| Name | Type | Location | Resource Group | ID |")
                md_content.append("|---|---|---|---|---|")
                for item in sorted(res_removed, key=lambda x: x.get('name', 'N/A')):
                    # Use strikethrough for removed items
                    md_content.append(f"| ~~{item.get('name','N/A')}~~ | `{item.get('type','N/A')}` | {item.get('location','N/A')} | {item.get('resource_group','N/A')} | `{item.get('id','N/A')}` |")
            
            if res_modified:
                md_content.append("\n**Modified Resources:**")
                md_content.append("\n| Name | Type | Resource Group | Changes |")
                md_content.append("|---|---|---|---|")
                for item in sorted(res_modified, key=lambda x: x.get('name', 'N/A')):
                    before = item.get("before", {})
                    after = item.get("after", {})
                    # Find specific changes for common fields
                    changes = []
                    # Check location changes
                    if before.get("location") != after.get("location"):
                        changes.append(f"Location: {before.get('location', 'N/A')} → {after.get('location', 'N/A')}")
                    # Check tags changes - display differently
                    before_tags = before.get("tags", {}) or {}
                    after_tags = after.get("tags", {}) or {}
                    if before_tags != after_tags:
                        changes.append("Tags changed")
                    # If no specific changes detected, just note modification
                    if not changes:
                        changes.append("Properties modified")
                    changes_text = "<br>".join(changes)
                    md_content.append(f"| {item.get('name','N/A')} | `{before.get('type','N/A')}` | {before.get('resource_group','N/A')} | {changes_text} |")

        # --- Networking Delta ---
        net_delta = details.get("networking", {})
        if net_delta:
            md_content.append("\n### Networking Changes")

            # VNets
            vnet_delta = net_delta.get("vnets", {})
            if vnet_delta.get("added") or vnet_delta.get("removed") or vnet_delta.get("modified"):
                md_content.append("\n#### Virtual Networks")
                md_content.append(f"**Summary:** +{len(vnet_delta.get('added', []))} added, -{len(vnet_delta.get('removed', []))} removed, ~{len(vnet_delta.get('modified', []))} modified")
                
                # Added VNets
                if vnet_delta.get("added"):
                    md_content.append("\n**Added VNets:**")
                    md_content.append("\n| Name | Location | Address Space | Resource Group |")
                    md_content.append("|---|---|---|---|")
                    for item in sorted(vnet_delta.get("added", []), key=lambda x: x.get('name', 'N/A')):
                        address_space = ", ".join(item.get("address_space", []))
                        md_content.append(f"| {item.get('name','N/A')} | {item.get('location','N/A')} | `{address_space}` | {item.get('resource_group','N/A')} |")
                
                # Removed VNets
                if vnet_delta.get("removed"):
                    md_content.append("\n**Removed VNets:**")
                    md_content.append("\n| Name | Location | Address Space | Resource Group |")
                    md_content.append("|---|---|---|---|")
                    for item in sorted(vnet_delta.get("removed", []), key=lambda x: x.get('name', 'N/A')):
                        address_space = ", ".join(item.get("address_space", []))
                        md_content.append(f"| ~~{item.get('name','N/A')}~~ | {item.get('location','N/A')} | `{address_space}` | {item.get('resource_group','N/A')} |")
                
                # Modified VNets
                if vnet_delta.get("modified"):
                    md_content.append("\n**Modified VNets:**")
                    md_content.append("\n| Name | Resource Group | Changes |")
                    md_content.append("|---|---|---|")
                    for item in sorted(vnet_delta.get("modified", []), key=lambda x: x.get('name', 'N/A')):
                        before = item.get("before", {})
                        after = item.get("after", {})
                        changes = []
                        if before.get("address_space") != after.get("address_space"):
                            before_space = ", ".join(before.get("address_space", []))
                            after_space = ", ".join(after.get("address_space", []))
                            changes.append(f"Address Space: `{before_space}` → `{after_space}`")
                        if not changes:
                            changes.append("Properties modified")
                        changes_text = "<br>".join(changes)
                        md_content.append(f"| {item.get('name','N/A')} | {before.get('resource_group','N/A')} | {changes_text} |")

            # Subnets, Peerings, NSGs - similar pattern to VNets but with their specific fields
            # Abbreviated for brevity; expand as needed to match the data structure

        # --- Governance Delta (Brief Version) ---
        gov_delta = details.get("governance", {})
        if gov_delta:
            md_content.append("\n### Governance Changes")
            
            # Policy States
            policy_delta = gov_delta.get("policy_states", {})
            if policy_delta.get("added") or policy_delta.get("removed"):
                md_content.append("\n#### Policy Compliance")
                md_content.append(f"**Summary:** +{len(policy_delta.get('added', []))} new non-compliant, -{len(policy_delta.get('removed', []))} resolved")
                
                # Details could be expanded but might get too verbose

            # Advisor Recommendations
            rec_delta = gov_delta.get("advisor_recommendations", {})
            if rec_delta.get("added") or rec_delta.get("removed"):
                md_content.append("\n#### Advisor Recommendations")
                md_content.append(f"**Summary:** +{len(rec_delta.get('added', []))} new, -{len(rec_delta.get('removed', []))} resolved")
                
                # New recommendations
                if rec_delta.get("added"):
                    md_content.append("\n**New Recommendations:**")
                    for item in rec_delta.get("added", []):
                        md_content.append(f"- {item.get('short_description', 'N/A')} (Impact: {item.get('impact', 'N/A')})")
                
                # Resolved recommendations
                if rec_delta.get("removed"):
                    md_content.append("\n**Resolved Recommendations:**")
                    for item in rec_delta.get("removed", []):
                        md_content.append(f"- ~~{item.get('short_description', 'N/A')}~~ (Impact: {item.get('impact', 'N/A')})")

    # --- Save Markdown Report ---
    try:
        with open(report_filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(md_content))
        logging.info(f"Successfully generated Delta Report: {report_filepath}")
        return report_filepath
    except Exception as e:
        logging.error(f"Failed to write Delta Report: {e}")
        return None 