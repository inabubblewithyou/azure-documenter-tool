"""
Analysis helpers for the design document writer.
Contains helper functions that analyze Azure resource data and produce summaries.
"""

import logging
from collections import defaultdict

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
    
    # Collect all resource group names from the main resources list
    all_rg_names = set() # Use a set to automatically handle duplicates
    for sub_id, data in all_data.items():
        if "error" in data or "resources" not in data:
            continue
        resources = data.get("resources", [])
        for resource in resources:
            if isinstance(resource, dict) and "resource_group" in resource:
                rg_name = resource.get("resource_group")
                if rg_name: # Check if resource_group is not None or empty
                    all_rg_names.add(rg_name)
    
    # Convert set to list for analysis
    all_rgs_list = list(all_rg_names)

    if not all_rgs_list:
        return "_No resource groups found in the environment._"
    
    # Analyze patterns - look for common prefixes
    prefix_counts = {}
    for rg_name in all_rgs_list: # Use the corrected list
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
        percentage = (count / len(all_rgs_list)) * 100 # Use the corrected list length
        prefix_summary.append(f"- Prefix `{prefix}-`: {count} groups ({percentage:.1f}% of total)")
    
    if prefix_summary:
        pattern_text = "\n".join(prefix_summary)
        return f"Common patterns detected in {len(all_rgs_list)} resource groups:\n{pattern_text}" # Use the corrected list length
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
    
    total_assignments = sum([role_assignment_counts["user"], role_assignment_counts["group"], 
                          role_assignment_counts["service_principal"], role_assignment_counts["managed_identity"]])
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
    built_in_percentage = (role_assignment_counts["built_in"] / (role_assignment_counts["built_in"] + role_assignment_counts["custom"])) * 100 if (role_assignment_counts["built_in"] + role_assignment_counts["custom"]) > 0 else 0
    rbac_summary.append(f"**{built_in_percentage:.1f}%** of roles are built-in (vs. custom)")
    
    # Analyze scope distribution
    total_scopes = sum([role_assignment_counts["subscription"], role_assignment_counts["resource_group"], role_assignment_counts["resource"]])
    if total_scopes > 0:
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
    system_percentage = (identity_counts["system_assigned"] / total_identities) * 100 if total_identities > 0 else 0
    user_percentage = (identity_counts["user_assigned"] / total_identities) * 100 if total_identities > 0 else 0
    dual_percentage = (identity_counts["dual_mode"] / total_identities) * 100 if total_identities > 0 else 0
    
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

def _analyze_lifecycle_policies(all_data):
    """Analyzes resource lifecycle policies and retention settings.
    
    Args:
        all_data (dict): Dictionary of subscription data from fetchers.
        
    Returns:
        str: Markdown-formatted summary of lifecycle policies.
    """
    if not all_data:
        return "_No subscription data available for lifecycle policy analysis._"
    
    # Track lifecycle policy usage
    lifecycle_counts = {
        "storage_lifecycle": 0,
        "total_storage": 0,
        "key_vault_soft_delete": 0,
        "total_key_vaults": 0,
        "vm_backup": 0,
        "total_vms": 0
    }
    
    for sub_id, data in all_data.items():
        if "error" in data:
            continue
        
        # Check Storage Account lifecycle policies
        if "storage_accounts" in data:
            storage_accounts = data.get("storage_accounts", [])
            lifecycle_counts["total_storage"] += len(storage_accounts)
            
            for sa in storage_accounts:
                if not isinstance(sa, dict):
                    continue
                
                if sa.get("has_lifecycle_policy", False):
                    lifecycle_counts["storage_lifecycle"] += 1
        
        # Check Key Vault soft delete
        if "key_vaults" in data:
            key_vaults = data.get("key_vaults", [])
            lifecycle_counts["total_key_vaults"] += len(key_vaults)
            
            for kv in key_vaults:
                if not isinstance(kv, dict):
                    continue
                
                if kv.get("soft_delete_enabled", False):
                    lifecycle_counts["key_vault_soft_delete"] += 1
        
        # Check VM backup status
        if "virtual_machines" in data:
            vms = data.get("virtual_machines", [])
            lifecycle_counts["total_vms"] += len(vms)
            
            for vm in vms:
                if not isinstance(vm, dict):
                    continue
                
                if vm.get("has_backup", False):
                    lifecycle_counts["vm_backup"] += 1
    
    # Create summary
    summary = []
    
    # Add storage lifecycle stats
    if lifecycle_counts["total_storage"] > 0:
        storage_percentage = (lifecycle_counts["storage_lifecycle"] / lifecycle_counts["total_storage"]) * 100
        summary.append(f"- **{storage_percentage:.1f}%** of Storage Accounts have blob lifecycle management")
    
    # Add Key Vault soft-delete stats
    if lifecycle_counts["total_key_vaults"] > 0:
        kv_percentage = (lifecycle_counts["key_vault_soft_delete"] / lifecycle_counts["total_key_vaults"]) * 100
        summary.append(f"- **{kv_percentage:.1f}%** of Key Vaults have soft-delete protection")
    
    # Add VM backup stats
    if lifecycle_counts["total_vms"] > 0:
        vm_percentage = (lifecycle_counts["vm_backup"] / lifecycle_counts["total_vms"]) * 100
        summary.append(f"- **{vm_percentage:.1f}%** of Virtual Machines have backup configured")
    
    if summary:
        return "\n".join(summary)
    else:
        return "_No resource lifecycle policies detected._" 