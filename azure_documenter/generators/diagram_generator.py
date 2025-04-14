import os
import logging
import graphviz # Python interface for Graphviz

def generate_vnet_diagram(subscription_data, diagram_output_path, timestamp_str):
    """Generates a timestamped VNet/Subnet diagram for a single subscription using Graphviz."""
    sub_id = subscription_data.get("subscription_info", {}).get("id", "unknown_sub")
    sub_display_name = subscription_data.get("subscription_info", {}).get("display_name", sub_id)
    tenant_name = subscription_data.get("subscription_info", {}).get("tenant_display_name", "Unknown_Tenant")
    version = subscription_data.get("run_details", {}).get("version", 0.0)
    networking_data = subscription_data.get("networking", {})
    vnets = networking_data.get("vnets", [])
    subnets = networking_data.get("subnets", [])

    if not vnets:
        logging.info(f"[{sub_id}] No VNets found, skipping VNet diagram generation.")
        return None

    logging.info(f"[{sub_id}] Generating VNet diagram...")

    # Clean tenant name for filename
    clean_tenant_name = tenant_name.replace(" ", "_").replace("/", "_").replace("\\", "_")
    safe_sub_name = "".join(c for c in sub_display_name if c.isalnum() or c in (' ', '_', '-')).rstrip()
    
    # Add timestamp and version to filename
    filename_base = f"vnet_topology_{clean_tenant_name}_{safe_sub_name}_{sub_id}_{timestamp_str}_v{version:.1f}"
    filename_gv = f"{filename_base}.gv"
    filename_png = f"{filename_base}.png"
    
    output_filepath_gv = os.path.join(diagram_output_path, filename_gv)
    output_filepath_png = os.path.join(diagram_output_path, filename_png)

    # Create a Graphviz Digraph
    # Using subgraph for each VNet to group subnets visually
    dot = graphviz.Digraph(name=f'cluster_subscription_{sub_id}', comment=f'Azure VNet Topology - {sub_display_name} ({timestamp_str})')
    dot.attr(label=f'Subscription: {sub_display_name} ({sub_id})\nRun: {timestamp_str}')
    dot.attr(fontsize='20')
    dot.attr(labelloc='t') # Title location at the top
    dot.attr(rankdir='TB') # Top-to-bottom layout

    try:
        for vnet in vnets:
            vnet_id = vnet['id']
            vnet_name = vnet['name']
            vnet_rg = vnet['resource_group']
            vnet_label = f"VNet: {vnet_name}\nRG: {vnet_rg}\nSpace: { ', '.join(vnet.get('address_space', [])) }"

            # Create a subgraph for the VNet
            with dot.subgraph(name=f'cluster_{vnet_id}') as vnet_cluster:
                vnet_cluster.attr(label=vnet_label)
                vnet_cluster.attr(style='filled', color='lightblue') # VNet container style
                vnet_cluster.attr(rank='same') # Try to keep subnets horizontally aligned?

                # Add nodes for subnets within this VNet's subgraph
                vnet_subnets = [s for s in subnets if s.get('vnet_id') == vnet_id]
                if not vnet_subnets:
                    # Add a placeholder node if VNet has no subnets defined in our data
                    vnet_cluster.node(f"placeholder_{vnet_id}", label="(No Subnets Found)", shape="plaintext")
                else:
                    for subnet in vnet_subnets:
                        subnet_id = subnet['id']
                        subnet_name = subnet['name']
                        subnet_prefix = subnet['address_prefix']
                        subnet_label = f"Subnet: {subnet_name}\nPrefix: {subnet_prefix}"
                        # Add NSG/RT info if available
                        nsg_id = subnet.get('nsg_id')
                        rt_id = subnet.get('route_table_id')
                        if nsg_id:
                            subnet_label += f"\nNSG: {nsg_id.split('/')[-1]}"
                        if rt_id:
                            subnet_label += f"\nRouteTable: {rt_id.split('/')[-1]}"

                        vnet_cluster.node(subnet_id, label=subnet_label, shape='box', style='filled', fillcolor='azure') # Subnet node style

        # Add Peering connections (basic lines between VNet subgraphs for now)
        peerings = networking_data.get("peerings", [])
        for peering in peerings:
            local_vnet_id = peering.get('local_vnet_id')
            remote_vnet_id = peering.get('remote_vnet_id')
            peering_state = peering.get('peering_state')

            # Only draw if both ends are known and state is Connected
            if local_vnet_id and remote_vnet_id and peering_state == 'Connected':
                 # Find the subgraph clusters for source and target
                 # Graphviz cluster names need 'cluster_' prefix
                 local_cluster_name = f'cluster_{local_vnet_id}'
                 remote_cluster_name = f'cluster_{remote_vnet_id}'

                 # Add edge between the clusters (or representative nodes)
                 # Edges between clusters need lhead/ltail pointing to cluster names
                 # We need *nodes* within the clusters to connect.
                 # Let's connect the first subnet of each, or the placeholder if no subnets.
                 local_node = next((s['id'] for s in subnets if s.get('vnet_id') == local_vnet_id), f"placeholder_{local_vnet_id}")
                 remote_node = next((s['id'] for s in subnets if s.get('vnet_id') == remote_vnet_id), f"placeholder_{remote_vnet_id}")

                 # Check if nodes exist before adding edge
                 # Note: This basic approach won't handle cross-subscription peering well visually yet
                 # as the remote VNet might not be in *this* diagram's clusters.
                 # For now, we only draw if both VNet clusters are present in *this* sub's diagram.
                 local_vnet_exists = any(v['id'] == local_vnet_id for v in vnets)
                 remote_vnet_exists = any(v['id'] == remote_vnet_id for v in vnets)

                 if local_vnet_exists and remote_vnet_exists:
                    dot.edge(local_node, remote_node,
                             label=f"Peering: {peering.get('name')}",
                             color='blue', style='dashed', constraint='false') # constraint=false helps layout

        # Render the diagram (e.g., to PNG)
        os.makedirs(diagram_output_path, exist_ok=True)
        output_format = 'png' # Or svg
        # Pass only the base filename (without directory) to render
        rendered_path = dot.render(filename_base, directory=diagram_output_path, format=output_format, cleanup=True, view=False) # cleanup removes the .gv source, view=False prevents opening

        logging.info(f"[{sub_id}] Successfully generated VNet diagram: {rendered_path}")
        # Return the PNG filename (not full path) for document inclusion
        return filename_png

    except Exception as e:
        logging.error(f"[{sub_id}] Failed to generate VNet diagram: {e}")
        # Attempt to remove potentially corrupted files
        try:
            if os.path.exists(output_filepath_gv):
                os.remove(output_filepath_gv)
            if os.path.exists(output_filepath_gv + "." + output_format):
                 os.remove(output_filepath_gv + "." + output_format)
        except OSError as rm_err:
            logging.error(f"[{sub_id}] Error cleaning up failed diagram files: {rm_err}")
        return None

def generate_tenant_network_diagram(all_data, diagram_output_path, timestamp_str, version):
    """Generates a tenant-wide network diagram showing all VNets and peerings across subscriptions."""
    logging.info("Generating tenant-wide network diagram...")
    
    # Try to determine tenant name from subscription data
    tenant_name = "Unknown_Tenant"
    # Look for tenant info in any subscription
    for sub_id, data in all_data.items():
        if "subscription_info" in data and "tenant_display_name" in data["subscription_info"]:
            tenant_name = data["subscription_info"]["tenant_display_name"]
            break
    
    # Clean tenant name for filename
    clean_tenant_name = tenant_name.replace(" ", "_").replace("/", "_").replace("\\", "_")
    
    # Create output filename with tenant name, timestamp and version
    filename_base = f"tenant_network_topology_{clean_tenant_name}_{timestamp_str}_v{version:.1f}"
    filename_gv = f"{filename_base}.gv"
    filename_png = f"{filename_base}.png"
    
    output_filepath_gv = os.path.join(diagram_output_path, filename_gv)
    output_filepath_png = os.path.join(diagram_output_path, filename_png)
    
    # Create a Graphviz Digraph for the tenant
    dot = graphviz.Digraph(name='tenant_network_topology', 
                           comment=f'Azure Tenant-Wide Network Topology')
    dot.attr(label=f'{tenant_name} - Network Topology')
    dot.attr(fontsize='20')
    dot.attr(labelloc='t') # Title at top
    
    # Optimize layout for compact but readable diagram
    dot.attr(compound='true')  # Allow edges between clusters
    dot.attr(rankdir='TB')     # Top-to-bottom layout is more compact
    dot.attr(nodesep='0.5')    # Reduced node separation
    dot.attr(ranksep='0.75')   # Reduced rank separation
    dot.attr(overlap='false')  # Prevent node overlap
    dot.attr(splines='true')   # Curved splines for easier tracing
    
    # PEERING DEBUG: Print raw networking data for diagnosis
    logging.info("----- START PEERING DEBUG -----")
    for sub_id, subscription_data in all_data.items():
        if "error" in subscription_data:
            continue
        networking_data = subscription_data.get("networking", {})
        peerings = networking_data.get("peerings", [])
        sub_name = subscription_data.get("subscription_info", {}).get("display_name", sub_id)
        logging.info(f"Subscription {sub_name} has {len(peerings)} peerings")
        for p in peerings:
            logging.info(f"  Peering: {p.get('name')}, State: {p.get('peering_state')}")
            logging.info(f"    Local VNet: {p.get('local_vnet_id')}")
            logging.info(f"    Remote VNet: {p.get('remote_vnet_id')}")
    logging.info("----- END PEERING DEBUG -----")
    
    # Collect all VNets and peerings across subscriptions
    all_vnets = []
    all_peerings = []
    vnet_to_subscription = {}  # Map VNet ID to subscription info for labeling
    all_subscription_ids = set()  # Track all subscription IDs in our tenant
    vnet_name_by_id = {}  # Map of VNet IDs to their names for reference
    
    # First pass: collect all VNets and their subscription context
    for sub_id, subscription_data in all_data.items():
        if "error" in subscription_data:
            continue
            
        # Track this subscription as part of our tenant
        all_subscription_ids.add(sub_id)
        
        sub_display_name = subscription_data.get("subscription_info", {}).get("display_name", sub_id)
        networking_data = subscription_data.get("networking", {})
        
        # Add VNets from this subscription
        vnets = networking_data.get("vnets", [])
        for vnet in vnets:
            vnet_id = vnet['id']
            vnet_name = vnet['name']
            vnet_name_by_id[vnet_id] = vnet_name  # Store for easy lookup by ID
            
            vnet["subscription_id"] = sub_id
            vnet["subscription_name"] = sub_display_name
            all_vnets.append(vnet)
            vnet_to_subscription[vnet_id] = {
                "id": sub_id,
                "name": sub_display_name
            }
            
        # Add peerings from this subscription
        peerings = networking_data.get("peerings", [])
        for peering in peerings:
            peering["source_subscription_id"] = sub_id
            peering["source_subscription_name"] = sub_display_name
            all_peerings.append(peering)
    
    # Enhanced debug logging to verify peering data
    peering_count = len(all_peerings)
    logging.info(f"[NETWORK-DEBUG] Found {len(all_vnets)} VNets and {peering_count} peerings across {len(all_subscription_ids)} subscriptions")
    if peering_count == 0:
        logging.warning("NO PEERINGS FOUND IN ANY SUBSCRIPTION - network diagram will not show connections!")
    
    for peering in all_peerings:
        peering_name = peering.get('name', 'Unknown')
        local_vnet_id = peering.get('local_vnet_id', 'Unknown')
        remote_vnet_id = peering.get('remote_vnet_id', 'Unknown')
        state = peering.get('peering_state', 'Unknown')
        logging.info(f"[NETWORK-DEBUG] Peering: {peering_name}, State: {state}, From: {local_vnet_id} To: {remote_vnet_id}")
    
    try:
        # SIMPLIFIED DIAGRAM: Instead of using clusters, we'll use a flat structure with VNets
        # grouped visually by subscription. This makes peering connections much more visible.
        
        # Create nodes for each VNet
        for vnet in all_vnets:
            vnet_id = vnet['id']
            vnet_name = vnet['name']
            sub_name = vnet_to_subscription[vnet_id]['name']
            address_space = ", ".join(vnet.get('address_space', []))
            
            # Create more compact VNet node label
            vnet_label = f"{vnet_name}\n{address_space}\n({sub_name})"
            
            # Add node directly to graph (no clusters)
            dot.node(vnet_id, label=vnet_label, shape='box', 
                    style='filled', fillcolor='lightblue', penwidth='1.5',
                    width='1.5', height='1.0')  # More compact size
        
        # Track how many peerings we're actually adding to the diagram
        peering_edges_added = 0
        
        # Directly add edges for ALL peerings
        for peering in all_peerings:
            local_vnet_id = peering.get('local_vnet_id')
            remote_vnet_id = peering.get('remote_vnet_id')
            peering_state = peering.get('peering_state')
            peering_name = peering.get('name', 'Unknown')
            
            # Skip if missing data
            if not local_vnet_id or not remote_vnet_id:
                logging.warning(f"Skipping peering {peering_name} due to missing VNet IDs")
                continue
                
            # Only draw connected peerings
            if peering_state == 'Connected':
                # Get VNet names for label
                local_name = vnet_name_by_id.get(local_vnet_id, local_vnet_id.split('/')[-1])
                remote_name = vnet_name_by_id.get(remote_vnet_id, remote_vnet_id.split('/')[-1])
                
                # Check if remote VNet isn't in our collected data, create a node for it if needed
                if remote_vnet_id not in vnet_name_by_id:
                    try:
                        # Extract remote VNet name and subscription from ID
                        parts = remote_vnet_id.split('/')
                        remote_vnet_name = parts[-1] if len(parts) > 8 else "External VNet"
                        remote_sub_id = parts[2] if len(parts) > 3 else "unknown"
                        
                        # Add to our name lookup
                        vnet_name_by_id[remote_vnet_id] = remote_vnet_name
                        
                        # Create node for this external VNet with different color
                        dot.node(remote_vnet_id, 
                                label=f"{remote_vnet_name}\nExternal VNet\n(Sub: {remote_sub_id[-8:]})", 
                                shape='box', style='filled', fillcolor='lightyellow', 
                                penwidth='1.5', width='1.5', height='1.0')
                    except Exception as e:
                        logging.warning(f"Failed to extract info from external VNet ID: {remote_vnet_id}: {e}")
                        # Create a basic placeholder node
                        dot.node(remote_vnet_id, label="External VNet", 
                                shape='box', style='filled', fillcolor='lightyellow',
                                penwidth='1.5', width='1.5', height='1.0')
                
                # Make peering connections visible but without text label
                try:
                    # Add a visible edge 
                    dot.edge(local_vnet_id, remote_vnet_id, 
                          color='blue4', style='bold', penwidth='2.0', 
                          dir='both', arrowhead='normal', arrowtail='normal',
                          constraint='true')
                    
                    peering_edges_added += 1
                    logging.info(f"Added peering edge from {local_name} to {remote_name}")
                except Exception as e:
                    logging.error(f"Failed to add peering edge: {e}")
        
        # Log how many peering edges were added
        logging.info(f"Added {peering_edges_added} peering edges to the diagram")
        
        # Render the diagram
        os.makedirs(diagram_output_path, exist_ok=True)
        output_format = 'png'
        
        # Set output size - more compact
        dot.attr(dpi='150')  # Lower DPI, we need compact diagram
        dot.attr(size='9,5')  # Smaller size (inches)
        
        rendered_path = dot.render(filename_base, directory=diagram_output_path, format=output_format, cleanup=True, view=False)
        
        logging.info(f"Tenant-wide network diagram generated: {rendered_path}")
        # Return the PNG filename (not full path) for document inclusion
        return filename_png
            
    except Exception as e:
        logging.error(f"Failed to generate tenant-wide network diagram: {e}")
        # Clean up potentially corrupt files
        try:
            if os.path.exists(output_filepath_gv):
                os.remove(output_filepath_gv)
            if os.path.exists(output_filepath_gv + "." + output_format):
                os.remove(output_filepath_gv + "." + output_format)
        except OSError as rm_err:
            logging.error(f"Error cleaning up failed diagram files: {rm_err}")
        return None

def generate_all_diagrams(all_data, diagram_output_path, timestamp_str):
    """Generates all network diagrams for the environment."""
    logging.info("Starting diagram generation...")
    
    # Ensure diagram directory exists and is absolute
    # Create diagrams directory under outputs
    base_output_dir = os.path.dirname(os.path.dirname(diagram_output_path))  # Go up two levels to get base output dir
    diagram_dir = os.path.join(base_output_dir, "outputs", "diagrams")
    diagram_dir = os.path.abspath(diagram_dir)
    os.makedirs(diagram_dir, exist_ok=True)
    logging.info(f"Using diagram directory: {diagram_dir}")
    
    # Initialize return structure
    generated_diagrams = {
        "subscription_diagrams": {},
        "tenant_diagrams": {}
    }

    # Get version from run_details (should be same across all subs)
    version = 0.0
    for sub_id, data in all_data.items():
        if isinstance(data, dict) and "run_details" in data:
            version = data["run_details"].get("version", 0.0)
            break

    logging.info(f"Generating diagrams with version {version}")

    # Generate subscription-specific diagrams
    for sub_id, data in all_data.items():
        if "error" not in data and "networking" in data and data["networking"].get("vnets"):
            # Add version to the data for diagram generation
            data["run_details"] = data.get("run_details", {})
            data["run_details"]["version"] = version
            diagram_rel_path = generate_vnet_diagram(data, diagram_dir, timestamp_str)
            if diagram_rel_path:
                # Store just the filename, not the full path
                generated_diagrams["subscription_diagrams"][sub_id] = {"vnet_topology": diagram_rel_path}
                logging.info(f"Generated subscription diagram: {diagram_rel_path}")
        else:
            sub_display_name = data.get("subscription_info", {}).get("display_name", sub_id)
            logging.info(f"Skipping diagram generation for {sub_display_name} ({sub_id}) due to error or no VNets.")
    
    # Generate tenant-wide network diagram with version
    tenant_diagram_path = generate_tenant_network_diagram(all_data, diagram_dir, timestamp_str, version)
    if tenant_diagram_path:
        # Store just the filename, not the full path
        generated_diagrams["tenant_diagrams"]["network_topology"] = tenant_diagram_path
        logging.info(f"Generated tenant diagram: {tenant_diagram_path}")
    
    logging.info("Finished all diagram generation.")
    return generated_diagrams 