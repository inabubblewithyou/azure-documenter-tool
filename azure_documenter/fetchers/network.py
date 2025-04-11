import logging
from azure.mgmt.network import NetworkManagementClient
from azure.core.exceptions import HttpResponseError

def fetch_networking_details(credential, subscription_id, resources_list):
    """Fetches VNet, subnet, NSG, peering, Firewall, Public IP, Gateways, DDoS plans for a subscription."""
    logging.info(f"[{subscription_id}] Fetching networking details...")
    network_client = NetworkManagementClient(credential, subscription_id)
    network_data = {
        "vnets": [],
        "subnets": [],
        "nsgs": [],
        "peerings": [],
        "firewalls": [],
        "public_ips": [],
        "vpn_gateways": [],
        "expressroute_circuits": [],
        "ddos_protection_plans": [],
        "private_endpoints": [],
        "private_dns_zones": [],
        # TODO: Add other types like app gateways, priv dns, route tables etc. later
    }

    # Get unique resource group names from the resources list for efficient GW listing
    resource_groups = set()
    if resources_list:
        for resource in resources_list:
             if isinstance(resource, dict) and resource.get('resource_group'):
                 resource_groups.add(resource['resource_group'])
    else:
         logging.warning(f"[{subscription_id}] Resources list not provided to fetch_networking_details. VPN Gateway fetch might be incomplete or skipped.")
         # Optionally, could try listing RGs separately, but less efficient

    try:
        # Fetch VNets
        vnets = list(network_client.virtual_networks.list_all())
        logging.info(f"[{subscription_id}] Found {len(vnets)} VNets.")
        for vnet in vnets:
            vnet_details = {
                "id": vnet.id,
                "name": vnet.name,
                "location": vnet.location,
                "resource_group": vnet.id.split('/')[4],
                "address_space": vnet.address_space.address_prefixes if vnet.address_space else [],
                "tags": vnet.tags
            }
            network_data["vnets"].append(vnet_details)

            # Fetch Subnets within the VNet
            if vnet.subnets:
                for subnet in vnet.subnets:
                    subnet_details = {
                        "id": subnet.id,
                        "name": subnet.name,
                        "vnet_name": vnet.name,
                        "vnet_id": vnet.id,
                        "resource_group": vnet.id.split('/')[4],
                        "address_prefix": subnet.address_prefix,
                        "nsg_id": subnet.network_security_group.id if subnet.network_security_group else None,
                        "route_table_id": subnet.route_table.id if subnet.route_table else None,
                        # Add service endpoints, delegations etc. if needed later
                    }
                    network_data["subnets"].append(subnet_details)

            # Fetch VNet Peerings within the VNet
            if vnet.virtual_network_peerings:
                for peering in vnet.virtual_network_peerings:
                    peering_details = {
                        "id": peering.id,
                        "name": peering.name,
                        "local_vnet_id": vnet.id,
                        "remote_vnet_id": peering.remote_virtual_network.id if peering.remote_virtual_network else None,
                        "peering_state": str(peering.peering_state), # Enum to string
                        "allow_vnet_access": peering.allow_virtual_network_access,
                        "allow_forwarded_traffic": peering.allow_forwarded_traffic,
                        "allow_gateway_transit": peering.allow_gateway_transit,
                        "use_remote_gateways": peering.use_remote_gateways,
                        "resource_group": vnet.id.split('/')[4],
                    }
                    network_data["peerings"].append(peering_details)

        # Fetch NSGs (Subscription scope)
        nsgs = list(network_client.network_security_groups.list_all())
        logging.info(f"[{subscription_id}] Found {len(nsgs)} Network Security Groups.")
        for nsg in nsgs:
            nsg_details = {
                "id": nsg.id,
                "name": nsg.name,
                "location": nsg.location,
                "resource_group": nsg.id.split('/')[4],
                "rules": [], # We'll fetch rules separately if needed for detail
                "tags": nsg.tags
            }
            # Extract basic rule info or just count?
            if nsg.security_rules:
                 nsg_details["rules_count"] = len(nsg.security_rules)
            if nsg.default_security_rules:
                 nsg_details["default_rules_count"] = len(nsg.default_security_rules)

            network_data["nsgs"].append(nsg_details)

        # Fetch Azure Firewalls
        try:
            firewalls = list(network_client.azure_firewalls.list_all())
            logging.info(f"[{subscription_id}] Found {len(firewalls)} Azure Firewalls.")
            for fw in firewalls:
                 firewall_details = {
                     "id": fw.id,
                     "name": fw.name,
                     "location": fw.location,
                     "resource_group": fw.id.split('/')[4],
                     "sku": fw.sku.name if fw.sku else "Unknown",
                     "firewall_policy_id": fw.firewall_policy.id if fw.firewall_policy else None,
                     "tags": fw.tags
                 }
                 network_data["firewalls"].append(firewall_details)
        except HttpResponseError as e:
            logging.warning(f"[{subscription_id}] Could not list Azure Firewalls (Check Permissions?): {e.message}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching Azure Firewalls: {e}")

        # Fetch Public IP Addresses
        try:
            public_ips = list(network_client.public_ip_addresses.list_all())
            logging.info(f"[{subscription_id}] Found {len(public_ips)} Public IP Addresses.")
            for ip in public_ips:
                # Determine associated resource type (basic check)
                assoc_type = "None"
                if ip.ip_configuration:
                    # ID is like /subscriptions/.../virtualNetworks/.../subnets/.../ipConfigurations/...
                    # or /subscriptions/.../loadBalancers/.../frontendIPConfigurations/...
                    # or /subscriptions/.../applicationGateways/.../frontendIPConfigurations/... etc.
                    ip_config_id = ip.ip_configuration.id.lower()
                    if "/networkinterfaces/" in ip_config_id: assoc_type = "Network Interface"
                    elif "/loadbalancers/" in ip_config_id: assoc_type = "Load Balancer Frontend"
                    elif "/applicationgateways/" in ip_config_id: assoc_type = "Application Gateway Frontend"
                    elif "/bastionhosts/" in ip_config_id: assoc_type = "Bastion Host"
                    elif "/virtualnetworkgateways/" in ip_config_id: assoc_type = "VPN/ER Gateway"
                    elif "/azurefirewalls/" in ip_config_id: assoc_type = "Azure Firewall"
                    # Add more checks as needed (Nat Gateway, etc.)
                
                public_ip_details = {
                    "id": ip.id,
                    "name": ip.name,
                    "location": ip.location,
                    "resource_group": ip.id.split('/')[4],
                    "ip_address": ip.ip_address,
                    "allocation_method": str(ip.public_ip_allocation_method), # Enum to string
                    "sku": ip.sku.name if ip.sku else "Unknown",
                    "associated_resource_type": assoc_type, # Basic type detection
                    "tags": ip.tags
                }
                network_data["public_ips"].append(public_ip_details)
        except HttpResponseError as e:
            logging.warning(f"[{subscription_id}] Could not list Public IP Addresses (Check Permissions?): {e.message}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching Public IPs: {e}")

        # --- Fetch VPN Gateways (New) ---
        # VPN Gateways are listed per resource group
        all_vpn_gateways = []
        if resource_groups:
             logging.info(f"[{subscription_id}] Checking {len(resource_groups)} Resource Groups for VPN Gateways...")
             for rg_name in resource_groups:
                 try:
                    rg_gateways = list(network_client.virtual_network_gateways.list(resource_group_name=rg_name))
                    if rg_gateways:
                         logging.info(f"[{subscription_id}] Found {len(rg_gateways)} VPN Gateway(s) in RG '{rg_name}'.")
                         all_vpn_gateways.extend(rg_gateways)
                 except HttpResponseError as e:
                     # Permissions error is common here if reader role doesn't cover specific RGs
                     logging.warning(f"[{subscription_id}] Could not list VPN Gateways in RG '{rg_name}' (Check Permissions?): {e.message}")
                 except Exception as e:
                     logging.error(f"[{subscription_id}] Unexpected error fetching VPN Gateways in RG '{rg_name}': {e}")
        else:
             logging.warning(f"[{subscription_id}] Skipping VPN Gateway fetch as no resource groups were identified.")
             
        if all_vpn_gateways:
             logging.info(f"[{subscription_id}] Processing details for {len(all_vpn_gateways)} found VPN Gateways.")
             for gw in all_vpn_gateways:
                  gateway_details = {
                      "id": gw.id,
                      "name": gw.name,
                      "location": gw.location,
                      "resource_group": gw.id.split('/')[4],
                      "gateway_type": str(gw.gateway_type), # Enum to string
                      "vpn_type": str(gw.vpn_type) if gw.vpn_type else None,
                      "sku": gw.sku.name if gw.sku else "Unknown",
                      "tags": gw.tags
                  }
                  network_data["vpn_gateways"].append(gateway_details)

        # --- Fetch ExpressRoute Circuits (New) ---
        try:
            circuits = list(network_client.express_route_circuits.list_all())
            logging.info(f"[{subscription_id}] Found {len(circuits)} ExpressRoute Circuits.")
            for circuit in circuits:
                 circuit_details = {
                     "id": circuit.id,
                     "name": circuit.name,
                     "location": circuit.location,
                     "resource_group": circuit.id.split('/')[4],
                     "sku_family": circuit.sku.family if circuit.sku else "Unknown",
                     "sku_tier": circuit.sku.tier if circuit.sku else "Unknown",
                     "service_provider_name": circuit.service_provider_properties.service_provider_name if circuit.service_provider_properties else None,
                     "circuit_provisioning_state": str(circuit.provisioning_state),
                     "tags": circuit.tags
                 }
                 network_data["expressroute_circuits"].append(circuit_details)
        except HttpResponseError as e:
            logging.warning(f"[{subscription_id}] Could not list ExpressRoute Circuits (Check Permissions?): {e.message}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching ExpressRoute Circuits: {e}")

        # --- Fetch DDoS Protection Plans (New) ---
        try:
            ddos_plans = list(network_client.ddos_protection_plans.list())
            logging.info(f"[{subscription_id}] Found {len(ddos_plans)} DDoS Protection Plans.")
            for plan in ddos_plans:
                 plan_details = {
                     "id": plan.id,
                     "name": plan.name,
                     "location": plan.location,
                     "resource_group": plan.id.split('/')[4],
                     "virtual_network_ids": [vnet.id for vnet in plan.virtual_networks] if plan.virtual_networks else [],
                     "tags": plan.tags
                 }
                 network_data["ddos_protection_plans"].append(plan_details)
        except HttpResponseError as e:
            logging.warning(f"[{subscription_id}] Could not list DDoS Protection Plans (Check Permissions?): {e.message}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching DDoS Protection Plans: {e}")

        # --- Fetch Private Endpoints (New) ---
        try:
            # Correct method to list private endpoints at subscription scope
            private_endpoints = list(network_client.private_endpoints.list_by_subscription())
            logging.info(f"[{subscription_id}] Found {len(private_endpoints)} Private Endpoints.")
            for pe in private_endpoints:
                # Get linked service details
                pls_connections = []
                if pe.private_link_service_connections:
                    for conn in pe.private_link_service_connections:
                        pls_connections.append({
                            "name": conn.name,
                            "private_link_service_id": conn.private_link_service_id,
                            "group_ids": conn.group_ids,
                            "request_message": conn.request_message,
                            "status": str(conn.private_link_service_connection_state.status) # Enum to string
                        })
                
                pe_details = {
                    "id": pe.id,
                    "name": pe.name,
                    "location": pe.location,
                    "resource_group": pe.id.split('/')[4],
                    "subnet_id": pe.subnet.id if pe.subnet else None,
                    "private_link_service_connections": pls_connections,
                    "tags": pe.tags
                }
                network_data["private_endpoints"].append(pe_details)
        except HttpResponseError as e:
            logging.warning(f"[{subscription_id}] Could not list Private Endpoints (Check Permissions?): {e.message}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching Private Endpoints: {e}")
            
        # --- Fetch Private DNS Zones (New) ---
        # Note: This requires the PrivateDnsManagementClient
        # We might need to add a dependency or handle this separately if not already done.
        # Assuming PrivateDnsManagementClient is available for now:
        try:
            from azure.mgmt.privatedns import PrivateDnsManagementClient # Import here if not global
            private_dns_client = PrivateDnsManagementClient(credential, subscription_id)
            zones = list(private_dns_client.private_zones.list())
            logging.info(f"[{subscription_id}] Found {len(zones)} Private DNS Zones.")
            for zone in zones:
                # Get linked VNets
                vnet_links = []
                try:
                    links_list = list(private_dns_client.virtual_network_links.list(resource_group_name=zone.id.split('/')[4], private_zone_name=zone.name))
                    vnet_links = [link.virtual_network.id for link in links_list if link.virtual_network] # Get linked VNet IDs
                except Exception as link_error:
                    logging.warning(f"[{subscription_id}] Could not list VNet links for Private DNS Zone {zone.name}: {link_error}")
                    
                zone_details = {
                    "id": zone.id,
                    "name": zone.name,
                    "location": zone.location, # Usually 'global'
                    "resource_group": zone.id.split('/')[4],
                    "vnet_links": vnet_links,
                    "tags": zone.tags
                }
                network_data["private_dns_zones"].append(zone_details)
        except ImportError:
             logging.warning(f"[{subscription_id}] azure-mgmt-privatedns library not found. Skipping Private DNS Zone fetch.")
        except HttpResponseError as e:
            logging.warning(f"[{subscription_id}] Could not list Private DNS Zones (Check Permissions?): {e.message}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching Private DNS Zones: {e}")

    except HttpResponseError as e:
        if e.status_code == 403:
             logging.warning(f"[{subscription_id}] Authorization failed for networking details: {e.message}. Skipping.")
        else:
            logging.error(f"[{subscription_id}] Error fetching networking details: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching networking details: {e}")

    logging.info(f"[{subscription_id}] Finished fetching networking details.")
    return network_data 