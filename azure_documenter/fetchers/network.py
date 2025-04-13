import logging
import asyncio # Import asyncio
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.frontdoor import FrontDoorManagementClient  # Add Front Door client
from azure.mgmt.trafficmanager import TrafficManagerManagementClient  # Add Traffic Manager client
from azure.core.exceptions import HttpResponseError

async def fetch_networking_details(credential, subscription_id, resources_list):
    """Fetches VNet, subnet, NSG, peering, Firewall, Public IP, Gateways, DDoS plans, Route Tables, App Gateways (WAF), WAF Policies for a subscription."""
    logging.info(f"[{subscription_id}] Fetching networking details...")
    network_client = NetworkManagementClient(credential, subscription_id)
    
    # Initialize specific clients for Front Door and Traffic Manager
    frontdoor_client = FrontDoorManagementClient(credential, subscription_id)
    traffic_manager_client = TrafficManagerManagementClient(credential, subscription_id)

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
        "route_tables": [],
        "application_gateways": [],
        "waf_policies": [],
        "load_balancers": [],
        "front_doors": [],  # Add Front Door list
        "traffic_managers": []  # Add Traffic Manager list
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

        # --- Fetch Route Tables (New) ---
        try:
            route_tables = list(network_client.route_tables.list_all())
            logging.info(f"[{subscription_id}] Found {len(route_tables)} Route Tables.")
            for rt in route_tables:
                routes_info = []
                if rt.routes:
                    for route in rt.routes:
                        routes_info.append({
                            "name": route.name,
                            "address_prefix": route.address_prefix,
                            "next_hop_type": str(route.next_hop_type), # Enum
                            "next_hop_ip_address": route.next_hop_ip_address
                        })
                rt_details = {
                    "id": rt.id,
                    "name": rt.name,
                    "location": rt.location,
                    "resource_group": rt.id.split('/')[4],
                    "routes": routes_info,
                    "disable_bgp_route_propagation": rt.disable_bgp_route_propagation,
                    "tags": rt.tags
                }
                network_data["route_tables"].append(rt_details)
        except HttpResponseError as e:
            logging.warning(f"[{subscription_id}] Could not list Route Tables (Check Permissions?): {e.message}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching Route Tables: {e}")

        # --- Fetch Application Gateways (for WAF Config) (New) ---
        try:
            app_gateways = list(network_client.application_gateways.list_all())
            logging.info(f"[{subscription_id}] Found {len(app_gateways)} Application Gateways.")
            for ag in app_gateways:
                waf_config = None
                if ag.web_application_firewall_configuration:
                    waf_conf = ag.web_application_firewall_configuration
                    waf_config = {
                        "enabled": waf_conf.enabled,
                        "firewall_mode": str(waf_conf.firewall_mode), # Enum (Detection/Prevention)
                        "rule_set_type": waf_conf.rule_set_type,
                        "rule_set_version": waf_conf.rule_set_version,
                        "disabled_rule_groups": [rg.rule_group_name for rg in waf_conf.disabled_rule_groups] if waf_conf.disabled_rule_groups else [],
                        "request_body_check": waf_conf.request_body_check,
                        "max_request_body_size_in_kb": waf_conf.max_request_body_size_in_kb,
                        "file_upload_limit_in_mb": waf_conf.file_upload_limit_in_mb
                    }

                ag_details = {
                    "id": ag.id,
                    "name": ag.name,
                    "location": ag.location,
                    "resource_group": ag.id.split('/')[4],
                    "sku_name": ag.sku.name if ag.sku else "Unknown",
                    "sku_tier": ag.sku.tier if ag.sku else "Unknown",
                    "waf_configuration": waf_config, # WAF info
                    "firewall_policy_id": ag.firewall_policy.id if ag.firewall_policy else None, # Link to WAF Policy
                    "tags": ag.tags
                }
                network_data["application_gateways"].append(ag_details)
        except HttpResponseError as e:
            logging.warning(f"[{subscription_id}] Could not list Application Gateways (Check Permissions?): {e.message}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching Application Gateways: {e}")

        # --- Fetch Web Application Firewall Policies (WAF Policies) (New) ---
        try:
            waf_policies = list(network_client.web_application_firewall_policies.list_all())
            logging.info(f"[{subscription_id}] Found {len(waf_policies)} WAF Policies.")
            for policy in waf_policies:
                 policy_settings = None
                 if policy.policy_settings:
                     ps = policy.policy_settings
                     policy_settings = {
                         "state": str(ps.state), # Enum (Enabled/Disabled)
                         "mode": str(ps.mode), # Enum (Prevention/Detection)
                         "request_body_check": ps.request_body_check,
                         "max_request_body_size_in_kb": ps.max_request_body_size_in_kb,
                         "file_upload_limit_in_mb": ps.file_upload_limit_in_mb
                     }
                 managed_rules = None
                 if policy.managed_rules:
                     mr = policy.managed_rules
                     managed_rules = {
                        "managed_rule_sets": [
                             {"rule_set_type": mrs.rule_set_type, "rule_set_version": mrs.rule_set_version}
                             for mrs in mr.managed_rule_sets
                         ] if mr.managed_rule_sets else []
                     }

                 policy_details = {
                     "id": policy.id,
                     "name": policy.name,
                     "location": policy.location,
                     "resource_group": policy.id.split('/')[4],
                     "policy_settings": policy_settings,
                     "managed_rules": managed_rules,
                     # Links to associated resources (App Gateways, Front Doors, CDNs)
                     "application_gateway_ids": [ag.id for ag in policy.application_gateways] if policy.application_gateways else [],
                     # "http_listener_ids": [l.id for l in policy.http_listeners] if policy.http_listeners else [], # Typically for Front Door Classic
                     # "path_based_rule_ids": [p.id for p in policy.path_based_rules] if policy.path_based_rules else [], # Typically for Front Door Classic
                     "tags": policy.tags
                 }
                 network_data["waf_policies"].append(policy_details)
        except HttpResponseError as e:
            logging.warning(f"[{subscription_id}] Could not list WAF Policies (Check Permissions?): {e.message}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching WAF Policies: {e}")

        # --- Fetch Load Balancers ---
        try:
            load_balancers = list(network_client.load_balancers.list_all())
            logging.info(f"[{subscription_id}] Found {len(load_balancers)} Load Balancers.")
            for lb in load_balancers:
                lb_details = {
                    "id": lb.id,
                    "name": lb.name,
                    "location": lb.location,
                    "resource_group": lb.id.split('/')[4],
                    "sku": lb.sku.name if lb.sku else "Unknown",
                    "tags": lb.tags
                }
                network_data["load_balancers"].append(lb_details)
        except HttpResponseError as e:
            logging.warning(f"[{subscription_id}] Could not list Load Balancers (Check Permissions?): {e.message}")
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error fetching Load Balancers: {e}")

        # --- Fetch Front Doors (Classic) ---
        try:
            front_doors = list(frontdoor_client.front_doors.list())
            logging.info(f"[{subscription_id}] Found {len(front_doors)} Front Door instances.")
            for fd in front_doors:
                fd_details = {
                    "id": fd.id,
                    "name": fd.name,
                    "resource_group": fd.id.split('/')[4],
                    "frontend_endpoints": [ep.host_name for ep in fd.frontend_endpoints] if fd.frontend_endpoints else [],
                    "backend_pools": [pool.name for pool in fd.backend_pools] if fd.backend_pools else [],
                    "routing_rules": [rule.name for rule in fd.routing_rules] if fd.routing_rules else [],
                    "enabled_state": str(fd.enabled_state) if fd.enabled_state else None,
                    "tags": fd.tags
                }
                network_data["front_doors"].append(fd_details)
        except Exception as fd_e:
            logging.warning(f"[{subscription_id}] Could not list Front Door instances: {fd_e}")

        # --- Fetch Traffic Manager Profiles ---
        try:
            traffic_managers = list(traffic_manager_client.profiles.list_by_subscription())
            logging.info(f"[{subscription_id}] Found {len(traffic_managers)} Traffic Manager profiles.")
            for tm in traffic_managers:
                tm_details = {
                    "id": tm.id,
                    "name": tm.name,
                    "resource_group": tm.id.split('/')[4],
                    "profile_status": str(tm.profile_status) if tm.profile_status else None,
                    "routing_method": str(tm.traffic_routing_method) if tm.traffic_routing_method else None,
                    "dns_config": {
                        "relative_name": tm.dns_config.relative_name if tm.dns_config else None,
                        "ttl": tm.dns_config.ttl if tm.dns_config else None
                    } if tm.dns_config else None,
                    "monitor_config": {
                        "protocol": str(tm.monitor_config.protocol) if tm.monitor_config else None,
                        "port": tm.monitor_config.port if tm.monitor_config else None,
                        "path": tm.monitor_config.path if tm.monitor_config else None
                    } if tm.monitor_config else None,
                    "tags": tm.tags
                }
                network_data["traffic_managers"].append(tm_details)
        except Exception as tm_e:
            logging.warning(f"[{subscription_id}] Could not list Traffic Manager profiles: {tm_e}")

    except HttpResponseError as e:
        if e.status_code == 403:
             logging.warning(f"[{subscription_id}] Authorization failed for networking details: {e.message}. Skipping.")
        else:
            logging.error(f"[{subscription_id}] Error fetching networking details: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching networking details: {e}")

    logging.info(f"[{subscription_id}] Finished fetching networking details.")
    return network_data 