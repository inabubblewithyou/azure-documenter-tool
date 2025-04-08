import logging
from azure.mgmt.network import NetworkManagementClient
from azure.core.exceptions import HttpResponseError

def fetch_networking_details(credential, subscription_id):
    """Fetches VNet, subnet, NSG, and peering details for a subscription."""
    logging.info(f"[{subscription_id}] Fetching networking details...")
    network_client = NetworkManagementClient(credential, subscription_id)
    network_data = {
        "vnets": [],
        "subnets": [],
        "nsgs": [],
        "peerings": []
    }

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

    except HttpResponseError as e:
        if e.status_code == 403:
             logging.warning(f"[{subscription_id}] Authorization failed for networking details: {e.message}. Skipping.")
        else:
            logging.error(f"[{subscription_id}] Error fetching networking details: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching networking details: {e}")

    logging.info(f"[{subscription_id}] Finished fetching networking details.")
    return network_data 