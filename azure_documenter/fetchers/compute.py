# azure_documenter/fetchers/compute.py
import logging
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient # To find VMs first
from azure.core.exceptions import HttpResponseError

async def fetch_all_vm_details(credential, subscription_id):
    """Fetches detailed information for all Virtual Machines in a subscription."""
    logging.info(f"[{subscription_id}] Fetching detailed VM information...")
    vm_data = {"vms": []}
    
    try:
        # Client to list resources and find VMs
        resource_client = ResourceManagementClient(credential, subscription_id)
        # Client to get detailed VM info
        compute_client = ComputeManagementClient(credential, subscription_id)

        vm_resources = []
        try:
            # Filter resources to find VMs
            for resource in resource_client.resources.list(filter="resourceType eq 'Microsoft.Compute/virtualMachines'"):
                # Extract basic info needed to get full details
                rg_name = resource.id.split('/')[4]
                vm_name = resource.name
                vm_resources.append({'rg': rg_name, 'name': vm_name, 'id': resource.id})
        except HttpResponseError as e:
            logging.error(f"[{subscription_id}] Failed to list VM resources: {e.message}")
            return vm_data
        except Exception as e:
            logging.error(f"[{subscription_id}] Unexpected error listing VM resources: {e}")
            return vm_data

        if not vm_resources:
            logging.info(f"[{subscription_id}] Found 0 Virtual Machines.")
            return vm_data

        logging.info(f"[{subscription_id}] Found {len(vm_resources)} Virtual Machines. Fetching details...")

        # Fetch details for each VM
        for vm_basic_info in vm_resources:
            rg = vm_basic_info['rg']
            name = vm_basic_info['name']
            vm_id = vm_basic_info['id']
            try:
                # Get full VM details including instance view for status
                vm = compute_client.virtual_machines.get(rg, name, expand='instanceView')

                # Extract desired properties directly from the vm object
                hardware_profile = vm.hardware_profile
                storage_profile = vm.storage_profile
                os_profile = vm.os_profile
                availability_set = vm.availability_set # This is an ID object or None
                instance_view = vm.instance_view # Already expanded

                # OS Type
                os_type = "Unknown"
                if os_profile:
                    if os_profile.windows_configuration:
                        os_type = "Windows"
                    elif os_profile.linux_configuration:
                        os_type = "Linux"
                elif storage_profile and storage_profile.os_disk:
                    os_type = storage_profile.os_disk.os_type.value if storage_profile.os_disk.os_type else "Unknown" # Enum to string

                # Status from Instance View
                status = "Unknown"
                if instance_view and instance_view.statuses:
                    power_status = next((s.display_status for s in instance_view.statuses if s.code and s.code.startswith('PowerState/')), None)
                    if power_status:
                        status = power_status
                # Fallback to provisioning state if instance view doesn't provide status
                if status == "Unknown" and vm.provisioning_state:
                    status = vm.provisioning_state

                vm_details = {
                    "id": vm.id,
                    "name": vm.name,
                    "location": vm.location,
                    "resource_group": rg,
                    "vmSize": hardware_profile.vm_size if hardware_profile else "Unknown",
                    "osType": os_type,
                    "zones": vm.zones, # List of zones or None
                    "availability_set_id": availability_set.id if availability_set else None,
                    "status": status,
                    "tags": vm.tags
                    # Add other details as needed (e.g., network interface IDs, disk info)
                }
                vm_data["vms"].append(vm_details)

            except HttpResponseError as e:
                logging.warning(f"[{subscription_id}] Failed to get details for VM '{name}' in RG '{rg}': {e.message}")
            except Exception as e:
                logging.error(f"[{subscription_id}] Unexpected error getting details for VM '{name}' in RG '{rg}': {e}")

    except ImportError:
         logging.error(f"[{subscription_id}] Failed to fetch VM details: azure-mgmt-compute library not found. Please install it.")
    except Exception as e:
        logging.error(f"[{subscription_id}] Failed to initialize Compute/Resource client: {e}")

    logging.info(f"[{subscription_id}] Finished fetching detailed VM information. Found details for {len(vm_data['vms'])} VMs.")
    return vm_data 