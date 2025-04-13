import logging
import asyncio # Import asyncio
from azure.identity import DefaultAzureCredential
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.keyvault.secrets import SecretClient # Added for secrets/certs
from azure.keyvault.certificates import CertificateClient, CertificatePolicy # Added for certs
from azure.core.exceptions import HttpResponseError, ClientAuthenticationError

# Fetch Key Vaults (Management Plane)
async def fetch_key_vaults(credential, subscription_id):
    """Fetches Key Vault resources within the subscription."""
    logging.info(f"[{subscription_id}] Fetching Key Vault resources...")
    vaults_data = []
    try:
        kv_mgmt_client = KeyVaultManagementClient(credential, subscription_id)
        vaults = list(kv_mgmt_client.vaults.list_by_subscription())
        logging.info(f"[{subscription_id}] Found {len(vaults)} Key Vaults.")
        for vault in vaults:
            vault_details = {
                "id": vault.id,
                "name": vault.name,
                "location": vault.location,
                "resource_group": vault.id.split('/')[4],
                "vault_uri": vault.properties.vault_uri,
                "sku": vault.properties.sku.name,
                "tenant_id": vault.properties.tenant_id,
                "enabled_for_deployment": vault.properties.enabled_for_deployment,
                "enabled_for_disk_encryption": vault.properties.enabled_for_disk_encryption,
                "enabled_for_template_deployment": vault.properties.enabled_for_template_deployment,
                "enable_soft_delete": vault.properties.enable_soft_delete,
                "soft_delete_retention_days": getattr(vault.properties, 'soft_delete_retention_days', None),
                "enable_purge_protection": vault.properties.enable_purge_protection,
                "public_network_access": vault.properties.public_network_access,
                "tags": vault.tags
            }
            vaults_data.append(vault_details)
    except HttpResponseError as e:
        logging.warning(f"[{subscription_id}] Could not list Key Vaults (Check Permissions?): {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching Key Vaults: {e}")
    return vaults_data

# Fetch Key Vault Certificate Details (Data Plane)
async def fetch_key_vault_certificates(credential, vault_uri):
    """Fetches certificate details from a specific Key Vault."""
    logging.info(f"Fetching Certificates from Key Vault: {vault_uri}")
    certificates_data = {
        "vault_uri": vault_uri,
        "certificates": [],
        "error": None
    }
    try:
        # Data plane client uses vault URI and credential
        cert_client = CertificateClient(vault_url=vault_uri, credential=credential)

        cert_properties_iterable = cert_client.list_properties_of_certificates()
        count = 0
        for cert_props in cert_properties_iterable:
            count += 1
            try:
                # Get the specific version (latest by default if not specified)
                # cert_version = cert_client.get_certificate_version(cert_props.name, cert_props.version)
                # Get the full certificate object for more details (policy, issuer etc.)
                # Note: Getting the full cert might require Certificates Get permission
                full_cert = cert_client.get_certificate(cert_props.name)

                policy_details = None
                if full_cert.policy:
                    policy = full_cert.policy
                    policy_details = {
                        "key_type": policy.key_type,
                        "key_size": policy.key_size,
                        "exportable": policy.exportable,
                        "reuse_key": policy.reuse_key,
                        "content_type": policy.content_type,
                        "subject": policy.subject,
                        "validity_in_months": policy.validity_in_months,
                        # Add more policy attributes if needed (issuer, key_usage, etc.)
                    }

                cert_info = {
                    "name": full_cert.name,
                    "id": full_cert.id,
                    "version": full_cert.properties.version,
                    "enabled": full_cert.properties.enabled,
                    "not_before": full_cert.properties.not_before,
                    "expires_on": full_cert.properties.expires_on,
                    "created_on": full_cert.properties.created_on,
                    "updated_on": full_cert.properties.updated_on,
                    "thumbprint": full_cert.properties.x509_thumbprint_string, # Useful identifier
                    "tags": full_cert.properties.tags,
                    "policy": policy_details
                }
                certificates_data["certificates"].append(cert_info)
            except Exception as e:
                logging.warning(f"Could not fetch details for certificate '{cert_props.name}' in vault {vault_uri}: {e}")
                # Append basic info even if detail fetch fails
                certificates_data["certificates"].append({
                    "name": cert_props.name,
                    "id": cert_props.id,
                    "enabled": cert_props.enabled,
                    "error": f"Failed to fetch full details: {e}"
                })

        logging.info(f"Found {count} certificates in {vault_uri}.")

    except (HttpResponseError, ClientAuthenticationError) as e:
         error_message = f"Authentication or permission error accessing Key Vault {vault_uri} for certificates: {e}"
         certificates_data["error"] = error_message
         logging.warning(error_message)
    except ImportError:
         error_message = f"azure-keyvault-certificates library not found. Please install it."
         certificates_data["error"] = error_message
         logging.warning(error_message)
    except Exception as e:
         # Catch other potential errors like vault not found, network issues etc.
         error_message = f"Unexpected error fetching certificates from {vault_uri}: {e}"
         certificates_data["error"] = error_message
         logging.error(error_message)

    return certificates_data

# Placeholder for App Settings Fetcher (belongs in a different file, maybe resources.py or web.py)
def fetch_app_settings(credential, subscription_id, resource_group, app_name):
    # This function would use WebSiteManagementClient typically
    logging.warning("App Settings fetcher placeholder - implementation needed.")
    pass 