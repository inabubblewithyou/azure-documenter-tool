import logging
import asyncio
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.core.exceptions import HttpResponseError

async def fetch_database_details(credential, subscription_id):
    """Fetches details for SQL Databases and Cosmos DB instances."""
    logging.info(f"[{subscription_id}] Fetching database details...")
    
    database_data = {
        "sql_servers": [],
        "sql_databases": [],
        "sql_elastic_pools": [],
        "cosmos_accounts": [],
        "cosmos_databases": []
    }
    
    # SQL Server and Database details
    try:
        sql_client = SqlManagementClient(credential, subscription_id)
        
        # Fetch SQL Servers
        servers = list(sql_client.servers.list())
        logging.info(f"[{subscription_id}] Found {len(servers)} SQL servers.")
        
        for server in servers:
            server_details = {
                "id": server.id,
                "name": server.name,
                "resource_group": server.id.split('/')[4],
                "location": server.location,
                "version": server.version,
                "administrator_login": server.administrator_login,
                "state": server.state,
                "fully_qualified_domain_name": server.fully_qualified_domain_name,
                "minimal_tls_version": server.minimal_tls_version,
                "public_network_access": server.public_network_access,
                "tags": server.tags
            }
            
            # Fetch databases for this server
            try:
                databases = list(sql_client.databases.list_by_server(
                    server.id.split('/')[4],
                    server.name
                ))
                
                for db in databases:
                    db_details = {
                        "id": db.id,
                        "name": db.name,
                        "location": db.location,
                        "kind": db.kind,
                        "sku": {
                            "name": db.sku.name if db.sku else None,
                            "tier": db.sku.tier if db.sku else None,
                            "capacity": db.sku.capacity if db.sku else None
                        } if db.sku else None,
                        "status": db.status,
                        "max_size_bytes": db.max_size_bytes,
                        "elastic_pool_id": db.elastic_pool_id,
                        "zone_redundant": db.zone_redundant,
                        "backup_storage_redundancy": getattr(db, 'backup_storage_redundancy', None),
                        "tags": db.tags
                    }
                    database_data["sql_databases"].append(db_details)
                
                # Fetch elastic pools for this server
                elastic_pools = list(sql_client.elastic_pools.list_by_server(
                    server.id.split('/')[4],
                    server.name
                ))
                
                for pool in elastic_pools:
                    pool_details = {
                        "id": pool.id,
                        "name": pool.name,
                        "server_name": server.name,
                        "resource_group": pool.id.split('/')[4],
                        "location": pool.location,
                        "state": pool.state,
                        "sku": {
                            "name": pool.sku.name if pool.sku else None,
                            "tier": pool.sku.tier if pool.sku else None,
                            "capacity": pool.sku.capacity if pool.sku else None
                        },
                        "per_database_settings": {
                            "min_capacity": pool.per_database_settings.min_capacity if pool.per_database_settings else None,
                            "max_capacity": pool.per_database_settings.max_capacity if pool.per_database_settings else None
                        },
                        "tags": pool.tags
                    }
                    database_data["sql_elastic_pools"].append(pool_details)
                    
            except Exception as db_e:
                logging.error(f"[{subscription_id}] Error fetching databases/pools for server {server.name}: {db_e}")
            
            database_data["sql_servers"].append(server_details)
            
    except HttpResponseError as e:
        if e.status_code == 403:
            logging.warning(f"[{subscription_id}] Authorization failed for SQL resources: {e.message}")
        else:
            logging.error(f"[{subscription_id}] Error fetching SQL resources: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching SQL resources: {e}")

    # Cosmos DB details
    try:
        cosmos_client = CosmosDBManagementClient(credential, subscription_id)
        
        # Fetch Cosmos DB accounts
        accounts = list(cosmos_client.database_accounts.list())
        logging.info(f"[{subscription_id}] Found {len(accounts)} Cosmos DB accounts.")
        
        for account in accounts:
            account_details = {
                "id": account.id,
                "name": account.name,
                "resource_group": account.id.split('/')[4],
                "location": account.location,
                "kind": account.kind,
                "write_locations": [loc.location_name for loc in account.write_locations] if account.write_locations else [],
                "read_locations": [loc.location_name for loc in account.read_locations] if account.read_locations else [],
                "enable_automatic_failover": account.enable_automatic_failover,
                "consistency_policy": {
                    "default_consistency_level": str(account.consistency_policy.default_consistency_level) if account.consistency_policy else None,
                    "max_staleness_prefix": account.consistency_policy.max_staleness_prefix if account.consistency_policy else None,
                    "max_interval_in_seconds": account.consistency_policy.max_interval_in_seconds if account.consistency_policy else None
                },
                "ip_rules": [rule.ip_address_or_range for rule in account.ip_rules] if account.ip_rules else [],
                "is_virtual_network_filter_enabled": account.is_virtual_network_filter_enabled,
                "enable_multiple_write_locations": account.enable_multiple_write_locations,
                "enable_cassandra": account.capabilities and any(cap.name == "EnableCassandra" for cap in account.capabilities),
                "enable_table": account.capabilities and any(cap.name == "EnableTable" for cap in account.capabilities),
                "enable_gremlin": account.capabilities and any(cap.name == "EnableGremlin" for cap in account.capabilities),
                "backup_policy": {
                    "type": str(account.backup_policy.type) if account.backup_policy else None,
                    "interval_in_minutes": account.backup_policy.periodic_mode_properties.backup_interval_in_minutes if (account.backup_policy and hasattr(account.backup_policy, 'periodic_mode_properties')) else None,
                    "retention_in_hours": account.backup_policy.periodic_mode_properties.backup_retention_interval_in_hours if (account.backup_policy and hasattr(account.backup_policy, 'periodic_mode_properties')) else None
                },
                "tags": account.tags
            }
            
            # Fetch databases for this account
            try:
                databases = list(cosmos_client.sql_resources.list_sql_databases(
                    account.id.split('/')[4],  # Extract resource group from ID
                    account.name
                ))
                
                for db in databases:
                    db_details = {
                        "id": db.id,
                        "name": db.name,
                        "account_name": account.name,
                        "resource_group": account.id.split('/')[4],  # Extract resource group from ID
                        "location": account.location,
                        "throughput": db.resource.throughput if db.resource else None,
                        "auto_scale_settings": {
                            "max_throughput": db.resource.auto_scale_settings.max_throughput if db.resource and db.resource.auto_scale_settings else None
                        } if db.resource and db.resource.auto_scale_settings else None
                    }
                    database_data["cosmos_databases"].append(db_details)
                    
            except Exception as db_e:
                logging.error(f"[{subscription_id}] Error fetching Cosmos databases for account {account.name}: {db_e}")
            
            database_data["cosmos_accounts"].append(account_details)
            
    except HttpResponseError as e:
        if e.status_code == 403:
            logging.warning(f"[{subscription_id}] Authorization failed for Cosmos DB resources: {e.message}")
        else:
            logging.error(f"[{subscription_id}] Error fetching Cosmos DB resources: {e.message}")
    except Exception as e:
        logging.error(f"[{subscription_id}] Unexpected error fetching Cosmos DB resources: {e}")
    
    return database_data 