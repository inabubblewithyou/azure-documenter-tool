# Azure Documenter Tool

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

## Overview

The Azure Documenter Tool is a Python-based utility designed to automate the discovery, analysis, and documentation of Microsoft Azure environments. It connects to Azure using standard authentication methods, gathers detailed information across specified subscriptions, and generates comprehensive reports and diagrams.

This tool aims to simplify and accelerate the process of understanding complex Azure deployments, performing audits, generating design documentation, and tracking changes over time.

## Who is this for?

*   **Cloud Architects:** To visualize, document, and validate Azure architecture designs.
*   **Azure Administrators:** To audit configurations, manage resources, and track inventory.
*   **Security Analysts:** To review security posture, identify potential risks, and assess compliance.
*   **Consultants:** To quickly understand and document client Azure environments.
*   **DevOps Engineers:** To integrate infrastructure documentation into CI/CD pipelines.

## Key Features

### Comprehensive Data Fetching
The tool utilizes various fetcher modules (`azure_documenter/fetchers/`) to gather data across multiple Azure service categories:

*   **Core Infrastructure:** Resource Groups, Subscriptions, Management Groups, Resources (general inventory).
*   **Compute:** Virtual Machines (details, sizes, OS), Availability Sets, Scale Sets.
*   **Networking:** VNets, Subnets, VNet Peerings, Network Security Groups (NSGs), Route Tables, Public IPs, VPN Gateways, ExpressRoute Circuits, Azure Firewalls, Load Balancers (Standard/Basic), Application Gateways, Front Doors, Traffic Manager Profiles, Private DNS Zones, Private Endpoints, DDoS Protection Plans.
*   **Storage:** Storage Accounts (types, replication, endpoints), Managed Disks.
*   **Databases:** Azure SQL Databases/Servers, Cosmos DB Accounts, MySQL, PostgreSQL.
*   **Web & Applications:** App Services, App Service Plans, Function Apps.
*   **Security:** Microsoft Defender for Cloud (Plans, Score), Security Center Policies, JIT Policies, Role Assignments (RBAC), Custom Roles, Key Vaults (details, access policies, certificates, secrets overview).
*   **Identity:** Entra ID Tenant Details, Service Principals (summary).
*   **Governance:** Azure Policy States, Advisor Recommendations, Management Group Hierarchy.
*   **Monitoring:** Log Analytics Workspaces, Diagnostic Settings, Autoscale Settings.
*   **Costs:** Subscription-level cost summaries (MTD, previous month).
*   **AI Services:** Cognitive Services, Azure Search, Bot Services.

### Report Generation & Analysis
Based on the fetched data, the tool generates various outputs using modules in `azure_documenter/generators/`:

*   **Design Document (`--mode Design`):**
    *   A high-level architectural overview and analysis.
    *   Includes executive summaries, network topology analysis, security posture assessment, cost analysis, and recommendations.
    *   Ideal for understanding the overall design and identifying areas for improvement.
    *   Automatically versioned using `outputs/version_tracking/`.
    *   Optionally enhanceable with AI analysis using the `--llm` flag (requires configuration).
*   **Audit Report (`--mode Audit` - Default):**
    *   A detailed, resource-focused report.
    *   Provides inventories, configurations, and status details for discovered resources.
    *   Suitable for in-depth technical reviews and compliance checks.
*   **Network Diagrams:**
    *   Generates network topology diagrams using Graphviz and the `diagrams` library.
    *   Provides both tenant-wide overviews and subscription-specific VNet diagrams.
    *   Outputs diagrams in PNG format to `outputs/diagrams/`.
*   **Output Formats:**
    *   Primary reports generated in **Markdown** (`outputs/reports/`).
    *   Markdown reports automatically converted to static **HTML** with navigation (`outputs/reports/`).
    *   Raw fetched data saved as **JSON** files (`outputs/data/`) per run, containing all collected details. These files enable the Compare and Regenerate modes.
*   **Delta Comparison (`--mode Compare`):**
    *   Compares two previous runs using the timestamps from their respective JSON data files.
    *   Generates a report highlighting added, removed, or modified resources/configurations.
*   **Report Regeneration (`--mode Regenerate`):**
    *   Re-generates an Audit or Design report from a previously saved JSON data file without needing to re-scan Azure.
    *   Identifies the correct data file using the run timestamp (`--input-timestamp`).
    *   Useful for generating different report types from the same data or recovering a deleted report.
    *   *Note:* Regenerated reports rely on the original diagrams still being present in the `outputs/diagrams` directory from the initial run.

### Additional Features

*   **Interactive/Automated Subscription Selection:** Choose subscriptions interactively or process all accessible ones (`--all-subscriptions`).
*   **Silent Mode (`--silent`):** Suppresses console output for use in automated scripts or pipelines.
*   **Detailed Logging:** Records execution details and potential errors to `outputs/logs/`.
*   **Authentication Flexibility:** Uses `DefaultAzureCredential`, supporting Azure CLI login, Service Principals, Managed Identity, etc.
*   **Cross-Platform:** Runs on Windows, macOS, and Linux.

## Requirements

### Software
1.  **Python:** Version 3.8 or higher.
2.  **Git:** To clone the repository.
3.  **Graphviz:** Required for generating network diagrams. Install from [graphviz.org/download/](https://graphviz.org/download/) and ensure the `dot` executable is in your system's PATH.
4.  **Python Packages:** Listed in `requirements.txt`.

### Azure
1.  **Azure Account:** Access to an Azure tenant and one or more subscriptions.
2.  **Azure RBAC Permissions:** The identity running the tool (User or Service Principal) needs appropriate permissions on the target subscriptions or management groups.
    *   **Minimum:** The **`Reader`** role is generally required for basic resource discovery.
    *   **Recommended for Full Detail:** To fetch comprehensive details across all categories (especially security settings, cost data, policy assignments, and Entra ID information), broader permissions might be necessary. Consider roles like **`Security Reader`**, **`Cost Management Reader`**, and potentially permissions to read Entra ID data (like **`Directory Readers`**). Always grant permissions based on the principle of least privilege according to your organization's policies.

## Installation

1.  **Clone the Repository:**
    ```bash
    git clone <repository_url> # Replace with the actual URL
    cd azure-documenter-tool
    ```

2.  **Create and Activate a Virtual Environment:** (Recommended)
    ```bash
    # Linux/macOS
    python3 -m venv .venv
    source .venv/bin/activate

    # Windows (Command Prompt)
    python -m venv .venv
    .venv\\Scripts\\activate.bat

    # Windows (PowerShell)
    python -m venv .venv
    .venv\\Scripts\\Activate.ps1
    ```

3.  **Install Python Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: The `requirements.txt` file is located inside the project root)*

4.  **Install Graphviz:** Follow instructions for your OS at [graphviz.org/download/](https://graphviz.org/download/). Verify installation by running `dot -V` in your terminal.

## Authentication

The tool uses Azure Identity's `DefaultAzureCredential`. This automatically tries multiple authentication methods in a predefined order. The most common methods are:

1.  **Azure CLI:** Log in via your terminal before running the script. This is often the simplest method for interactive use.
    ```bash
    az login
    az account set --subscription <your-target-subscription-id> # Optional, but recommended
    ```
2.  **Environment Variables (Service Principal):** Suitable for automation. Set the following environment variables:
    *   `AZURE_CLIENT_ID`: The Application (client) ID of your Service Principal.
    *   `AZURE_TENANT_ID`: Your Azure Tenant ID.
    *   `AZURE_CLIENT_SECRET`: The client secret for your Service Principal.
    *(See Azure documentation for creating Service Principals and assigning roles).*\
3.  **Other Methods:** `DefaultAzureCredential` also supports Managed Identity (useful when running on Azure resources like VMs or App Services), Visual Studio Code credentials, etc. See the Azure SDK for Python documentation for the full list and order.

## Usage

Run the tool from the project's root directory using the `main.py` script located inside the `azure_documenter` folder.

```bash
python azure_documenter/main.py [OPTIONS]
```

### Modes & Key Options

*   **`--mode Audit`** (Default): Generates a detailed audit report focusing on resource inventory and configuration.
*   **`--mode Design`**: Generates a higher-level design document focusing on architecture, security, and cost analysis.
*   **`--mode Compare --compare TIMESTAMP1 TIMESTAMP2`**: Compares two previous runs identified by the timestamps in their data file names (e.g., `20231027_103000`). Requires the corresponding JSON files in `outputs/data/`.
*   **`--mode Regenerate --input-timestamp TIMESTAMP --output-type {Audit|Design}`**: Regenerates a report from a previous run's data. Requires the corresponding JSON file in `outputs/data/` and relies on diagrams from the original run still existing in `outputs/diagrams/`.
    *   `--input-timestamp`: The `YYYYMMDD_HHMMSS` timestamp from the data filename.
    *   `--output-type`: Specify whether to generate an `Audit` or `Design` report.
*   **`--all-subscriptions`**: Process all subscriptions accessible to the authenticated identity without prompting.
*   **`--silent`** or **`-s`**: Run in silent mode, suppressing console output (logs are still written to file). Useful for automation.
*   **`--llm`**: (Use with `--mode Design`) Enables AI-enhanced analysis and summaries in the Design Document. Requires LLM provider configuration (see below).

### Examples

```bash
# Run default Audit mode, selecting subscriptions interactively
python azure_documenter/main.py

# Generate a Design Document for all subscriptions silently
python azure_documenter/main.py --mode Design --all-subscriptions --silent

# Generate a Design Document with LLM enhancements for selected subscriptions
python azure_documenter/main.py --mode Design --llm

# Compare two specific audit runs
python azure_documenter/main.py --mode Compare --compare 20231026_150000 20231027_090000

# Regenerate a Design report from a previous run identified by its timestamp
python azure_documenter/main.py --mode Regenerate --input-timestamp 20240115_112233 --output-type Design

# Regenerate an Audit report from a previous run
python azure_documenter/main.py --mode Regenerate --input-timestamp 20240115_112233 --output-type Audit
```

## Output Structure

All outputs are placed in the `outputs/` directory, created inside the `azure_documenter` folder:

```
azure-documenter-tool/
├── azure_documenter/
│   ├── outputs/
│   │   ├── reports/          # Generated Markdown (.md) and HTML (.html) reports
│   │   ├── diagrams/         # Network topology diagrams (.png)
│   │   ├── data/             # Raw fetched data per run (.json)
│   │   ├── logs/             # Detailed execution logs (.log)
│   │   ├── csv/              # CSV data exports (e.g., resource summary from Audit mode)
│   │   └── version_tracking/ # Stores the latest version number for Design Docs
│   ├── fetchers/
│   ├── generators/
│   └── main.py
├── requirements.txt
└── README.md
```

*   **Reports:** Files are named descriptively, including the mode (Audit/Design/Delta/Regenerated type), tenant name, timestamp, and version (for Design mode).
*   **Diagrams:** Named by tenant/subscription and type (e.g., `tenant_network_topology_<timestamp>.png`, `subid_vnet_topology_<timestamp>.png`).
*   **Data:** Raw JSON files are named `azure_audit_raw_data_{TenantName}_{Timestamp}_v{Version}.json`. These comprehensive files contain all data fetched during the run and are essential for the `--mode Compare` and `--mode Regenerate` features.
*   **Logs:** Named `azure_documenter_run_{Timestamp}.log`.
*   **CSV Exports:** Contains structured data exports. Currently includes `azure_audit_resource_summary_{TenantName}_{Timestamp}_v{Version}.csv` generated during Audit mode runs.
*   **Version Tracking:** JSON files named `tenant_{TenantID}.json` track the latest version number used for a tenant's Design documents.

## Configuration (Optional - LLM Integration)

To use the `--llm` feature for enhanced Design Documents, you need to configure access to an OpenAI or Azure OpenAI model.

1.  Create a `.env` file in the `azure_documenter` directory (alongside `main.py`).
2.  Add the relevant variables based on your provider:

    **For Azure OpenAI:**
    ```dotenv
    LLM_PROVIDER=AZURE_OPENAI
    AZURE_OPENAI_API_KEY=your_api_key
    AZURE_OPENAI_ENDPOINT=https://your-aoai-resource.openai.azure.com/
    AZURE_OPENAI_DEPLOYMENT=your_deployment_or_model_name
    # Optional: Specify API version if needed
    # AZURE_OPENAI_API_VERSION=2023-05-15
    ```

    **For OpenAI:**
    ```dotenv
    LLM_PROVIDER=OPENAI
    OPENAI_API_KEY=your_openai_api_key
    # Optional: Specify model name if not using default (e.g., gpt-4)
    # OPENAI_MODEL_NAME=gpt-4
    ```

Ensure the model you specify (via deployment name or model name) is suitable for text generation and analysis tasks. If `LLM_PROVIDER` is not set or set to `none`, the LLM features will be disabled.

## Contributing

Contributions are welcome! Please follow standard Fork and Pull Request workflows. Ensure code includes appropriate logging and adheres to general Python best practices.

## License

(Specify License Here - e.g., MIT License) 