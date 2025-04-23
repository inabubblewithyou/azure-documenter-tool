# Azure Documenter Tool


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

* Python 3.12+
* Azure Authentication (CLI or Service Principal)
* Required Azure RBAC Permissions:
  - Reader role at subscription or management group level
  - Additional permissions for enhanced features (e.g., Graph API)
* Graphviz for diagram generation
* Python packages from requirements.txt

## Installation

1. Clone the Repository:
   ```bash
   git clone https://github.com/inabubblewithyou/azure-documenter-tool.git
   cd azure-documenter-tool
   ```

2. Install Python Dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   # or .venv\Scripts\activate.bat  # Windows CMD
   # or .venv\Scripts\Activate.ps1  # Windows PowerShell
   pip install -r requirements.txt
   ```

3. Install Graphviz from https://graphviz.org/download/

4. Authenticate to Azure:
   ```bash
   az login
   # Optional: Set default subscription
   az account set --subscription <subscription-id>
   ```

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

```
outputs/
├── reports/          # Markdown and HTML reports
├── diagrams/         # Network topology diagrams
├── data/            # Raw JSON audit data
├── logs/            # Detailed execution logs
└── version_tracking/ # Document version tracking
```

## Configuration

* Mode Selection: Audit (default) or Design
* Subscription Scope: Interactive or all subscriptions
* Output Control: Normal or silent mode
* Logging: Console (INFO) and File (DEBUG)
* LLM Integration: Configure via environment variables:
  ```env
  # For Azure OpenAI:
  LLM_PROVIDER=AZURE_OPENAI
  AZURE_OPENAI_API_KEY=your_api_key
  AZURE_OPENAI_ENDPOINT=your_endpoint
  AZURE_OPENAI_DEPLOYMENT=your_deployment_name

  # Or for OpenAI:
  LLM_PROVIDER=OPENAI
  OPENAI_API_KEY=your_api_key
  ```

## Documentation

For detailed documentation, feature descriptions, and troubleshooting guides, please refer to the project wiki. 