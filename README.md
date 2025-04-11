# Azure Documenter Tool

## 🔍 Purpose

A powerful automated tool that audits and documents Azure infrastructure across multiple subscriptions within a tenant. It automatically discovers, analyzes, and describes Azure resources, networks, security posture, costs, and governance status, generating both detailed audit reports and comprehensive design documents.

## ✅ Core Features

*   **Interactive Subscription Selection:** Choose which subscriptions to audit through an interactive menu, or select all available subscriptions.
*   **Multi-Subscription Audit:** Enumerates all accessible Azure subscriptions via `DefaultAzureCredential`.
*   **Comprehensive Data Collection:** Gathers detailed information about:
    *   Resources (Name, Type, Location, Tags, SKU, Resource Group)
    *   Identity & Access Management (Tenant Domain, RBAC, Privileged Accounts, PIM, Managed Identity)
    *   Networking (VNets, Subnets, Peering, Gateways, Firewalls, DDoS, Private Endpoints, Public IPs, DNS)
    *   Compute & Application Services (VMs, App Services, Runtime Stacks, Containers, Serverless - *basic detection*)
    *   Data Platform (Storage Accounts, Data Lakes, Databases - SQL, NoSQL, Analytics Services, Encryption, Classification, Sovereignty)
    *   Security (Defender for Cloud Plans, Sentinel, Key Vaults, Vulnerability Management - *basic detection*)
    *   Monitoring & Operations (Log Analytics, Backup Vaults, ASR, Agent Status - *basic detection*)
    *   Governance (Policy Assignments, Non-Compliant States, Advisor Recommendations)
    *   Costs (Month-to-Date actual costs via `azure-mgmt-consumption`)
*   **Network Visualization:**
    *   **Tenant-Wide Network Diagram:** Shows all VNets across subscriptions and their peering relationships, automatically identifying Hub-Spoke topology.
    *   **Per-Subscription VNet Diagrams:** Detailed network diagrams for each subscription.
*   **Multiple Export Formats:** Generates reports and data in:
    *   **Markdown Audit Report:** (`outputs/reports/azure_audit_report_TIMESTAMP.md`) Detailed raw data and technical findings.
    *   **Markdown Design Document:** (`outputs/reports/azure_design_document_TIMESTAMP.md`) A structured enterprise architecture document populated with discovered data.
    *   **Static HTML Reports:** (`outputs/reports/...TIMESTAMP.html`) Browsable HTML versions of both Markdown reports with enhanced styling and local assets.
    *   **CSV:** Raw resource inventory data (`outputs/data/azure_resource_inventory_TIMESTAMP.csv`).
    *   **JSON:** Raw aggregated data from all fetchers (`outputs/data/azure_data_TIMESTAMP.json`).
*   **Delta Comparison:** Compare two audit runs (JSON data files) to identify changes:
    *   Added, removed, and modified resources, VNets, subnets, peerings, etc.
    *   Resolved and new policy violations and advisor recommendations.
    *   Generates dedicated delta reports (Markdown and HTML) with clear highlighting of changes.
*   **Execution Modes:**
    *   `Audit` (default): Generates the detailed technical audit report (Markdown/HTML).
    *   `Design`: Generates the comprehensive Design Document report (Markdown/HTML), populating a template with discovered data.
*   **Silent Mode:**
    *   Run the tool with the `--silent` flag to suppress console output.
    *   Ideal for automated scripts or scheduled tasks.
    *   Logs are still written to files in `outputs/logs`.

## 🧱 Project Structure

```
azure_documenter/
├── main.py               # Entrypoint, orchestrates fetching and generation
├── config.py             # Handles configuration (e.g., LLM keys via .env)
├── delta_analyzer.py     # Compares audit data from different runs
├── fetchers/             # Modules for calling Azure APIs (resources, network, security, etc.)
│   ├── resources.py
│   ├── network.py
│   ├── security.py
│   ├── costs.py
│   ├── governance.py
│   ├── monitoring.py     # Added for monitoring/operations data
│   └── identity.py       # Added for identity data
├── generators/           # Modules for creating outputs
│   ├── diagram_generator.py    # Creates network diagrams
│   ├── markdown_writer.py     # Creates Audit Markdown report & CSV
│   ├── design_document_writer.py # Creates Design Document Markdown report
│   ├── html_exporter.py       # Converts Markdown to HTML
│   └── delta_report_writer.py # Creates delta comparison reports
├── outputs/              # Default directory for generated files
│   ├── reports/          # Markdown and HTML reports
│   ├── diagrams/         # PNG/SVG diagrams
│   ├── data/             # CSV data exports & raw JSON files
│   └── logs/             # Log files, especially for silent mode
├── .env.template         # Template for environment variables
└── requirements.txt      # Python dependencies
```

## ⚙️ Requirements

*   Python 3.8+
*   Azure CLI installed and authenticated (`az login`) OR Azure Service Principal environment variables set (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`).
*   **Required Permissions:** The identity used needs sufficient Azure RBAC permissions (typically `Reader` role at the root Management Group or individual subscriptions) to list resources, network components, security settings, policies, and costs across the desired scope.
*   Graphviz: The core Graphviz binaries must be installed and available in your system's PATH for diagram generation. (See [https://graphviz.org/download/](https://graphviz.org/download/))
*   Python packages listed in `azure_documenter/requirements.txt`.

## 🛠️ Setup & Installation

1.  **Clone the Repository:**
    ```bash
    git clone <repository_url>
    cd azure-documenter-tool
    ```
2.  **Install Python Dependencies:**
    ```bash
    # Recommended: Create and activate a virtual environment
    python -m venv .venv
    source .venv/bin/activate  # Linux/macOS
    # .venv\Scripts\activate    # Windows

    pip install -r azure_documenter/requirements.txt
    ```
3.  **Install Graphviz:** Download and install Graphviz for your OS from [graphviz.org](https://graphviz.org/download/) and ensure the `dot` command is accessible in your PATH.
4.  **Authenticate to Azure:**
    *   **Recommended:** Use Azure CLI:
        ```bash
        az login
        az account set --subscription <your-primary-subscription-id> # Optional
        ```
    *   **Alternatively:** Set environment variables for a Service Principal.
5.  **(Optional) Configure Logging:**
    *   Copy the template environment file:
    ```bash
    cp azure_documenter/.env.template azure_documenter/.env
    ```
    *   Edit the `.env` file to set the `LOG_LEVEL` (DEBUG, INFO, WARNING, ERROR, CRITICAL).

## 🚀 Usage

Navigate to the root directory (`azure-documenter-tool/`) in your terminal.

*   **Run in Audit Mode (Default):**
    ```bash
    python azure_documenter/main.py
    ```
    (Select subscriptions interactively)

*   **Run Audit Mode for All Subscriptions:**
    ```bash
    python azure_documenter/main.py --all-subscriptions
    ```

*   **Run in Design Mode for All Subscriptions:**
    ```bash
    python azure_documenter/main.py --mode Design --all-subscriptions
    ```

*   **Run Silently (e.g., for Automation):**
    ```bash
    python azure_documenter/main.py --mode Design --all-subscriptions --silent
    ```
    (No console output, check `outputs/logs` for details)

*   **Compare Two Previous Audit Runs (using JSON data files):**
    ```bash
    # Get timestamps from the JSON filenames in outputs/data/
    python azure_documenter/main.py --compare TIMESTAMP1 TIMESTAMP2
    ```
    Example:
    ```bash
    python azure_documenter/main.py --compare 20250410_011459 20250410_021824
    ```
    This loads the audit data from the specified JSON files, analyzes changes, and generates delta reports.

Outputs are generated in the `azure_documenter/outputs/` directory, organized into `reports/`, `diagrams/`, `data/`, and `logs/`.

## 📋 Typical Workflow

1.  **Initial Documentation (Design Mode):** Run the tool in Design mode to get a comprehensive baseline document.
    ```bash
    python azure_documenter/main.py --mode Design --all-subscriptions
    ```
2.  **Periodic Audits:** Run the tool in Audit mode regularly (e.g., weekly, monthly) to capture the current state.
    ```bash
    python azure_documenter/main.py --all-subscriptions --silent # For automation
    ```
3.  **Change Verification:** After making infrastructure changes, run an audit and compare it to a previous baseline.
    ```bash
    # Run new audit
    python azure_documenter/main.py --all-subscriptions
    # Compare (replace timestamps)
    python azure_documenter/main.py --compare <timestamp_before_changes> <timestamp_after_changes>
    ```
4.  **Review Delta Report:** Examine the generated delta report to verify changes and identify unexpected drift.

## 🔧 Configuration

*   **Subscription Selection:** Interactive prompt by default, or use `--all-subscriptions`.
*   **Execution Mode:** Use `--mode Audit` (default) or `--mode Design`.
*   **Silent Mode:** Use `--silent` to suppress console output.
*   **Logging:** Control verbosity via `LOG_LEVEL` in the `.env` file.

## 📚 Key Report Sections (Design Document Mode)

The generated Design Document (`--mode Design`) provides a structured overview:

1.  **Executive Summary:** High-level overview, current state, recommendations.
2.  **Enterprise Organization:** Management groups, subscription strategy.
3.  **Identity & Access Management:** Tenant details, AuthN/AuthZ, PIM.
4.  **Network Architecture:** Topology (Hub-Spoke detection), connectivity, security, DNS, private access.
5.  **Compute & Application Services:** Workload patterns (IaaS/PaaS), scaling, DevOps.
6.  **Data Platform:** Storage, databases, analytics, data protection.
7.  **Security & Compliance:** Security posture, SecOps, key management, compliance.
8.  **Monitoring & Operations:** Logging, visibility, alerting, ITSM.
9.  **Business Continuity & Disaster Recovery:** Resilience, backup, DR.
10. **Cost Management & Optimization:** Cost structure, optimization, budgets.
11. **Governance & Compliance:** Policy framework, resource governance.
12. **Roadmap & Recommendations:** Maturity assessment, strategic initiatives.
13. **Landing Zone Design:** Target model, examples.
14. **Appendix:** Technical details, diagrams, tables (policy states, privileged roles, etc.).

## 📝 Future Enhancements

*   More detailed resource configuration fetching (e.g., specific NSG rules, App Service settings).
*   Deeper Azure AD analysis.
*   Tenant-wide resource interconnectivity diagrams (beyond network peering).
*   Interactive HTML reports with filtering/sorting.
*   Built-in policy compliance evaluation templates.
*   Direct integration with documentation platforms (e.g., SharePoint, Confluence). 