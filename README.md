# Azure Documenter Tool

## 🔍 Purpose

A powerful automated tool that audits and documents Azure infrastructure across multiple subscriptions within a tenant. It automatically discovers, analyzes, and describes Azure resources, networks, security posture, costs, and governance status, generating both detailed audit reports and comprehensive design documents.

## ✅ Core Features

*   **Interactive Subscription Selection:** Choose which subscriptions to audit through an interactive menu, or select all available subscriptions.
*   **Multi-Subscription Audit:** Enumerates all accessible Azure subscriptions via `DefaultAzureCredential`.
*   **Comprehensive Data Collection:** Gathers detailed information about:
    *   Resources (Name, Type, Location, Tags, SKU, Resource Group)
    *   Identity & Access Management (Tenant Domain, RBAC Summary, Privileged Accounts, Managed Identity - *Service Principal analysis requires Graph API setup*)
    *   Networking (VNets, Subnets, Peering, Gateways, Firewalls, DDoS, Private Endpoints, Public IPs, DNS, Service Endpoints, Private Link Services)
    *   Compute & Application Services (VMs, App Services, Runtimes, Serverless Components [Functions, Logic Apps, Container Apps, APIM, Event Grid], Container Services [AKS, ACI])
    *   Data Platform (Storage Accounts, Data Lakes, Databases - SQL, NoSQL, Analytics Services, Encryption, Classification, Sovereignty)
    *   Security (Defender for Cloud Plans, Sentinel, Key Vaults, Access Policies)
    *   Monitoring & Operations (Log Analytics, Backup Vaults, ASR - *basic detection*)
    *   Governance (Policy Assignments, Non-Compliant States, Advisor Recommendations, Tagging Analysis, Lifecycle Policies)
    *   Costs (Month-to-Date actual costs via `azure-mgmt-consumption`)
*   **Network Visualization:**
    *   **Tenant-Wide Network Diagram:** Shows all VNets across subscriptions and their peering relationships, automatically identifying Hub-Spoke topology.
    *   **Per-Subscription VNet Diagrams:** Detailed network diagrams for each subscription.
*   **Multiple Export Formats:** Generates reports and data in:
    *   **Markdown Audit Report:** (`outputs/reports/azure_audit_report_TIMESTAMP.md`) Detailed raw data and technical findings.
    *   **Markdown Design Document:** (`outputs/reports/azure_design_document_TIMESTAMP_vX.X.md`) A structured enterprise architecture document populated with discovered data, versioned automatically.
    *   **Static HTML Reports:** (`outputs/reports/...TIMESTAMP.html`) Browsable HTML versions of both Markdown reports with enhanced styling, TOC navigation, fixed header, and properly rendered tables.
    *   **JSON:** Raw aggregated data from all fetchers (`outputs/data/azure_data_TIMESTAMP.json`).
*   **Delta Comparison:** Compare two audit runs (JSON data files) to identify changes:
    *   Added, removed, and modified resources, VNets, subnets, peerings, etc.
    *   Resolved and new policy violations and advisor recommendations.
    *   Generates dedicated delta reports (Markdown and HTML) with clear highlighting of changes.
*   **Execution Modes:**
    *   `Audit` (default): Generates the detailed technical audit report (Markdown/HTML).
    *   `Design`: Generates the comprehensive Design Document report (Markdown/HTML), populating a template with discovered data.
*   **Version Tracking:** Automatically increments and tracks the document version number for the Design Document based on the tenant ID (`outputs/version_tracking/tenant_TENANT_ID.json`).
*   **Silent Mode:**
    *   Run the tool with the `--silent` flag to suppress console output.
    *   Ideal for automated scripts or scheduled tasks.
    *   Logs are still written to files in `outputs/logs`.
*   **Branding Update:** Uses "Entra ID" terminology instead of "Azure AD".

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
│   └── identity.py       # Added for Entra ID/SP related fetchers
├── generators/           # Modules for creating outputs
│   ├── diagram_generator.py    # Creates network diagrams
│   ├── markdown_writer.py     # Creates Audit Markdown report
│   ├── design_document_writer.py # Creates Design Document Markdown report
│   ├── html_exporter.py       # Converts Markdown to HTML with enhancements
│   ├── delta_report_writer.py # Creates delta comparison reports
│   └── llm_writer.py        # Optional LLM enhancement (if configured)
├── outputs/              # Default directory for generated files
│   ├── reports/          # Markdown and HTML reports
│   ├── diagrams/         # PNG diagrams
│   ├── data/             # Raw JSON audit files
│   ├── logs/             # Log files (DEBUG level logging by default)
│   └── version_tracking/ # Tracks Design Document versions per tenant
├── .env.template         # Template for environment variables
└── requirements.txt      # Python dependencies
```

## ⚙️ Requirements

*   Python 3.8+
*   Azure CLI installed and authenticated (`az login`) OR Azure Service Principal environment variables set (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`).
*   **Required Permissions:** The identity used needs sufficient Azure RBAC permissions (typically `Reader` role at the root Management Group or individual subscriptions) to list resources, network components, security settings, policies, and costs across the desired scope. *Graph API permissions (e.g., `Directory.Read.All`) are needed for full Service Principal analysis.*
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
    # Linux/macOS:
    source .venv/bin/activate
    # Windows (Command Prompt):
    # .venv\\Scripts\\activate.bat
    # Windows (PowerShell):
    # .venv\\Scripts\\Activate.ps1

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
5.  **(Optional) Configure Environment Variables:**
    *   Copy the template environment file:
    ```bash
    # In the azure_documenter directory
    cp .env.template .env
    ```
    *   Edit the `.env` file if needed (e.g., for LLM API keys - not currently implemented). Logging level is now handled directly in `main.py`.

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
    (No console output, check `outputs/logs` for detailed logs)

*   **Compare Two Previous Audit Runs (using JSON data files):**
    ```bash
    # Get timestamps from the JSON filenames in outputs/data/
    python azure_documenter/main.py --compare TIMESTAMP1 TIMESTAMP2
    ```
    Example:
    ```bash
    python azure_documenter/main.py --compare 20250411_194838 20250411_201500
    ```
    This loads the audit data from the specified JSON files, analyzes changes, and generates delta reports.

Outputs are generated in the `azure_documenter/outputs/` directory, organized into `reports/`, `diagrams/`, `data/`, `logs/`, and `version_tracking/`.

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
*   **Logging:** Console logs INFO+, File logs DEBUG+ (in `outputs/logs/`).

## 📚 Key Report Sections (Design Document Mode)

The generated Design Document (`--mode Design`) provides a structured overview:

1.  **Executive Summary:** High-level overview, current state, recommendations.
2.  **Enterprise Organization:** Management groups, subscription strategy, RG patterns, resource lifecycle tags.
3.  **Identity & Access Management:** Tenant details, AuthN/AuthZ (RBAC summary), PIM, Service Principals (stubbed).
4.  **Network Architecture:** Topology (Hub-Spoke detection), connectivity, security, DNS, private access (Private Endpoints, Service Endpoints, Private Link Services).
5.  **Compute & Application Services:** Workload patterns (IaaS/PaaS), App/API/Container/Serverless summaries.
6.  **Data Platform:** Storage, databases, analytics, data protection.
7.  **Security & Compliance:** Security posture, SecOps, key management, compliance.
8.  **Monitoring & Operations:** Logging, visibility, alerting, ITSM.
9.  **Business Continuity & Disaster Recovery:** Resilience, backup, DR.
10. **Cost Management & Optimization:** Cost structure (MTD costs), optimization, budgets.
11. **Governance & Compliance:** Policy framework, resource governance (tagging, lifecycle policies).
12. **Roadmap & Recommendations:** Maturity assessment, strategic initiatives.
13. **Landing Zone Design:** Target model, examples.
14. **Appendix:** Technical details, diagrams, tables (policy states, privileged roles, etc.).

## 📝 Future Enhancements

*   **Fetchers for Missing Data:** Implement fetchers for Management Groups, Route Tables, WAF, Diagnostic Settings, Alerts, detailed Costs, Policy Definitions, Custom Roles, JIT, App Settings, Key Vault Certs, etc.
*   **Full Service Principal Analysis:** Implement Graph API calls in `fetchers/identity.py`.
*   **Deeper Analysis Helpers:** Improve analysis logic for DNS flows, tagging maturity, technical debt, etc.
*   **Interactive HTML Reports:** Add client-side filtering/sorting to tables.
*   **More Diagram Types:** Tenant resource connectivity, application dependency maps.
*   **Configuration File:** Move more settings (e.g., output paths, default mode) to a config file instead of command-line args.
*   **Error Handling:** More granular error reporting per fetcher/section.
*   **Testing:** Add unit and integration tests.
*   **LLM Integration:** Re-enable/refine optional LLM enhancement for summaries. 