# Azure Documenter Tool

## 🔍 Purpose

A powerful automated tool that audits and documents Azure infrastructure across multiple subscriptions within a tenant. It replaces manual documentation efforts by automatically discovering, analyzing, and describing Azure resources, networks, security posture, costs, and governance status.

## ✅ Core Features

*   **Interactive Subscription Selection:** Choose which subscriptions to audit through an interactive menu, or select all available subscriptions.
*   **Multi-Subscription Audit:** Enumerates all accessible Azure subscriptions via `DefaultAzureCredential`.
*   **Comprehensive Data Collection:** Gathers detailed information about:
    *   Resources (Name, Type, Location, Tags, Resource Group)
    *   Networking (VNets, Subnets, NSGs, VNet Peerings)
    *   Security (RBAC Role Assignments, Global Administrators, Privileged Accounts, Security Center Secure Score)
    *   Costs (Month-to-Date actual costs via `azure-mgmt-consumption`)
    *   Governance (Non-compliant Policy States, Advisor Recommendations)
*   **Network Visualization:**
    *   **Tenant-Wide Network Diagram:** Shows all VNets across subscriptions and their peering relationships
    *   **Per-Subscription VNet Diagrams:** Detailed network diagrams for each subscription
*   **Multiple Export Formats:** Generates reports and data in:
    *   **Markdown:** Detailed report (`outputs/reports/azure_audit_report_TIMESTAMP.md`) suitable for documentation systems or direct viewing.
    *   **Static HTML:** A browsable HTML version of the Markdown report (`outputs/reports/azure_audit_report_TIMESTAMP.html`) with basic styling. All assets are local.
    *   **CSV:** Raw resource inventory data (`outputs/data/azure_resource_inventory_TIMESTAMP.csv`).
*   **Delta Comparison:** Compare two audit runs to identify changes:
    *   Added, removed, and modified resources, VNets, subnets, peerings, etc.
    *   Resolved and new policy violations and advisor recommendations.
    *   Generates dedicated delta reports with clear highlighting of changes.
*   **Security Information:** Consolidated tenant-wide security details including:
    *   List of Global Administrators and Privileged Accounts across all subscriptions
    *   Non-Compliant Policy States with resource and subscription information
    *   Security Advisories sorted by category and impact
*   **Optional LLM Integration (Design Mode):**
    *   If configured with an OpenAI or Azure OpenAI API key and run in `--mode Design`.
    *   Generates AI-powered narrative summaries for each subscription's architecture.
    *   Embeds these summaries into the **Markdown** report.
*   **Audit vs. Design Modes:**
    *   `Audit` (default): Focuses on technical details and raw data.
    *   `Design`: Includes technical details plus LLM-generated narrative summaries (if configured).

## 🧱 Project Structure

```
azure_documenter/
├── main.py               # Entrypoint, orchestrates fetching and generation
├── config.py             # Handles configuration (e.g., LLM keys via .env)
├── delta_analyzer.py     # Compares audit data from different runs
├── fetchers/             # Modules for calling Azure APIs
│   ├── resources.py      # Resource information
│   ├── network.py        # VNets, subnets, peerings, NSGs
│   ├── security.py       # RBAC, privileged accounts, security score
│   ├── costs.py          # Consumption cost data
│   └── governance.py     # Policies and advisor recommendations
├── generators/           # Modules for creating outputs
│   ├── diagram_generator.py    # Creates network diagrams
│   ├── llm_writer.py          # Generates LLM summaries
│   ├── markdown_writer.py     # Creates Markdown report & CSV
│   ├── html_exporter.py       # Converts Markdown to HTML
│   └── delta_report_writer.py # Creates delta comparison reports
├── outputs/              # Default directory for generated files
│   ├── reports/          # Markdown and HTML reports
│   ├── diagrams/         # PNG/SVG diagrams
│   └── data/             # CSV data exports & raw JSON files
├── .env.template         # Template for environment variables
└── requirements.txt      # Python dependencies
```

## ⚙️ Requirements

*   Python 3.7+
*   Azure CLI installed and configured OR Azure Service Principal environment variables set (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`).
*   Graphviz: The core Graphviz binaries must be installed and available in your system's PATH for diagram generation. (See [https://graphviz.org/download/](https://graphviz.org/download/))
*   Python packages listed in `azure_documenter/requirements.txt`.

## 🛠️ Setup & Installation

1.  **Clone the Repository (or ensure you have the code):**
    ```bash
    git clone <repository_url>
    cd azure-documenter-tool
    ```
2.  **Install Python Dependencies:**
    ```bash
    pip install -r azure_documenter/requirements.txt
    ```
3.  **Install Graphviz:** Download and install Graphviz for your operating system from [graphviz.org](https://graphviz.org/download/) and ensure the `dot` command is accessible in your PATH.
4.  **Authenticate to Azure:**
    *   **Recommended:** Use Azure CLI:
        ```bash
        az login
        az account set --subscription <your-default-subscription-id> # Optional but helpful
        ```
    *   **Alternatively:** Set environment variables for a Service Principal:
        *   `AZURE_CLIENT_ID`
        *   `AZURE_TENANT_ID`
        *   `AZURE_CLIENT_SECRET`
5.  **(Optional) Configure LLM and Logging:**
    *   If you want to use the `--mode Design` feature with AI summaries or configure logging, copy the template environment file:
    ```bash
    cp azure_documenter/.env.template azure_documenter/.env
    ```
    *   Edit the `.env` file to add your API keys and configure other settings.

        **For Azure OpenAI:**
        ```dotenv
        LLM_PROVIDER="AZURE_OPENAI"
        AZURE_OPENAI_API_KEY="your_azure_openai_key"
        AZURE_OPENAI_ENDPOINT="https://your_azure_openai_endpoint.openai.azure.com/"
        AZURE_OPENAI_DEPLOYMENT="your_deployment_name" # e.g., gpt-35-turbo
        ```

        **For OpenAI:**
        ```dotenv
        LLM_PROVIDER="OPENAI"
        OPENAI_API_KEY="your_openai_key"
        ```
        
        **To control logging verbosity:**
        ```dotenv
        LOG_LEVEL=INFO  # Default, options: DEBUG, INFO, WARNING, ERROR, CRITICAL
        ```

## 🚀 Usage

Navigate to the root directory (`azure-documenter-tool/`) in your terminal.

*   **Run in Audit Mode (Default):**
    ```bash
    python azure_documenter/main.py
    ```
    You will be prompted to select which subscriptions to audit.

*   **Run for All Subscriptions Without Interactive Selection:**
    ```bash
    python azure_documenter/main.py --all-subscriptions
    ```

*   **Run in Design Mode (Requires LLM configured in `.env`):**
    ```bash
    python azure_documenter/main.py --mode Design
    ```

*   **Compare Two Previous Audit Runs:**
    ```bash
    python azure_documenter/main.py --compare TIMESTAMP1 TIMESTAMP2
    ```
    This will:
    1. Load the audit data from runs with timestamps TIMESTAMP1 and TIMESTAMP2
    2. Analyze changes between them
    3. Generate delta reports (Markdown and HTML) highlighting added, removed, and modified resources

Outputs will be generated in the `azure_documenter/outputs/` directory, organized into `reports/`, `diagrams/`, and `data/`.

## 📋 Typical Workflow

1. **Initial Audit:** Run the tool to document the current state of your Azure infrastructure:
   ```bash
   python azure_documenter/main.py
   ```
   Select the subscriptions you want to audit when prompted. This will generate timestamped reports and save the raw data.

2. **Make Changes:** Implement fixes or changes to your Azure environment.

3. **Re-run Audit:** Run the tool again to generate a new audit with a new timestamp.
   ```bash
   python azure_documenter/main.py
   ```

4. **Compare Audits:** Compare the initial and latest audits to identify changes:
   ```bash
   python azure_documenter/main.py --compare 20250406_123456 20250407_123456
   ```
   Replace the timestamps with those from your specific audit runs.

5. **Review Delta Report:** Examine the generated delta report to confirm your changes were applied correctly.

## 🔧 Configuration

*   **Subscription Selection:**
    * By default, the tool will prompt you to interactively select which subscriptions to audit
    * Use the `--all-subscriptions` flag to audit all accessible subscriptions without prompting
    
*   **LLM API Keys:** 
    * Configure in the `.env` file based on the `.env.template`
    * The tool prioritizes the provider specified in `LLM_PROVIDER`
    * If no keys are found, LLM features are disabled even in Design mode

*   **Logging:**
    Control verbosity through the `LOG_LEVEL` environment variable in the `.env` file:
    ```
    LOG_LEVEL=CRITICAL  # Only critical errors
    LOG_LEVEL=ERROR     # Errors and critical errors
    LOG_LEVEL=WARNING   # Warnings, errors, and critical errors (good for quieter runs)
    LOG_LEVEL=INFO      # Default - includes informational messages
    LOG_LEVEL=DEBUG     # Most verbose - all messages including Azure SDK details
    ```

## 📚 Key Report Sections

The generated report includes detailed information organized into these sections:

1. **Tenant Summary**
   * Overview of discovered subscriptions
   * Tenant-wide network diagram showing VNet peerings across subscriptions
   
2. **Tenant-Wide Security Information**
   * Global Administrators and Privileged Accounts (Owner, Contributor, etc.)
   * Non-Compliant Policy States across all subscriptions
   * Security Advisories with impact ratings
   
3. **Per-Subscription Details**
   * Resource inventory tables
   * Network diagrams and component details
   * Security posture information
   * Cost data
   * Governance status

## 📝 Future Enhancements

*   Enhanced Azure AD integration for better user/principal resolution
*   Tenant-wide resource interconnectivity diagrams (e.g., App -> Function -> Storage)
*   Interactive HTML reports with filtering and sorting capabilities
*   More detailed resource configuration information
*   Built-in policy compliance evaluation templates
*   Automatic scheduled runs and change detection
*   Direct integration with documentation platforms (e.g., SharePoint, Confluence) 