# Azure Documenter Tool

## Purpose

A powerful automated tool that audits and documents Azure infrastructure across multiple subscriptions within a tenant. It automatically discovers, analyzes, and describes Azure resources, networks, security posture, costs, and governance status, generating both detailed audit reports and comprehensive design documents.

## Core Features

### Data Collection and Analysis
* **Resource Management**
  - Comprehensive resource inventory across subscriptions
  - Resource group naming pattern analysis
  - Resource lifecycle management tracking
  - Tag usage analysis and recommendations

* **Identity and Access Management**
  - Entra ID tenant analysis
  - RBAC implementation review
  - Privileged access management status
  - Managed identity usage patterns
  - Service principal analysis
  - Custom role definitions

* **Network Architecture**
  - VNet and subnet configuration
  - Peering relationships
  - Gateway configurations
  - Firewall implementations
  - DDoS protection status
  - Private endpoints
  - DNS architecture
  - Load balancer configurations
  - Network security groups
  - Service endpoints
  - Private Link services

* **Compute and Applications**
  - Virtual machine inventory and analysis
  - App Service configurations
  - Serverless component usage
  - Container service implementations
  - Auto-scaling configurations
  - Availability patterns
  - Runtime environments

* **Data Platform**
  - Storage account configurations
  - Database services (SQL, Cosmos DB)
  - Data Lake implementations
  - Analytics services
  - Backup storage analysis
  - Data classification
  - Data sovereignty assessment

* **Security and Compliance**
  - Microsoft Defender for Cloud status
  - Microsoft Sentinel implementation
  - Key Vault configurations
  - Encryption strategies
  - Policy compliance status
  - Security recommendations

* **Cost Management**
  - Subscription cost analysis
  - Resource type cost distribution
  - Cost allocation by resource group
  - Cost optimization recommendations
  - Month-to-date and forecast costs
  - Service-specific cost breakdowns

* **Monitoring and Operations**
  - Log Analytics workspace analysis
  - Monitoring agent status
  - Diagnostic settings
  - Backup configurations
  - Site Recovery status

### Report Generation
* **Design Document**
  - Comprehensive architecture assessment
  - Best practice recommendations
  - Automatically versioned
  - Executive summary
  - Detailed technical appendices
  - Optional AI-enhanced analysis with `--llm` flag

* **Audit Report**
  - Detailed technical findings
  - Resource inventories
  - Configuration details
  - Compliance status

* **Network Diagrams**
  - Tenant-wide network topology
  - Subscription-specific network diagrams
  - Hub-spoke relationship visualization

* **Output Formats**
  - Markdown reports
  - Static HTML with navigation
  - Raw JSON data
  - Network diagrams (PNG)

### Additional Features
* Interactive subscription selection
* Silent mode for automation
* Delta comparison between audits
* Version tracking
* Detailed logging
* Cross-subscription analysis

## Requirements

* Python 3.8+
* Azure Authentication (CLI or Service Principal)
* Required Azure RBAC Permissions:
  - Reader role at subscription or management group level
  - Additional permissions for enhanced features (e.g., Graph API)
* Graphviz for diagram generation
* Python packages from requirements.txt

## Installation

1. Clone the Repository:
   ```bash
   git clone <repository_url>
   cd azure-documenter-tool
   ```

2. Install Python Dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   # or .venv\Scripts\activate.bat  # Windows CMD
   # or .venv\Scripts\Activate.ps1  # Windows PowerShell
   pip install -r azure_documenter/requirements.txt
   ```

3. Install Graphviz from https://graphviz.org/download/

4. Authenticate to Azure:
   ```bash
   az login
   # Optional: Set default subscription
   az account set --subscription <subscription-id>
   ```

## Usage

Basic Usage:
```bash
# Default audit mode
python azure_documenter/main.py

# Design document mode
python azure_documenter/main.py --mode Design

# Design document with AI-enhanced analysis
python azure_documenter/main.py --mode Design --llm

# All subscriptions
python azure_documenter/main.py --all-subscriptions

# Silent mode for automation
python azure_documenter/main.py --mode Design --all-subscriptions --silent

# Compare two audits
python azure_documenter/main.py --compare TIMESTAMP1 TIMESTAMP2
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