import os
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ==== Azure Authentication ====
# Azure authentication defaults to DefaultAzureCredential
# which tries multiple authentication methods

# ==== Output Settings ====
# CSV export settings
CSV_EXPORT_ENABLED = True

# ==== LLM Integration ====
# Choose your LLM provider (if any)
# Options: "OPENAI", "AZURE_OPENAI", None
LLM_PROVIDER = os.getenv("LLM_PROVIDER")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT")

# ==== Logging Configuration ====
# Default log level can be overridden by environment variable
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Application logger
APP_LOGGER = logging.getLogger('azure_documenter')

# Configure logging based on environment variable
def configure_logging():
    """Configure logging levels based on environment variables"""
    # Set the application logger level based on environment variable
    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    APP_LOGGER.setLevel(level)
    
    # Return the configured logger
    return APP_LOGGER

# Validate LLM configuration
if LLM_PROVIDER == "AZURE_OPENAI" and AZURE_OPENAI_API_KEY and AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_DEPLOYMENT:
    APP_LOGGER.info("Using Azure OpenAI configuration.")
elif LLM_PROVIDER == "OPENAI" and OPENAI_API_KEY:
    APP_LOGGER.info("Using OpenAI configuration.")
else:
    APP_LOGGER.info("No LLM API Key found in environment variables (checked AZURE_OPENAI_API_KEY/ENDPOINT/DEPLOYMENT and OPENAI_API_KEY). LLM features will be disabled.")
    LLM_PROVIDER = None

# You can add other configurations here, e.g.,
# REPORT_TITLE = "My Company Azure Audit"
# DEFAULT_REGION_FILTER = ["eastus", "westus2"] 