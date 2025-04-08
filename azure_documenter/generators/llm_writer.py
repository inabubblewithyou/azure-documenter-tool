import logging
import os
from openai import AzureOpenAI, OpenAI # Import both

# Import config variables
from config import (
    LLM_PROVIDER,
    AZURE_OPENAI_API_KEY,
    AZURE_OPENAI_ENDPOINT,
    AZURE_OPENAI_DEPLOYMENT,
    OPENAI_API_KEY
)

client = None
if LLM_PROVIDER == "AZURE_OPENAI":
    try:
        client = AzureOpenAI(
            api_key=AZURE_OPENAI_API_KEY,
            azure_endpoint=AZURE_OPENAI_ENDPOINT,
            api_version="2023-05-15",
        )
        # Verify deployment exists? API call might be needed.
        logging.info(f"Azure OpenAI client initialized for deployment '{AZURE_OPENAI_DEPLOYMENT}'.")
    except Exception as e:
        logging.error(f"Failed to initialize Azure OpenAI client: {e}")
        LLM_PROVIDER = None # Disable LLM if client fails
elif LLM_PROVIDER == "OPENAI":
    try:
        client = OpenAI(api_key=OPENAI_API_KEY)
        # Verify connection? Maybe list models?
        # models = client.models.list()
        logging.info("OpenAI client initialized.")
    except Exception as e:
        logging.error(f"Failed to initialize OpenAI client: {e}")
        LLM_PROVIDER = None # Disable LLM if client fails

def generate_llm_summary(prompt, max_tokens=1000):
    """Generates a summary using the configured LLM provider."""
    if not client or not LLM_PROVIDER:
        logging.warning("LLM client not available or not configured. Skipping generation.")
        return "_LLM summary generation skipped (client not configured)._"

    logging.info(f"Sending prompt to {LLM_PROVIDER}...")
    try:
        if LLM_PROVIDER == "AZURE_OPENAI":
            response = client.chat.completions.create(
                model=AZURE_OPENAI_DEPLOYMENT,
                messages=[
                    {"role": "system", "content": "You are an expert cloud architect summarizing Azure infrastructure."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=0.3, # Lower temperature for more factual summaries
            )
        elif LLM_PROVIDER == "OPENAI":
             response = client.chat.completions.create(
                # Use a suitable model, e.g., gpt-3.5-turbo or gpt-4 if available
                model="gpt-3.5-turbo", # Make this configurable?
                messages=[
                    {"role": "system", "content": "You are an expert cloud architect summarizing Azure infrastructure."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=0.3,
            )

        summary = response.choices[0].message.content.strip()
        logging.info(f"Successfully received summary from {LLM_PROVIDER}.")
        return summary

    except Exception as e:
        logging.error(f"Error during LLM ({LLM_PROVIDER}) call: {e}")
        return f"_LLM summary generation failed: {e}_"

def generate_subscription_narrative(subscription_data):
    """Creates a prompt and generates a narrative summary for a subscription."""
    sub_info = subscription_data.get("subscription_info", {})
    sub_name = sub_info.get("display_name", sub_info.get("id"))
    resources = subscription_data.get("resources", [])
    networking = subscription_data.get("networking", {})
    costs = subscription_data.get("costs", {})
    governance = subscription_data.get("governance", {})

    # Basic prompt engineering - provide key counts and details
    prompt = f"Generate a concise executive summary (2-3 paragraphs) for the Azure subscription '{sub_name}'. "
    prompt += f"It contains {len(resources)} resources. "
    prompt += f"Networking includes {len(networking.get('vnets', []))} VNets, {len(networking.get('subnets', []))} subnets, and {len(networking.get('peerings', []))} peerings. "
    cost_str = "Cost data not available." 
    if costs.get('mtd_actual_cost') is not None:
        cost_str = f"Month-to-date cost is {costs['mtd_actual_cost']:.2f} {costs.get('currency', '')} ."
    prompt += cost_str
    prompt += f" There are {len(governance.get('advisor_recommendations', []))} Advisor recommendations. "
    prompt += "Highlight the main components and purpose if discernible. Mention any significant cost or governance points."

    # Add more details to the prompt for better summaries? (e.g., key resource types)

    return generate_llm_summary(prompt)

def enhance_report_with_llm(all_data, markdown_report_path):
    """Adds LLM-generated summaries to the Markdown report (Design Mode)."""
    if not LLM_PROVIDER:
        logging.warning("LLM Provider not configured, cannot enhance report.")
        return False # Indicate no enhancement was done

    logging.info(f"Enhancing report '{markdown_report_path}' with LLM summaries...")
    enhanced_content = []
    in_subscription_section = False
    current_sub_id = None

    try:
        with open(markdown_report_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for line in lines:
            enhanced_content.append(line) # Keep the original line

            # Detect start of a subscription section
            if line.startswith("## Subscription:"):
                in_subscription_section = True
                # Extract sub_id (assuming format `Subscription: Name (`id`)`)
                try:
                    current_sub_id = line.split("`")[1]
                except IndexError:
                    logging.warning(f"Could not parse subscription ID from line: {line.strip()}")
                    current_sub_id = None
                    in_subscription_section = False # Cannot proceed without ID

            # Inject LLM summary after the subscription header
            if in_subscription_section and current_sub_id and line.strip().endswith(f"(`{current_sub_id}`)"):
                if current_sub_id in all_data and "error" not in all_data[current_sub_id]:
                    logging.info(f"Generating LLM narrative for subscription {current_sub_id}...")
                    narrative = generate_subscription_narrative(all_data[current_sub_id])
                    enhanced_content.append("\n**AI-Generated Summary:**\n")
                    enhanced_content.append(f"> {narrative.replace('\n', '\n> ')}\n\n") # Format as blockquote
                else:
                    logging.info(f"Skipping LLM narrative for {current_sub_id} due to previous error or missing data.")
                    enhanced_content.append("\n_[AI-Generated Summary Skipped]_\n\n")
                # Reset flags after injection
                in_subscription_section = False
                current_sub_id = None

        # Overwrite the original markdown file with enhanced content
        with open(markdown_report_path, 'w', encoding='utf-8') as f:
            f.writelines(enhanced_content)

        logging.info(f"Successfully enhanced Markdown report with LLM summaries: {markdown_report_path}")
        return True

    except FileNotFoundError:
        logging.error(f"Markdown file not found for LLM enhancement: {markdown_report_path}")
        return False
    except Exception as e:
        logging.error(f"Failed to enhance report with LLM summaries: {e}")
        return False 