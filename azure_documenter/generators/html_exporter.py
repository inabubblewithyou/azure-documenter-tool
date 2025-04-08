import os
import logging
import markdown # Python Markdown library

# Basic CSS for some styling (can be expanded or moved to a separate file)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{ font-family: sans-serif; line-height: 1.6; padding: 20px; max-width: 1000px; margin: auto; }}
        h1, h2, h3 {{ color: #333; border-bottom: 1px solid #ccc; padding-bottom: 5px; }}
        h1 {{ font-size: 2em; }}
        h2 {{ font-size: 1.5em; margin-top: 1.5em; }}
        h3 {{ font-size: 1.2em; margin-top: 1.2em; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 1em; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        code {{ background-color: #eee; padding: 2px 4px; border-radius: 3px; }}
        pre code {{ display: block; background-color: #eee; padding: 10px; border-radius: 3px; }}
        img {{ max-width: 100%; height: auto; display: block; margin-top: 10px; margin-bottom: 10px; border: 1px solid #ddd; }}
        /* Add more styles as needed */
    </style>
</head>
<body>
{body}
</body>
</html>
"""

def export_markdown_to_html(markdown_filepath, output_report_dir, timestamp_str):
    """Converts a Markdown file to a timestamped static HTML file."""

    # Construct timestamped HTML filename
    time_suffix = f"_{timestamp_str}" if timestamp_str else ""
    markdown_basename = os.path.basename(markdown_filepath)
    html_filename = os.path.splitext(markdown_basename)[0].replace("azure_audit_report", f"azure_audit_report{time_suffix}") + ".html"
    # Ensure we use the base report filename if no timestamp in md path
    if not timestamp_str and "_" in os.path.splitext(markdown_basename)[0]:
        # Handle case where timestamped MD file is passed without explicit timestamp
        html_filename = os.path.splitext(markdown_basename)[0] + ".html"
    elif not timestamp_str:
        # Default if no timestamp at all
         html_filename = "azure_audit_report.html"

    output_html_filepath = os.path.join(output_report_dir, html_filename)

    logging.info(f"Converting Markdown '{markdown_filepath}' to HTML '{output_html_filepath}'...")
    try:
        # Read the Markdown file
        with open(markdown_filepath, 'r', encoding='utf-8') as f:
            md_text = f.read()

        # Convert Markdown to HTML
        # Enable extensions like 'tables' for proper rendering
        html_body = markdown.markdown(md_text, extensions=['markdown.extensions.tables', 'markdown.extensions.fenced_code'])

        # Extract title (assuming first H1 is the title)
        title = f"Azure Audit Report ({timestamp_str})"
        try:
            first_h1_start = html_body.find("<h1>")
            if first_h1_start != -1:
                first_h1_end = html_body.find("</h1>", first_h1_start)
                title = html_body[first_h1_start + 4:first_h1_end]
        except Exception:
            pass # Use default title if extraction fails

        # Embed HTML body into the template
        final_html = HTML_TEMPLATE.format(title=title, body=html_body)

        # Write the HTML file
        os.makedirs(os.path.dirname(output_html_filepath), exist_ok=True)
        with open(output_html_filepath, 'w', encoding='utf-8') as f:
            f.write(final_html)

        logging.info(f"Successfully generated HTML report: {output_html_filepath}")
        return output_html_filepath # Return path to HTML file

    except FileNotFoundError:
        logging.error(f"Markdown file not found: {markdown_filepath}")
        return None
    except Exception as e:
        logging.error(f"Failed to convert Markdown to HTML: {e}")
        return None 