import os
import logging
import markdown # Python Markdown library
import re
import datetime # Added for date generation
import time # For timezone formatting
import html # For decoding potential entities
import uuid # To generate unique placeholders

# Global flag that can be set by the main module
SILENT_MODE = False

# Regex to find Markdown tables (Simpler version)
MD_TABLE_REGEX = re.compile(
    r"^(?P<header>\|.*\|)\s*$\n"           # Header row: starts/ends with |, optional trailing space
    r"^(?P<separator>\|[:\-\|\s]+?\|)\s*$\n"  # Separator row: starts/ends with |, contains :,-,|,space, optional trailing space
    r"(?P<data>(?:^\|.*\|$\n)+)"        # Data rows: one or more lines starting/ending with |
    , re.MULTILINE
)

def _parse_md_row(row_str):
    """Parses a single Markdown table row string into a list of cells."""
    row_str = row_str.strip() # Strip leading/trailing whitespace from the whole line first
    if not row_str or not row_str.startswith('|') or not row_str.endswith('|'):
        return []
    # Split by pipe, remove empty strings from start/end, strip whitespace
    cells = [cell.strip() for cell in row_str[1:-1].split('|')]
    # Decode HTML entities that might be present (like &#124;)
    cells = [html.unescape(cell) for cell in cells]
    return cells

def _preprocess_and_extract_tables(markdown_content):
    """Finds MD tables in raw Markdown, converts to HTML, replaces with placeholders."""
    
    extracted_tables = {} # {placeholder: html_table_string}
    placeholder_count = 0

    def replace_with_placeholder(match):
        nonlocal placeholder_count
        original_md_table_text = match.group(0) # The entire matched Markdown table
        # Use named groups for clarity
        header_line = match.group("header").strip()
        # separator_line = match.group("separator").strip() # Separator not needed for HTML gen
        data_lines_block = match.group("data").strip()

        # Debug: Log the matched block
        logging.debug(f"Regex matched potential MD table block:\n---\n{original_md_table_text}\n---")

        headers = _parse_md_row(header_line)
        if not headers:
            logging.warning(f"Failed to parse MD table header during preprocessing: {header_line}")
            return original_md_table_text # Return original text if header parsing fails

        # Generate HTML table
        html_table = ['<div class="table-container">', # Add wrapper for styling
                      '<table>', '<thead>', '<tr>']
        for header in headers:
            header_text = re.sub(r'`(.+?)`', r'\1', header) # Remove backticks
            html_table.append(f'<th>{html.escape(header_text)}</th>') # Escape header text
        html_table.append('</tr></thead>')

        html_table.append('<tbody>')
        data_rows = data_lines_block.split('\n')
        for row_str in data_rows:
            if not row_str.strip(): continue # Skip empty lines
            cells = _parse_md_row(row_str)
            if len(cells) == len(headers): # Ensure cell count matches header count
                html_table.append('<tr>')
                for cell in cells:
                    # Handle code blocks and ensure basic HTML safety
                    cell_content = html.escape(cell) # Escape potential HTML in cell content first
                    cell_content = re.sub(r'`(.+?)`', r'<code>\1</code>', cell_content) # Then apply code tag
                    html_table.append(f'<td>{cell_content}</td>')
                html_table.append('</tr>')
            else:
                if not all(c == '' or re.match(r'^[:\-]+$', c) for c in cells):
                    logging.warning(f"MD table row cell count mismatch during preprocessing. Header: {len(headers)}, Row: {len(cells)}. Row content: '{row_str}'")
        html_table.append('</tbody></table></div>')
        html_table_string = '\n'.join(html_table)

        # Generate unique placeholder
        placeholder_count += 1
        placeholder = f"%%%HTML_TABLE_PLACEHOLDER_{uuid.uuid4().hex[:8]}%%%"
        extracted_tables[placeholder] = html_table_string
        
        logging.debug(f"Preprocessed MD table, replaced with placeholder: {placeholder}")
        # Return the placeholder, ensuring it's on its own line for clarity
        return "\n" + placeholder + "\n"

    # Replace all found Markdown tables with placeholders
    markdown_with_placeholders = MD_TABLE_REGEX.sub(replace_with_placeholder, markdown_content)
    
    if placeholder_count > 0:
        logging.info(f"Preprocessed {placeholder_count} Markdown table(s) into HTML placeholders.")
    else:
        logging.info("No Markdown tables found during preprocessing step.")
        
    return markdown_with_placeholders, extracted_tables

# Enhanced HTML template with placeholders for dynamic header content
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_title}</title>
    <style>
        /* Base variables */
        :root {
            --primary-color: #0078d4;
            --primary-dark: #106ebe;
            --primary-light: #e6f3ff;
            --accent-color: #2b88d8;
            --background-color: #f9f9f9;
            --sidebar-bg: #ffffff;
            --text-color: #333333;
            --text-light: #666666;
            --border-color: #e0e0e0;
            --table-header-bg: #f2f9ff;
            --table-alt-row: #f9f9f9;
            --table-hover: #f0f7ff;
            --code-bg: #f5f5f5;
            --section-header-bg: #f3f8fc;
            --success-color: #107c10;
            --warning-color: #d83b01;
            --info-color: #0078d4;
            --danger-color: #d13438;
            --sidebar-width: 280px;
            --header-height: 60px;
            --box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }

        /* Reset and base styles */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--background-color);
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }

        /* Main layout */
        .header {
            background-color: var(--primary-color);
            color: white;
            height: var(--header-height);
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 100;
            display: flex;
            align-items: center;
            padding: 0 20px;
            box-shadow: var(--box-shadow);
        }
        
        .header-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
            width: 100%;
        }
        
        .header-title {
            font-size: 20px;
            font-weight: 600;
        }
        
        .header-meta {
            font-size: 14px;
            opacity: 0.9;
        }
        
        .main-container {
            display: flex;
            margin-top: var(--header-height);
            min-height: calc(100vh - var(--header-height));
        }
        
        .sidebar {
            width: var(--sidebar-width);
            background-color: var(--sidebar-bg);
            border-right: 1px solid var(--border-color);
            position: fixed;
            top: var(--header-height);
            bottom: 0;
            left: 0;
            overflow-y: auto;
            padding: 20px 0;
            z-index: 90;
            box-shadow: 1px 0 5px rgba(0, 0, 0, 0.05);
        }
        
        .content {
            flex: 1;
            margin-left: var(--sidebar-width);
            padding: 30px;
            max-width: 100%;
        }
        
        /* Sidebar navigation */
        .nav-title {
            font-size: 16px;
            font-weight: 600;
            color: var(--primary-color);
            padding: 0 20px 10px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 15px;
        }
        
        .nav-list {
            list-style-type: none;
        }
        
        .nav-list li {
            margin-bottom: 2px;
        }
        
        .nav-list a {
            display: block;
            padding: 8px 20px;
            color: var(--text-color);
            text-decoration: none;
            border-left: 3px solid transparent;
            transition: all 0.2s ease;
        }
        
        .nav-list a:hover {
            background-color: var(--primary-light);
            border-left-color: var(--primary-color);
        }
        
        .nav-list a.active {
            background-color: var(--primary-light);
            border-left-color: var(--primary-color);
            font-weight: 500;
        }
        
        .nav-list .nav-h2 { padding-left: 30px; font-size: 14px; }
        .nav-list .nav-h3 { padding-left: 45px; font-size: 13px; }
        .nav-list .nav-h4 { padding-left: 60px; font-size: 12px; }
        
        /* Typography */
        h1, h2, h3, h4, h5, h6 {
            margin-top: 1.2em;
            margin-bottom: 0.6em;
            color: #2c3e50;
            line-height: 1.3;
            scroll-margin-top: calc(var(--header-height) + 20px); /* Offset for fixed header */
        }
        
        h1 { 
            font-size: 2em; 
            border-bottom: 2px solid #3498db;
            padding-bottom: 0.4em;
            margin-bottom: 20px;
        }
        
        h2 { 
            font-size: 1.6em; 
            border-bottom: 1px solid #ecf0f1;
            padding-bottom: 0.3em;
            margin-top: 2em;
        }
        
        h3 { font-size: 1.3em; color: #34495e; }
        h4 { font-size: 1.1em; color: #7f8c8d; }
        
        p {
            margin-bottom: 1em;
        }
        
        /* Links */
        a {
            color: var(--primary-color);
            text-decoration: none;
        }
        
        a:hover {
            text-decoration: underline;
        }
        
        /* Content sections */
        /* Removed .section and .section-title rules */
        
        /* Tables */
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 1.5em 0;
            background-color: white;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            table-layout: auto;
            min-width: 600px; /* Ensure tables have a minimum width */
        }
        
        .table-container {
            overflow-x: auto;
            margin: 1.5em 0;
            max-width: 100%;
            position: relative;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        .table-container::after {
            content: "➡️ Scroll for more";
            position: absolute;
            bottom: 5px;
            right: 5px;
            font-size: 11px;
            color: var(--text-light);
            background: rgba(255, 255, 255, 0.7);
            padding: 2px 5px;
            border-radius: 3px;
            display: none;
        }
        
        .table-container.scrollable::after {
            display: block;
        }
        
        th {
            background-color: var(--table-header-bg);
            font-weight: 600;
            text-align: left;
            padding: 12px 15px;
            border-bottom: 2px solid var(--border-color);
            color: var(--primary-dark);
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        td {
            padding: 10px 15px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
            word-break: normal;
            max-width: 400px; /* Wider cells */
        }
        
        /* For long content, enable wrapping */
        td code {
            white-space: pre-wrap;
            word-break: break-word;
            max-width: 100%;
            display: inline-block;
        }
        
        tr:nth-child(even) {
            background-color: var(--table-alt-row);
        }
        
        tr:hover {
            background-color: var(--table-hover);
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        /* Lists */
        ul, ol {
            margin: 1em 0 1.5em 2em;
        }
        
        li {
            margin-bottom: 0.5em;
        }
        
        /* Code */
        code {
            font-family: 'Consolas', 'Monaco', monospace;
            background-color: var(--code-bg);
            padding: 2px 4px;
            border-radius: 3px;
            font-size: 0.9em;
            color: #d63384;
        }
        
        pre {
            background-color: var(--code-bg);
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            margin: 1.5em 0;
            border: 1px solid var(--border-color);
        }
        
        pre code {
            padding: 0;
            background: none;
            color: var(--text-color);
        }
        
        /* Images */
        img {
            max-width: 100%;
            height: auto;
            display: block;
            margin: 1.5em auto;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        /* Network diagrams */
        .network-diagram {
            text-align: center;
            margin: 30px 0;
        }
        
        .network-diagram img {
            max-width: 100%;
            max-height: 500px;
            margin: 10px auto;
        }
        
        .network-diagram-caption {
            font-style: italic;
            color: var(--text-light);
            margin-top: 8px;
            font-size: 14px;
        }
        
        /* Cards for resources */
        .resource-card {
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 20px;
            background-color: white;
        }
        
        .resource-card-header {
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
        }
        
        .resource-card-title {
            font-weight: 600;
            color: var(--primary-color);
        }
        
        .resource-card-body {
            display: flex;
            flex-wrap: wrap;
        }
        
        .resource-card-property {
            flex: 1 0 50%;
            padding: 4px 0;
            display: flex;
        }
        
        .resource-card-property-name {
            font-weight: 500;
            width: 40%;
            color: var(--text-light);
        }
        
        .resource-card-property-value {
            width: 60%;
        }
        
        /* Status indicators */
        .status {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: 500;
        }
        
        .status-success {
            background-color: rgba(16, 124, 16, 0.15);
            color: var(--success-color);
        }
        
        .status-warning {
            background-color: rgba(216, 59, 1, 0.15);
            color: var(--warning-color);
        }
        
        .status-info {
            background-color: rgba(0, 120, 212, 0.15);
            color: var(--info-color);
        }
        
        .status-danger {
            background-color: rgba(209, 52, 56, 0.15);
            color: var(--danger-color);
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 20px 0;
            margin-top: 40px;
            border-top: 1px solid var(--border-color);
            color: var(--text-light);
            font-size: 14px;
        }
        
        /* Utility classes */
        .text-center { text-align: center; }
        .text-right { text-align: right; }
        .font-bold { font-weight: bold; }
        .mt-0 { margin-top: 0; }
        .mb-0 { margin-bottom: 0; }
        
        /* Responsive adjustments */
        @media (max-width: 1024px) {
            :root {
                --sidebar-width: 240px;
            }
        }
        
        @media (max-width: 768px) {
            .main-container {
                flex-direction: column;
            }
            
            .sidebar {
                width: 100%;
                position: static;
                height: auto;
                border-right: none;
                border-bottom: 1px solid var(--border-color);
                padding: 10px 0;
            }
            
            .content {
                margin-left: 0;
                padding: 20px;
            }
            
            .nav-list a {
                padding: 6px 15px;
            }
            
            .header {
                padding: 0 15px;
            }
            
            .header-title {
                font-size: 18px;
            }
            
            .header-meta {
                display: none;
            }
            
            :root {
                --header-height: 50px;
            }
            
            h1 { font-size: 1.8em; }
            h2 { font-size: 1.4em; }
            h3 { font-size: 1.2em; }
            
            .section {
                padding: 15px;
            }
            
            .resource-card-property {
                flex: 1 0 100%;
            }
        }
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            // Update header meta text directly
            const headerMeta = document.querySelector('.header-meta');
            if (headerMeta) {
                // Text is already set by Python template replacement
                // We can add a title attribute for hover if needed, but keep full text visible
                const fullText = headerMeta.textContent.trim();
                headerMeta.title = fullText; // Add hover title
                // No need to truncate if CSS handles overflow or wrapping
            }
            
            // Process headings for navigation and anchor links
            const headings = document.querySelectorAll('h1, h2, h3, h4');
            const navList = document.createElement('ul');
            navList.className = 'nav-list';
            
            headings.forEach((heading, index) => {
                // Skip the first heading (document title)
                if (index === 0) return;
                
                // Add ID to heading if it doesn't have one
                if (!heading.id) {
                    const id = heading.textContent
                        .toLowerCase()
                        .replace(/[^a-z0-9 -]/g, '')
                        .replace(/\\s+/g, '-')
                        .replace(/-+/g, '-');
                    heading.id = `section-${id}`; // Use a simpler prefix
                }
                
                // Create navigation item
                const li = document.createElement('li');
                const a = document.createElement('a');
                a.href = `#${heading.id}`;
                a.textContent = heading.textContent;
                a.className = `nav-${heading.tagName.toLowerCase()}`;
                li.appendChild(a);
                navList.appendChild(li);
                
                // Add click event to update active state
                a.addEventListener('click', (e) => {
                    document.querySelectorAll('.nav-list a').forEach(link => {
                        link.classList.remove('active');
                    });
                    a.classList.add('active');
                    // Don't prevent default scroll, just update active state
                });
            });
            
            // Add the navigation to the sidebar
            const sidebar = document.getElementById('sidebar');
            if (sidebar) {
                sidebar.appendChild(navList);
            }
            
            // Enhance tables with wrapper for responsiveness
            document.querySelectorAll('table').forEach(table => {
                // Create wrapper if it doesn't exist already
                if (!table.parentNode.classList.contains('table-container')) {
                    const wrapper = document.createElement('div');
                    wrapper.className = 'table-container';
                    table.parentNode.insertBefore(wrapper, table);
                    wrapper.appendChild(table);
                    
                    // Check if table is wider than container
                    setTimeout(() => {
                        if (table.offsetWidth > wrapper.offsetWidth) {
                            wrapper.classList.add('scrollable');
                        }
                    }, 100);
                }
            });
            
            // Enhance images - especially network diagrams
            document.querySelectorAll('img').forEach(img => {
                const alt = img.alt || '';
                if (alt.toLowerCase().includes('diagram') || 
                    alt.toLowerCase().includes('topology') || 
                    img.src.toLowerCase().includes('diagram') || 
                    img.src.toLowerCase().includes('topology')) {
                    
                    // Only wrap if not already wrapped
                    if (!img.parentNode.classList.contains('network-diagram')) {
                        const wrapper = document.createElement('div');
                        wrapper.className = 'network-diagram';
                        img.parentNode.insertBefore(wrapper, img);
                        wrapper.appendChild(img);
                        
                        const caption = document.createElement('div');
                        caption.className = 'network-diagram-caption';
                        caption.textContent = alt || 'Network Diagram';
                        wrapper.appendChild(caption);
                    }
                }
            });
            
            // Format code blocks in tables for better readability
            document.querySelectorAll('td code').forEach(codeElement => {
                if (codeElement.textContent.length > 40) {
                    codeElement.title = codeElement.textContent; // Show full content on hover
                }
            });
        });
        
        // Function to highlight active section on scroll
        window.addEventListener('scroll', () => {
            const scrollPosition = window.scrollY;
            
            // Find all headings
            const headings = document.querySelectorAll('h1, h2, h3');
            
            // Determine which heading is currently visible
            let currentHeading = null;
            
            // Iterate in reverse order to handle nested headings correctly
            for (let i = headings.length - 1; i >= 0; i--) {
                const heading = headings[i];
                if (heading.offsetTop <= scrollPosition + 100) {
                    currentHeading = heading;
                    break;
                }
            }
            
            if (currentHeading) {
                // Remove active class from all links
                document.querySelectorAll('.nav-list a').forEach(link => {
                    link.classList.remove('active');
                });
                
                // Add active class to corresponding nav link
                const targetLink = document.querySelector(`.nav-list a[href="#${currentHeading.id}"]`);
                if (targetLink) {
                    targetLink.classList.add('active');
                }
            }
        });
    </script>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <div class="header-title">{{HEADER_TITLE_PLACEHOLDER}}</div>
            <div class="header-meta">{{GENERATED_DATE_PLACEHOLDER}}</div>
        </div>
    </header>

    <div class="main-container">
        <nav class="sidebar" id="sidebar">
            <div class="nav-title">Table of Contents</div>
            <!-- Navigation will be populated by JavaScript -->
        </nav>
        
        <main class="content">
            {{CONTENT_PLACEHOLDER}}
            
            <footer class="footer">
                <p>This document was automatically generated by the Azure Documenter Tool based on the discovered Azure environment state at the time of the scan.</p>
            </footer>
        </main>
    </div>
</body>
</html>
"""

def export_markdown_to_html(markdown_filepath, output_report_dir, tenant_display_name, tenant_default_domain, document_version, timestamp_str, silent_mode=False):
    """Converts a Markdown file to a timestamped static HTML file with enhanced styling.

    Args:
        markdown_filepath (str): Path to the input Markdown file.
        output_report_dir (str): Directory to save the output HTML file.
        tenant_display_name (str): The fetched display name of the tenant.
        tenant_default_domain (str): The fetched default domain of the tenant.
        document_version (float): The version number for this document run.
        timestamp_str (str): Timestamp string (YYYYMMDD_HHMMSS) for the run.
        silent_mode (bool): Whether to suppress console output.
    """
    # Set the global SILENT_MODE flag for this module
    global SILENT_MODE
    SILENT_MODE = silent_mode

    # Construct timestamped HTML filename
    time_suffix = f"_{timestamp_str}" if timestamp_str else ""
    markdown_basename = os.path.basename(markdown_filepath)
    
    # Create a clean tenant name for the filename
    clean_tenant_name = tenant_display_name.replace(" ", "_").replace("/", "_").replace("\\", "_")
    
    # Extract version from markdown filename if present, otherwise use provided version
    version_match = re.search(r"_v(\d+\.\d+)\.md$", markdown_basename)
    version_str = version_match.group(1) if version_match else f"{document_version:.1f}"
    
    # Construct HTML filename with the same pattern as markdown
    html_filename = f"Azure_Design_Document_{clean_tenant_name}_{timestamp_str}_v{version_str}.html"
    html_filepath = os.path.join(output_report_dir, html_filename)

    try:
        with open(markdown_filepath, "r", encoding='utf-8') as f_md:
            markdown_content = f_md.read()

        # Step 1: Preprocess Markdown to extract tables and replace with placeholders
        markdown_with_placeholders, extracted_tables = _preprocess_and_extract_tables(markdown_content)

        # Step 2: Run standard Markdown conversion on the content with placeholders
        # Re-enable 'tables' extension - it won't hurt, though it won't match placeholders
        intermediate_html = markdown.markdown(markdown_with_placeholders, extensions=[
            'markdown.extensions.tables',
            'markdown.extensions.fenced_code', 
            'markdown.extensions.toc',
            'markdown.extensions.nl2br'
            ])

        # Debugging: Log the intermediate HTML before placeholder replacement
        # logging.debug(f"--- Intermediate HTML before placeholder replacement ---")
        # logging.debug(intermediate_html[:1000] + ("..." if len(intermediate_html) > 1000 else "")) 
        # logging.debug(f"--------------------------------------------------")

        # Step 3: Replace placeholders with the generated HTML tables
        html_content = intermediate_html
        if extracted_tables:
            for placeholder, table_html in extracted_tables.items():
                # Ensure placeholder exists before replacing to avoid errors if regex was imperfect
                if placeholder in html_content:
                    html_content = html_content.replace(placeholder, table_html)
                    logging.debug(f"Replaced table placeholder {placeholder}")
                else:
                    logging.warning(f"Table placeholder {placeholder} not found in intermediate HTML. Skipping replacement.")
            # Final cleanup of any potential <p> tags around the inserted tables
            html_content = re.sub(r'<p>\s*(<div class="table-container">.*?</div>)\s*</p>', r'\1', html_content, flags=re.DOTALL)

        # --- Use passed-in tenant name --- 
        # Use the display name directly
        report_tenant_name = tenant_display_name if tenant_display_name and "(Tenant ID)" not in tenant_display_name else "Azure Environment"
        if not report_tenant_name: report_tenant_name = "Azure Environment" # Final fallback
             
        # --- Prepare Header Data --- 
        # Use the pure timestamp_str for the run ID
        page_title = f"Azure Design Audit for {report_tenant_name} ({timestamp_str})"
        header_title = f"Azure Design Audit for {report_tenant_name} - Run: {timestamp_str}"
        # Include time in the visible generated date
        generated_date = f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        # --- Populate HTML Template --- 
        final_html = HTML_TEMPLATE.replace("{{PAGE_TITLE_PLACEHOLDER}}", page_title)
        final_html = final_html.replace("{{HEADER_TITLE_PLACEHOLDER}}", header_title)
        final_html = final_html.replace("{{GENERATED_DATE_PLACEHOLDER}}", generated_date)
        final_html = final_html.replace("{{CONTENT_PLACEHOLDER}}", html_content)

        # Write the final HTML file
        with open(html_filepath, "w", encoding='utf-8') as f_html:
            f_html.write(final_html)

        if not SILENT_MODE:
            print(f"Successfully exported HTML report to: {html_filepath}")
        logging.info(f"Successfully exported HTML report to: {html_filepath}")

    except FileNotFoundError:
        if not SILENT_MODE:
            print(f"!!! Error: Markdown file not found at {markdown_filepath}")
        logging.error(f"Markdown file not found at {markdown_filepath} for HTML export")
    except Exception as e:
        if not SILENT_MODE:
            print(f"!!! Error exporting Markdown to HTML: {e}")
        logging.error(f"Error exporting Markdown to HTML ({markdown_filepath}): {e}", exc_info=True) 