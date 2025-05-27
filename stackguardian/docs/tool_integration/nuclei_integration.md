# Nuclei Integration Research

This document outlines methods for programmatically interacting with ProjectDiscovery's Nuclei scanner.

## Key Interaction Methods

Nuclei is primarily a command-line interface (CLI) tool. Programmatic interaction typically involves wrapping CLI calls.

1.  **Wrapping CLI calls with Python's `subprocess` module**:
    *   **Description**: This is the most common and straightforward method to integrate Nuclei into a Python application.
    *   **Usage**:
        *   **Basic Scan**:
            ```python
            import subprocess
            import json

            target_url = "http://example.com"
            command = ["nuclei", "-u", target_url, "-json", "-o", "nuclei_output.json"]
            
            try:
                # Consider timeout for long scans
                result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=300) 
                # Process results from "nuclei_output.json" or stdout if not using -o
                # If '-jsonl' is used, each line in stdout is a JSON object
                
                # Example: Reading from file
                with open("nuclei_output.json", "r") as f:
                    for line in f: # Nuclei JSON output is often line-delimited
                        try:
                            scan_result = json.loads(line)
                            # Process scan_result
                        except json.JSONDecodeError:
                            print(f"Error decoding JSON line: {line.strip()}")
                            
            except subprocess.CalledProcessError as e:
                print(f"Nuclei scan failed: {e.stderr}")
            except subprocess.TimeoutExpired:
                print(f"Nuclei scan timed out for {target_url}")
            except FileNotFoundError:
                print("Nuclei command not found. Ensure it's installed and in PATH.")
            ```
        *   **Specifying Targets**:
            *   Single URL: `-u http://example.com`
            *   List of URLs from a file: `-list /path/to/urls.txt`
            *   Can also accept CIDR or ASN inputs.
        *   **Selecting Templates**:
            *   Default templates: Nuclei runs a curated set by default.
            *   Specific templates: `-t cves/2021/CVE-2021-44228.yaml,exposures/tokens/generic/unwanted-disclosures.yaml`
            *   Templates by directory: `-t cves/,technologies/`
            *   Templates by severity: `-s critical,high,medium` or `-severity critical,high`
            *   Templates by tags: `-tags cve,jira`
            *   Excluding templates: `-etags ssl` or `-exclude-templates templates/ssl/weak-ssl-ciphers.yaml`
            *   Automatic template selection based on detected technology (Wappalyzer): `-ats` (Automatic Template Selection)
        *   **Outputting Results**:
            *   JSON: `-json` (writes line-delimited JSON to stdout or file specified by `-o`)
            *   JSONL: `-jsonl` (alias for `-json`) is often preferred for easier parsing of multiple results.
            *   Markdown: `-markdown`
            *   SARIF: `-sarif`
            *   File output: `-o /path/to/outputfile.json`
        *   **Filtering Results**:
            *   Severity: `-s critical,high`
            *   Author: `-a "John Doe"`
        *   **Rate Limiting and Performance**:
            *   `-rl <rate>`: Rate limit requests per second.
            *   `-c <concurrency>`: Number of concurrent templates to run.
        *   **Updating Templates**:
            *   `nuclei -update-templates` (important to do regularly)
            *   `nuclei -ut`
        *   **Handling Exit Codes**:
            *   `0`: Successful execution, vulnerabilities may or may not have been found.
            *   `1`: Error during execution (e.g., template syntax error, target unreachable if not handled gracefully by a template).
            *   `2`: No templates loaded.
            *   Check Nuclei documentation for specific exit codes as they might evolve. It's important to check `stderr` for error messages.
    *   **Pros**:
        *   Leverages the full power and latest features of Nuclei.
        *   Community templates are constantly updated.
    *   **Cons**:
        *   Requires Nuclei to be installed on the system running the Python code (or in a container).
        *   Managing subprocesses, especially for long-running scans, can be complex (timeouts, resource management).
        *   Parsing output (even JSON) requires careful implementation.

## Summary for StackGuardian Integration

*   **Installation**: Nuclei must be installed in the execution environment where StackGuardian's Celery workers will run (e.g., a Docker container).
*   **Template Management**:
    *   A mechanism to regularly update Nuclei templates (`nuclei -update-templates`) should be considered.
    *   StackGuardian could potentially allow users to specify categories of templates (e.g., "cves", "misconfigurations", "all") or even specific template IDs/tags.
*   **Execution**: Use Python's `subprocess` module to run Nuclei.
    *   Construct commands dynamically based on user-defined scan configurations.
    *   Capture `stdout` and `stderr` for results and errors.
*   **Output Parsing**:
    *   Use the `-jsonl` (or `-json`) flag for machine-readable output. Each line in the output stream (or file) will be a JSON object representing a finding.
    *   Parse this JSON into the `ActiveScanResultItem` schema.
*   **Error Handling**:
    *   Check the return code of the `subprocess.run` call.
    *   Parse `stderr` for error messages from Nuclei.
    *   Implement timeouts for scans to prevent indefinite runs.
*   **Security**: Be cautious if user-supplied input is used to construct parts of the Nuclei command (e.g., template names or paths) to prevent command injection, although Nuclei's flags are generally safe. Always validate and sanitize inputs.

For StackGuardian, wrapping Nuclei's CLI is the most practical approach. The integration should focus on providing a user-friendly way to configure common scan options and then translating those into the appropriate Nuclei CLI arguments. Results will need to be parsed from JSON output into the defined Pydantic models.I have already completed steps 1 and 2. I will now proceed with step 3: Define Pydantic Models for Scan Configuration and Results.

I will create `stackguardian/stackguardian/schemas/active_scan.py`.
