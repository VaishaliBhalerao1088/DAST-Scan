# OWASP ZAP Integration Research

This document outlines methods for programmatically interacting with OWASP ZAP.

## Key Interaction Methods

1.  **ZAP Python API Client (`python-owasp-zap-v2.4`)**:
    *   **Description**: Official Python client library for the ZAP API. This is generally the preferred method for robust integration.
    *   **Usage**:
        *   **Starting ZAP**: The client assumes ZAP is already running. ZAP needs to be started in daemon mode, typically with an API key.
            ```bash
            zap.sh -daemon -port 8080 -config api.key=your_api_key_here -config api.disablekey=false
            # Or on Windows:
            # zap.bat -daemon -port 8080 -config api.key=your_api_key_here -config api.disablekey=false
            ```
        *   **Connecting**:
            ```python
            from zapv2 import ZAPv2
            zap = ZAPv2(apikey='your_api_key_here', proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
            ```
        *   **Configuring Contexts**: Contexts define the scope of a scan.
            ```python
            context_name = 'MyContext'
            context_id = zap.context.new_context(context_name)
            zap.context.include_in_context(context_name, 'http://example.com/.*')
            # Exclude URLs if needed
            # zap.context.exclude_from_context(context_name, 'http://example.com/logout.*')
            ```
        *   **Session Management**: For authenticated scans, session handling (e.g., HTTP sessions, ZAP users) can be configured.
        *   **Initiating Scans**:
            *   **Spider**: `zap.spider.scan(url=target_url, contextname=context_name)`
            *   **AJAX Spider**: `zap.ajaxSpider.scan(url=target_url, contextname=context_name)` (for modern web apps)
            *   **Passive Scan**: ZAP passively scans all proxied traffic. `zap.pscan.records_to_scan` can check scan queue.
            *   **Active Scan**: `zap.ascan.scan(url=target_url, contextid=context_id, recurse=True, scanpolicyname='Default Policy')`
            *   **API Scan**:
                *   Import API definition (OpenAPI/Swagger): `zap.openapi.import_url(url=api_def_url, hostoverride=target_host)` or `zap.soap.import_url(url=wsdl_url)`
                *   Then run active scan on the imported API endpoints.
        *   **Retrieving Results**:
            *   Alerts: `zap.core.alerts(baseurl=target_url, riskid=None, start=None, count=None)` returns alerts in JSON.
            *   Reports: `zap.core.jsonreport()` or `zap.core.xmlreport()` can generate reports.
        *   **Shutting Down ZAP**: `zap.core.shutdown()` (if ZAP was started with the API key enabling shutdown).

2.  **Command-Line Interface (CLI)**:
    *   **Description**: Using `zap.sh` or `zap.bat` with specific flags for packaged scans.
    *   **Usage**:
        *   **Baseline Scan**: Good for CI/CD, passive scan against a target.
            ```bash
            zap.sh -cmd -quickurl http://example.com -quickprogress -autorun -baseline
            # Or with a config file:
            # zap.sh -cmd -autorun -configfile /path/to/config.properties
            ```
        *   **Full Scan**: Active scan, more intensive.
            ```bash
            zap.sh -cmd -quickurl http://example.com -quickprogress -autorun -fullscan
            ```
        *   **API Scan**:
            ```bash
            # Using OpenAPI definition
            zap.sh -cmd -autorun -openapi_url https://www.example.com/openapi.json -target_url https://www.example.com/api/ -report_file /zap/api_report.html
            ```
        *   **Output**: Reports can be generated in HTML, JSON, XML.
            `-J /path/to/report.json` for JSON report.
    *   **Pros**: Simpler for basic, automated scans.
    *   **Cons**: Less flexible than the Python API for complex scenarios.

3.  **Direct HTTP API Calls**:
    *   **Description**: ZAP exposes its API over HTTP (usually on the same port ZAP listens on).
    *   **Usage**: Similar to the Python client, but involves manual HTTP requests to endpoints like `/JSON/core/action/newScan/`.
    *   **Pros**: Language-agnostic.
    *   **Cons**: More cumbersome than using the Python client; need to handle HTTP requests, responses, and API key manually. The Python client abstracts this.

## Summary for Integration

*   **Starting ZAP**: A separate process, ideally in daemon mode with an API key. This needs to be managed by the application or a wrapper script.
*   **Configuration**: Python API client offers good control over contexts, scan policies, and other settings.
*   **Scanning**:
    *   Spidering (traditional and AJAX) is crucial before active scanning.
    *   API scans involve importing an API definition.
*   **Results**: JSON is the preferred format for programmatic parsing.
*   **Shutdown**: Can be done via API if enabled.

The **Python API Client** appears to be the most suitable for a flexible and robust integration within a Python application like StackGuardian. It provides fine-grained control over ZAP's functionalities. CLI might be useful for simpler, predefined scan types if detailed configuration via code is not needed.
