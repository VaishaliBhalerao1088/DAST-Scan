# External Tool Setup for Active Scans

For StackGuardian to perform active vulnerability scans, certain external tools need to be installed and accessible in the environment where the Celery workers execute.

## 1. OWASP ZAP (Zed Attack Proxy)

StackGuardian currently uses ZAP's `zap-baseline.py` script for baseline scans. This script requires a running ZAP instance.

**Installation Options:**

*   **Docker (Recommended for consistency):**
    *   Pull the official ZAP Docker image:
        ```bash
        docker pull owasp/zap2docker-stable
        ```
    *   Run ZAP as a daemon, exposing its API port (default 8080). Replace `your_api_key_here` if you intend to use one.
        ```bash
        docker run -d -p 8080:8080 -i owasp/zap2docker-stable zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.disablekey=true
        # Or with an API key:
        # docker run -d -p 8080:8080 -i owasp/zap2docker-stable zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.key=your_api_key_here -config api.disablekey=false 
        ```
    *   The `zap-baseline.py` script is included in this Docker image (usually at `/zap/zap-baseline.py`). The Celery task assumes this script is available and ZAP is running at `http://localhost:8080` (or as configured in `ZAP_BASE_URL`).
    *   If ZAP runs on a different host/port than the Celery worker, ensure `ZAP_BASE_URL` in `stackguardian/core/config.py` is updated, and the `zap-baseline.py` script can reach it. The script itself often uses environment variables like `ZAP_ADDRESS` and `ZAP_PORT` to connect, or relies on the ZAP Python API which can be configured.

*   **System Install:**
    *   Download ZAP from the [official website](https://www.zaproxy.org/download/).
    *   Install it on the system where the Celery worker runs.
    *   Ensure ZAP is started in daemon mode before scans are initiated.
    *   The `zap-baseline.py` script is usually found in the ZAP installation directory. Ensure this script is in the system's PATH or its full path is specified in the Celery task if modified.

**Configuration in StackGuardian:**
*   `ZAP_BASE_URL`: Set in `stackguardian/core/config.py` to the URL of the ZAP API (e.g., `http://localhost:8080`).
*   `ZAP_API_KEY`: Set in `stackguardian/core/config.py` if your ZAP instance requires an API key.

## 2. Nuclei

StackGuardian uses the Nuclei CLI for template-based scanning.

**Installation Options:**

*   **From GitHub Releases (Recommended):**
    *   Download the latest pre-compiled binary for your system from [ProjectDiscovery's Nuclei releases page](https://github.com/projectdiscovery/nuclei/releases).
    *   Place the `nuclei` binary in a directory included in your system's PATH (e.g., `/usr/local/bin`).
    *   Ensure it's executable: `chmod +x /path/to/nuclei`.

*   **Using Go:**
    *   If you have Go installed:
        ```bash
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        ```
    *   This will typically install Nuclei to `$HOME/go/bin/nuclei`. Ensure this directory is in your PATH.

**Template Management:**
*   Nuclei templates are crucial. Run `nuclei -update-templates` regularly to get the latest community templates.
    ```bash
    nuclei -update-templates
    # Optionally, update to a specific directory:
    # nuclei -update-templates -templates-dir /path/to/custom/nuclei-templates
    ```
*   The Celery worker executing Nuclei tasks needs access to these templates. By default, Nuclei looks for templates in `$HOME/.local/nuclei/templates`.

**Configuration in StackGuardian:**
*   No specific configuration is needed in `config.py` for Nuclei itself, other than ensuring the `nuclei` command is executable and in the PATH of the Celery worker's environment.
*   Scan configurations (templates, severity) are passed at runtime via API calls.

## Important Notes for Celery Worker Environment:

*   **PATH Variable**: Ensure the directories containing `zap-baseline.py` (if not using the ZAP Docker image's default path) and `nuclei` are in the `PATH` environment variable of the Celery worker.
*   **Permissions**: The user running the Celery worker must have execute permissions for these tools.
*   **Network Access**: Celery workers must be able to reach the target applications for scanning. If ZAP is running in a separate container, ensure the worker can reach ZAP's API.
*   **Resource Allocation**: Both ZAP and Nuclei can be resource-intensive. Monitor the Celery worker's resource usage (CPU, memory).

This setup ensures that the Celery tasks can successfully invoke `zap-baseline.py` and `nuclei` to perform scans.
