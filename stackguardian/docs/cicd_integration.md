# CI/CD Integration Guide (Draft)

StackGuardian provides API endpoints to integrate security scanning into your CI/CD pipelines.

## Authentication
It's recommended to create a dedicated service account user within StackGuardian for your CI/CD pipelines.
Authenticate this user via the `/api/v1/users/login` endpoint to obtain a JWT access token.
Include this token in the `Authorization: Bearer <token>` header for all subsequent API calls.

## Endpoints

### 1. Trigger Scan
- **URL:** `/api/v1/cicd/trigger_scan`
- **Method:** `POST`
- **Request Body:** See `CICDScanTriggerRequest` schema. The schema is available via the API documentation at `/docs` or `/redoc`.
  ```json
  // Example for a ZAP scan
  {
    "scan_type": "zap",
    "target_url": "https://your-app-staging.example.com",
    "zap_config": {
      "target_url": "https://your-app-staging.example.com",
      "scan_type": "baseline" // "baseline" is an example, refer to ZapScanConfig for actual scan_type values if defined
    }
  }
  ```
  ```json
  // Example for a Nuclei scan
  {
    "scan_type": "nuclei",
    "target_url": "https://your-app-staging.example.com",
    "nuclei_config": {
      "target_url": "https://your-app-staging.example.com",
      "templates": ["cves", "exposures/tokens"], // Optional: example templates
      "severity": ["HIGH", "CRITICAL"] // Optional: example severities
    }
  }
  ```
- **Response:** `CICDTaskStatus` with `task_id` and initial task status.

### 2. Fetch Results & Check Policy
- **URL:** `/api/v1/cicd/fetch_results`
- **Method:** `POST`
- **Request Body:** See `CICDScanResultRequest` schema.
  ```json
  {
    "task_id": "your_task_id_from_trigger_scan",
    "fail_on_severity": "HIGH", // Optional: e.g., CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    "minimum_alert_level": "MEDIUM" // Optional: Only fetch alerts of this severity or higher
  }
  ```
- **Response:** `CICDTaskStatus` with scan results.
    - If `fail_on_severity` is set and a vulnerability meets or exceeds the threshold, the endpoint will return an HTTP `412 Precondition Failed` error, which should fail your CI/CD pipeline.
    - If the scan task itself failed (e.g., tool error), an HTTP `500 Internal Server Error` is returned.
    - Otherwise, a `200 OK` with scan results (potentially filtered by `minimum_alert_level`).

## Example Workflow (using curl)

This example assumes you have `jq` installed for parsing JSON and `curl` for making HTTP requests.

1.  **Login and Get Token (once, or if token expires):**
    Replace `cicd_user` and `cicd_password` with your service account credentials.
    ```bash
    STACKGUARDIAN_URL="http://localhost:8000" # Or your StackGuardian instance URL
    USERNAME="cicd_user"
    PASSWORD="cicd_password"

    TOKEN=$(curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" \
                 -d "username=$USERNAME&password=$PASSWORD" \
                 "$STACKGUARDIAN_URL/api/v1/users/login" | jq -r .access_token)

    if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
        echo "Failed to get token. Exiting."
        exit 1
    fi
    echo "Successfully obtained token."
    ```

2.  **Trigger Scan:**
    Example for a ZAP baseline scan:
    ```bash
    TARGET_APP_URL="https://your-app-to-scan.example.com"
    TRIGGER_PAYLOAD=$(cat <<EOF
    {
      "scan_type": "zap",
      "target_url": "$TARGET_APP_URL",
      "zap_config": {
        "target_url": "$TARGET_APP_URL",
        "scan_type": "baseline"
      }
    }
    EOF
    )

    TASK_ID_RESPONSE=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
                         -d "$TRIGGER_PAYLOAD" \
                         "$STACKGUARDIAN_URL/api/v1/cicd/trigger_scan")
    
    TASK_ID=$(echo $TASK_ID_RESPONSE | jq -r .task_id)

    if [ -z "$TASK_ID" ] || [ "$TASK_ID" == "null" ]; then
        echo "Failed to trigger scan. Response: $TASK_ID_RESPONSE"
        exit 1
    fi
    echo "Scan triggered. Task ID: $TASK_ID"
    ```

3.  **Poll for Results (and Check Policy):**
    Implement proper polling with delays and a timeout.
    ```bash
    POLL_INTERVAL=30 # seconds
    MAX_ATTEMPTS=20  # e.g., 20 * 30s = 10 minutes timeout
    FAIL_SEVERITY="HIGH" # Or CRITICAL, MEDIUM etc.

    echo "Polling for results for Task ID: $TASK_ID..."

    for (( i=1; i<=$MAX_ATTEMPTS; i++ )); do
        echo "Attempt $i/$MAX_ATTEMPTS: Checking task status..."
        
        FETCH_PAYLOAD=$(cat <<EOF
        {
          "task_id": "$TASK_ID",
          "fail_on_severity": "$FAIL_SEVERITY"
        }
        EOF
        )

        HTTP_RESPONSE_CODE=$(curl -s -o /tmp/scan_results.json -w "%{http_code}" -X POST \
                                 -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
                                 -d "$FETCH_PAYLOAD" \
                                 "$STACKGUARDIAN_URL/api/v1/cicd/fetch_results")
        
        SCAN_RESULTS_BODY=$(cat /tmp/scan_results.json)

        if [ "$HTTP_RESPONSE_CODE" -eq 200 ]; then
            echo "Scan completed successfully."
            echo "Results: $SCAN_RESULTS_BODY"
            # Potentially parse $SCAN_RESULTS_BODY for further actions
            exit 0 # Success
        elif [ "$HTTP_RESPONSE_CODE" -eq 412 ]; then
            echo "Scan failed severity policy (Threshold: $FAIL_SEVERITY)."
            echo "Details: $SCAN_RESULTS_BODY"
            exit 1 # Failure - policy violation
        elif [ "$HTTP_RESPONSE_CODE" -eq 500 ]; then
            echo "Scan task execution failed on server."
            echo "Details: $SCAN_RESULTS_BODY"
            exit 1 # Failure - task error
        else
            TASK_STATUS=$(echo $SCAN_RESULTS_BODY | jq -r .status)
            echo "Task status: $TASK_STATUS (HTTP $HTTP_RESPONSE_CODE). Retrying in $POLL_INTERVAL seconds..."
            # Check if task status is PENDING or STARTED, otherwise it might be an unexpected error
            if [ "$TASK_STATUS" != "PENDING" ] && [ "$TASK_STATUS" != "STARTED" ]; then
                 echo "Unexpected task status or HTTP code. Details: $SCAN_RESULTS_BODY"
                 # exit 1 # Or handle as a retryable error for a few more times
            fi
        fi
        
        sleep $POLL_INTERVAL
    done

    echo "Scan did not complete within the timeout period."
    exit 1 # Failure - timeout
    ```

This guide provides a basic framework. You'll need to adapt the `curl` examples to your specific CI/CD system's scripting capabilities (e.g., using built-in functions for HTTP requests or tools like `wget`). Remember to handle secrets (like the `TOKEN`) securely within your CI/CD environment.
```
