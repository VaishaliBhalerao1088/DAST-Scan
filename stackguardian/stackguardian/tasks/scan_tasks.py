import json
import subprocess
import traceback
from celery import shared_task

from stackguardian.stackguardian.services.passive_scan import get_ssl_tls_info, get_http_headers_info
from stackguardian.stackguardian.schemas.scan import ScanTarget
from stackguardian.stackguardian.schemas.active_scan import (
    ZapScanConfig,
    NucleiScanConfig,
    ActiveScanReport,
    ActiveScanResultItem,
)
from stackguardian.stackguardian.core.config import settings
# from zapv2 import ZAPv2 # Would be used for direct ZAP API interaction


@shared_task(name="tasks.run_ssl_tls_scan")
def run_ssl_tls_scan_task(target_url: str) -> dict:
    """
    Celery task to perform an SSL/TLS scan on the given URL.
    """
    try:
        # Reconstruct the ScanTarget object. Pydantic will validate the URL.
        scan_target = ScanTarget(url=target_url)
        result = get_ssl_tls_info(scan_target)
        return result
    except Exception as e:
        # Log the exception or handle it as needed
        # For now, return a serializable error message
        return {"error": str(e), "traceback": traceback.format_exc()}

@shared_task(name="tasks.run_http_headers_scan")
def run_http_headers_scan_task(target_url: str) -> dict:
    """
    Celery task to perform an HTTP headers scan on the given URL.
    """
    try:
        # Reconstruct the ScanTarget object. Pydantic will validate the URL.
        scan_target = ScanTarget(url=target_url)
        result = get_http_headers_info(scan_target)
        return result
    except Exception as e:
        # Log the exception or handle it as needed
        # For now, return a serializable error message
        return {"error": str(e), "traceback": traceback.format_exc()}

@shared_task(name="tasks.run_zap_scan")
def run_zap_scan_task(config_dict: dict) -> dict: # Pass config as dict
    try:
        config = ZapScanConfig(**config_dict)
        target_url_str = str(config.target_url)
        
        # Using ZAP CLI (zap-baseline.py)
        command = [
            "zap-baseline.py", 
            "-t", target_url_str,
            "-j", # Output in JSON - this actually outputs a list of alert dicts to stdout
            # To specify a config file for zap-baseline:
            # "-c", "/path/to/zap_baseline_config.conf", 
            # To generate a report file:
            # "-r", "report.html",
        ]
        
        # If ZAP is running in a Docker container or non-default URL, 
        # zap-baseline.py needs to know how to reach it.
        # This usually means ZAP is started with API listening on 0.0.0.0
        # and you might need to pass ZAP's host/port to zap-baseline.py if it's not localhost:8080
        # For example, if ZAP is at http://zap-docker:8080
        # command.extend(["-P", "8080", "-H", "zap-docker"]) # This syntax is for zap.sh, not zap-baseline.py
        # zap-baseline.py itself uses ZAP_API_URL and ZAP_API_KEY environment variables or args to connect to ZAP
        # For simplicity, we assume zap-baseline.py can connect to ZAP at settings.ZAP_BASE_URL
        # and uses settings.ZAP_API_KEY if set.
        # Environment variables for zap-baseline.py:
        custom_env = {}
        if settings.ZAP_API_KEY:
            custom_env['ZAP_API_KEY'] = settings.ZAP_API_KEY
        if settings.ZAP_BASE_URL: # zap-baseline.py might use this to find ZAP
             # zap-baseline.py doesn't directly take ZAP_BASE_URL as env var for connection.
             # It assumes ZAP is at localhost:8080 or specified by ZAP_ADDRESS and ZAP_PORT env vars
             # or via command line args like -P and -H (which are not standard for zap-baseline.py).
             # The script `zap-baseline.py` often connects to ZAP via the ZAP Python API client, which
             # can be configured with proxies (ZAP_BASE_URL) and apikey (ZAP_API_KEY).
             # For now, we assume zap-baseline.py is configured to reach the ZAP instance.
             pass


        process = subprocess.run(command, capture_output=True, text=True, check=False, env=custom_env or None)
        
        # zap-baseline.py exit codes: 0=success, 1=WARN_FAIL_COUNT exceeded, 2=FAIL_FAIL_COUNT exceeded, 3=other error
        # We treat 0 and 1 as "successful" scan execution, 2 and 3 as failure.
        if process.returncode > 1 : 
            error_message = f"ZAP Baseline scan failed with exit code {process.returncode}.\n"
            if process.stderr:
                error_message += f"Stderr: {process.stderr}\n"
            if process.stdout: # Sometimes errors are also in stdout
                error_message += f"Stdout: {process.stdout}\n"
            raise Exception(error_message)
        
        # zap-baseline.py with -j outputs a JSON list of alert objects to stdout.
        try:
            raw_alerts = json.loads(process.stdout) if process.stdout else []
        except json.JSONDecodeError as json_err:
            # If stdout is not valid JSON, it's an issue.
            raise Exception(f"Failed to decode ZAP output as JSON: {json_err}\nStdout: {process.stdout}")

        vulnerabilities = []
        summary_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}

        for alert in raw_alerts: 
            severity = alert.get("risk", "Informational").capitalize()
            if severity not in summary_counts: 
                severity = "Informational" # Default for unknown severities
            summary_counts[severity] +=1
            
            vulnerabilities.append(ActiveScanResultItem(
                name=alert.get("name", "N/A"),
                severity=severity,
                description=alert.get("description", alert.get("desc", "")), # Some ZAP versions might use 'desc'
                cwe=alert.get("cweid", None),
                url_found=alert.get("url", target_url_str), 
                solution=alert.get("solution", ""),
                evidence=alert.get("evidence", None),
                parameter=alert.get("param", None),
                raw_details=alert 
            ))
        
        report = ActiveScanReport(
            scan_tool="OWASP ZAP Baseline",
            target=target_url_str,
            summary=summary_counts,
            vulnerabilities=vulnerabilities
        )
        return report.model_dump()

    except Exception as e:
        return {"error": str(e), "traceback": traceback.format_exc()}

@shared_task(name="tasks.run_nuclei_scan")
def run_nuclei_scan_task(config_dict: dict) -> dict:
    try:
        config = NucleiScanConfig(**config_dict)
        target_url_str = str(config.target_url)
        command = [
            "nuclei",
            "-u", target_url_str,
            "-jsonl", # Output in JSONL format (one JSON object per line)
            "-silent", 
        ]
        if config.templates:
            command.extend(["-t", ",".join(config.templates)])
        
        if config.severity:
            severity_map = {
                "critical": "critical", "high": "high", "medium": "medium",
                "low": "low", "info": "info", "informational": "info", "unknown": "unknown"
            }
            cli_severities = [severity_map[s.lower()] for s in config.severity if s.lower() in severity_map]
            if cli_severities:
                command.extend(["-s", ",".join(cli_severities)])
        
        process = subprocess.run(command, capture_output=True, text=True, check=False)
        
        if process.returncode != 0:
            if process.stderr:
                 raise Exception(f"Nuclei scan failed: {process.stderr}")
            elif not process.stdout.strip(): 
                 raise Exception(f"Nuclei scan failed with exit code {process.returncode} and no output.")
            # If there's stdout, we might still have partial results, so continue and parse them.

        vulnerabilities = []
        summary_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Unknown": 0}
        
        output_lines = process.stdout.strip().split('\n')
        if process.returncode !=0 and not output_lines and process.stderr: # If error and no stdout, re-raise based on stderr
             raise Exception(f"Nuclei scan failed: {process.stderr}")


        for line in output_lines:
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                print(f"Error decoding Nuclei JSON line: {line}") 
                continue

            # Normalize severity from Nuclei's output
            nuclei_severity = alert.get("info", {}).get("severity", "unknown").lower()
            mapped_severity = {
                "critical": "Critical", "high": "High", "medium": "Medium",
                "low": "Low", "info": "Informational", "informational": "Informational",
                "unknown": "Unknown"
            }.get(nuclei_severity, "Unknown")
            summary_counts[mapped_severity] += 1

            # CWE parsing: 'cwe-id' can be like "CWE-79" or just a number
            cwe_raw = alert.get("info", {}).get("classification", {}).get("cwe-id", [])
            cwe_val = None
            if cwe_raw:
                if isinstance(cwe_raw, list): cwe_raw = cwe_raw[0] # Take the first if it's a list
                if isinstance(cwe_raw, str) and "CWE-" in cwe_raw:
                    try:
                        cwe_val = int(cwe_raw.split("CWE-")[1])
                    except (ValueError, IndexError):
                        cwe_val = None 
                elif isinstance(cwe_raw, int):
                    cwe_val = cwe_raw


            vulnerabilities.append(ActiveScanResultItem(
                name=alert.get("info", {}).get("name", "N/A"),
                severity=mapped_severity,
                description=alert.get("info", {}).get("description", ""),
                cwe=cwe_val,
                url_found=alert.get("matched-at", alert.get("host", target_url_str)), # "host" is also common
                evidence=str(alert.get("extracted-results", []) or alert.get("matcher-name", "")),
                solution="Refer to template details and general remediation guidelines.",
                raw_details=alert
            ))
        
        report = ActiveScanReport(
            scan_tool="Nuclei",
            target=target_url_str,
            summary=summary_counts,
            vulnerabilities=vulnerabilities
        )
        return report.model_dump()

    except Exception as e:
        return {"error": str(e), "traceback": traceback.format_exc()}
