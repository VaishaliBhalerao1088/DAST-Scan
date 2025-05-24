import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Any

from stackguardian.stackguardian.schemas.scan import ScanTarget

def get_ssl_tls_info(target: ScanTarget) -> Dict[str, Any]:
    try:
        parsed_url = urlparse(str(target.url))
        hostname = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 443

        if not hostname:
            return {"error": "Could not parse hostname from URL."}

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssl_socket:
                cert = ssl_socket.getpeercert()
                
                # Process certificate details
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                
                not_before_str = cert.get('notBefore')
                not_after_str = cert.get('notAfter')
                
                date_format = '%b %d %H:%M:%S %Y %Z' # Example: Jun 19 00:00:00 2023 GMT
                
                not_before = datetime.strptime(not_before_str, date_format) if not_before_str else None
                not_after = datetime.strptime(not_after_str, date_format) if not_after_str else None
                
                is_expired = False
                if not_after:
                    is_expired = datetime.utcnow() > not_after

                ssl_info = {
                    "issuer": issuer,
                    "subject": subject,
                    "version": cert.get('version'),
                    "serial_number": cert.get('serialNumber'),
                    "not_before": not_before.isoformat() if not_before else None,
                    "not_after": not_after.isoformat() if not_after else None,
                    "is_expired": is_expired,
                    "tls_version": ssl_socket.version(),
                    "cipher": ssl_socket.cipher(),
                }
                return ssl_info

    except ssl.SSLError as e:
        return {"error": f"SSL Error: {e}"}
    except socket.gaierror as e:
        return {"error": f"Address-related error connecting to server: {e}"}
    except socket.timeout:
        return {"error": "Connection timed out"}
    except ConnectionRefusedError:
        return {"error": "Connection refused"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}

import requests

def get_http_headers_info(target: ScanTarget) -> Dict[str, Any]:
    try:
        response = requests.get(str(target.url), allow_redirects=True, timeout=10)
        headers = dict(response.headers) # Convert to dict for easier serialization if needed

        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "Referrer-Policy": headers.get("Referrer-Policy"),
            "Permissions-Policy": headers.get("Permissions-Policy") or headers.get("Feature-Policy"), # Check both
            "Server": headers.get("Server"),
            "X-Powered-By": headers.get("X-Powered-By"),
        }

        return {
            "all_headers": headers,
            "security_headers_summary": security_headers,
        }

    except requests.exceptions.SSLError as e:
        return {"error": f"SSL Error during HTTP request: {e}"}
    except requests.exceptions.ConnectionError as e:
        return {"error": f"Connection Error during HTTP request: {e}"}
    except requests.exceptions.Timeout as e:
        return {"error": f"Timeout during HTTP request: {e}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"An error occurred during HTTP request: {e}"}
