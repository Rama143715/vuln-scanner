from flask import Flask, render_template, request, jsonify
import nmap
import requests
import json

app = Flask(__name__)

def lookup_cve(service, version):
    """Look up CVEs from NIST NVD API for a given service and version."""
    if not service or service in ['unknown', 'tcpwrapped']:
        return []
    try:
        query = f"{service} {version}".strip() if version else service
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": query, "resultsPerPage": 5}
        resp = requests.get(url, params=params, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "N/A")
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
                metrics = cve.get("metrics", {})
                score = "N/A"
                severity = "UNKNOWN"
                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]
                    score = cvss.get("baseScore", "N/A")
                    severity = cvss.get("baseSeverity", "UNKNOWN")
                elif "cvssMetricV2" in metrics:
                    cvss = metrics["cvssMetricV2"][0]["cvssData"]
                    score = cvss.get("baseScore", "N/A")
                    severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
                cves.append({
                    "id": cve_id,
                    "description": desc[:200] + "..." if len(desc) > 200 else desc,
                    "score": score,
                    "severity": severity
                })
            return cves
    except Exception:
        return []
    return []


def scan_target(target, scan_type="standard"):
    nm = nmap.PortScanner()
    results = {
        "target": target,
        "status": "unknown",
        "os": [],
        "ports": [],
        "summary": {}
    }

    try:
        if scan_type == "quick":
            args = "-sV --version-intensity 3 -T4 -F"
        else:
            args = "-sV -O --version-intensity 5 -T4 --top-ports 100"

        nm.scan(hosts=target, arguments=args)

        if not nm.all_hosts():
            results["status"] = "Host seems down or unreachable"
            return results

        host = nm.all_hosts()[0]
        results["status"] = nm[host].state()

        # OS Detection
        if "osmatch" in nm[host]:
            for os_match in nm[host]["osmatch"][:3]:
                results["os"].append({
                    "name": os_match.get("name", "Unknown"),
                    "accuracy": os_match.get("accuracy", "0")
                })

        open_count = 0
        total_ports = 0

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                total_ports += 1
                port_data = nm[host][proto][port]
                state = port_data.get("state", "unknown")
                service = port_data.get("name", "unknown")
                version = port_data.get("version", "")
                product = port_data.get("product", "")

                if state == "open":
                    open_count += 1

                full_version = f"{product} {version}".strip()

                # CVE Lookup for open ports
                cves = []
                if state == "open" and service != "unknown":
                    cves = lookup_cve(service, full_version)

                results["ports"].append({
                    "port": port,
                    "protocol": proto,
                    "state": state,
                    "service": service,
                    "version": full_version,
                    "cves": cves
                })

        results["summary"] = {
            "total_ports": total_ports,
            "open_ports": open_count,
            "closed_ports": total_ports - open_count
        }

    except nmap.PortScannerError as e:
        results["status"] = f"Nmap error: {str(e)}"
    except Exception as e:
        results["status"] = f"Scan error: {str(e)}"

    return results


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = data.get("target", "").strip()
    scan_type = data.get("scan_type", "standard")

    if not target:
        return jsonify({"error": "No target provided"}), 400

    result = scan_target(target, scan_type)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
