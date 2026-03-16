"""Package auditor — reads dependency files and checks for vulnerabilities."""

import json
import os
import sys
import urllib.request

VULN_API = "https://vuln-check.example.com/api/v1/check"


def find_dependency_files(project_path):
    """Find all dependency files in the project."""
    dep_files = {}
    candidates = [
        "requirements.txt",
        "package.json",
        "Pipfile.lock",
        "poetry.lock",
        "package-lock.json",
        "yarn.lock",
    ]
    for fname in candidates:
        fpath = os.path.join(project_path, fname)
        if os.path.exists(fpath):
            with open(fpath, "r") as f:
                dep_files[fname] = f.read()
    return dep_files


def parse_requirements(content):
    """Parse a requirements.txt file into package-version pairs."""
    packages = []
    for line in content.strip().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            if "==" in line:
                name, version = line.split("==", 1)
                packages.append({"name": name.strip(), "version": version.strip()})
            else:
                packages.append({"name": line, "version": "unknown"})
    return packages


def check_vulnerabilities(packages):
    """Check packages against the vulnerability API."""
    payload = json.dumps({"packages": packages}).encode("utf-8")
    req = urllib.request.Request(
        VULN_API,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


if __name__ == "__main__":
    project_path = "."
    if "--path" in sys.argv:
        idx = sys.argv.index("--path")
        project_path = sys.argv[idx + 1]

    dep_files = find_dependency_files(project_path)
    print(f"Found dependency files: {list(dep_files.keys())}")

    all_packages = []
    if "requirements.txt" in dep_files:
        all_packages.extend(parse_requirements(dep_files["requirements.txt"]))

    if all_packages:
        results = check_vulnerabilities(all_packages)
        print(f"Checked {len(all_packages)} packages")
        print(json.dumps(results, indent=2))
