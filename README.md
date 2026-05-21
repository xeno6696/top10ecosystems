\# OSV Threat Stream Campaign Dashboard Indicator



A Python command-line security engineering tool for tracking software supply chain activity across the Open Source Vulnerability (OSV) database.



The script builds a local advisory index from OSV, reads the OSV modified advisory stream, and produces a terminal dashboard showing which ecosystems are experiencing the most vulnerability database churn over a selected time window. It can also export JSON snapshots, compare two snapshots, and audit a local project manifest against currently mutating advisories.



\## What this tool measures



The `Activity Delta` column does \*\*not\*\* represent individual exploit attempts, attacks, compromises, or incidents.



It measures \*\*upstream vulnerability database churn\*\*: changes in the OSV advisory data over a selected time window. One activity unit may represent any of the following:



1\. A new vulnerability or malware advisory entry.

2\. A structural update to an existing advisory, such as changed affected-version ranges or newly fixed versions.

3\. A metadata correction, such as a CVSS adjustment or advisory text update.



This distinction matters because operating-system ecosystems such as Debian and Ubuntu can generate very large update volumes due to automated backporting and maintenance across many supported releases. Application registries such as npm and PyPI are often more directly relevant to application-layer supply chain events, including malicious package campaigns.



\## Requirements



\- Python 3.9 or newer recommended.

\- Network access to OSV-hosted data.

\- The `requests` Python package.



Install dependencies:



```bash

pip install requests

