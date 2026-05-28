# OSV Threat Stream Campaign Dashboard Indicator

A Python command-line security engineering tool for tracking software supply chain activity across the Open Source Vulnerability (OSV) database.

[cite_start]The script builds a local advisory index from OSV, reads the OSV modified advisory stream, and produces a terminal dashboard showing which ecosystems are experiencing the most vulnerability database churn over a selected time window. [cite_start]It can also export JSON snapshots, compare two snapshots, and audit a local project manifest against currently mutating advisories.

## 🚀 Quick Start & Execution Path

For an engineer cloning this repository clean, follow this sequential execution path to bootstrap the environment and wire the high-performance local database warehouse:

### 1. Clone the Repository & Install Dependencies
First, target your workspace directory and install the required core packages and high-precision parsing libraries:
```bash
git clone <your-repository-url>
cd top-10-ecosystems
pip install -r requirements.txt