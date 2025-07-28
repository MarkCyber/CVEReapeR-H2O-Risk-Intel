
# CVEReapeR: An H2Oai Risk Intel Pipeline

![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)
![License: Custom](https://img.shields.io/badge/License-Custom-blue.svg)
![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)

An end to end machine learning pipeline for CVE risk analysis. This tool takes in vulnerability data (such as NVD CVEs, CISA KEV, ExploitDB), simulates or parses log data (depending on if you have real logs to input), and then uses H2O's AutoML feature to predict and prioritize the most dangerous vulnerabilities in your environment.

ELI5 (Explain Like Im 5): Give the AI all the hacker gossip and weird logs, and it goes pew pew on the baddies (CVE vulnerabilities) so your network doesn’t get jacked.


---

## Project structure:

```
CVEReapeR-H2O-Risk-Intel/
│
├── data/            # CVE data (NVD JSONs, CISA KEV CSV, logs)
├── exploitdb/       # ExploitDB exploit metadata (CSV)
├── models/          # Trained models
├── notebooks/       # Optional jupyter notebook/jupyter lab
├── outputs/         # Generated charts and risk report
├── run_analysis.py  # Main pipeline entrypoint, run this after setting config
├── config.yaml      # Configuration for data paths and parameters as well as email
└── .gitattributes   # Git LFS tracking for large CVE JSON files
```

---

## Overview

While CVEReapeR is functional, it is also a work in progress. The goal of CVEReapeR is to automate triage beyond just threat control. It contextualizes vulnerabilities based on exposure, asset type, and exploit availability to produce a prioritized, explainable list of threats tailored to your environment.

### Key Features:

- **End to end workflow:** Vulnerability scanner outputs and log data will return a full risk ranked report with explainability and next steps.
- **H2O AutoML:** Trains, tests, and selects the best model for risk classification.
- **Simulation option:** If real logs are unavailable, there is the option to simulate logs built into CVEReapeR.
- **Exploit-aware enrichment (thanks exploitdb):** Joins CVE data with real-world exploit metadata from exploitdb and (in the future- CISA KEV).
- **Explainable results:** Offers explainability based on feature importance scores and rule based logic.
- **Simple to read output:** Markdown results that are easy to interpet, along with an email feature to provide immediate results to others when needed.

---

## Technologies Used

- **Machine Learning:** H2O.ai (AutoML), GBM, xgboost
- **Data Handling:** Pandas, NumPy, YAML, JSON  
- **Visualization:** Matplotlib, Seaborn  
- **Explainability:** Feature importance and rule-based attribution  
- **Reporting:** Markdown + optional direct email

---

## 💧Blue Team Use Cases💧

CVEReapeR was built with defenders in mind: analysts, threat hunters, and vulnerability managers who need to understand their security posture fast.

### Defensive Applications:

- **Triage automation:** Prioritize vulnerabilities based on exploitability, asset exposure, and log evidence.
- **Risk reduction:** Contextual recommendations to aid in patch decisions along with network segmentation.
- **Reporting:** Share clean markdown reports or trigger email alerts for stakeholders.
- **Threat Hunting:** Use log parsing and asset simulation to enrich vulnerability findings.
  
---

## 🩸Red Team Use Cases🩸

While CVEReapeR was initially designed for blue teams, its output can still be valuable for offensive teams simulating real world adversaries.

### Offensive Applications:

- **Scenario planning:** Identify critical CVEs to use in assumed breach or post-exploitation.
- **Exploit path prioritization:** Rank vulnerable hosts by exploitability and service context.
- **Target selection for emulation:** Pinpoint high-value targets for red team scenarios.
- **Payload strategy:** Leverage exploit metadata to focus efforts on high-impact vulnerabilities.

---

## Example Output

The final report shows prioritized CVEs with model explanations and visuals:

### Top 5 Riskiest Hosts

*a chart showing those 5 hosts here*

### Example CVE Prediction

> **host015.mil - CVE-2021-44228**  
> • **AI Risk Level:** Critical  
> • **Explanation:** Public exploit exists, and the system is internet-exposed with log activity.  
> • **Recommended Action:** Patch immediately. If delayed, isolate from exposed networks.

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/markcyber/cvereaper-h2o-risk-intel.git
cd cvereaper-h2o-risk-intel
```

### 2. Install Dependencies

Python 3.9+ is highly recommended.

```bash
pip install -r requirements.txt
```

You may also need to install H2O if you have not already:

```bash
pip install -f https://h2o-release.s3.amazonaws.com/h2o/latest_stable_Py.html h2o
```

### 3. Modify the config

```bash
nano config.yaml
```

### 4. Run the Pipeline

```bash
python run_analysis.py
```
Outputs are saved in the `outputs/` directory.

---

## Data Sources

-  [NVD CVE JSONs (2019–2025)](https://nvd.nist.gov/vuln/data-feeds)  
-  [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)  
-  [ExploitDB](https://www.exploit-db.com)

All data used is publicly available, and usage complies with public/open data standards.

---

## Notes

- Large JSON files (>100MB) are managed using Git LFS  
- Trained model files in `models/` are optional; you can remove or regenerate them  
- You can simulate log data or plug in real enterprise logs (CSV format)

---

## License

This project is licensed under a custom non-commercial license.  
See the [LICENSE](./LICENSE.md) file for full details.

---

## Author

Made with ❤️ by **markcyber**  
Special focus on red teaming, cyber threat intelligence, and ML-based exploit prediction.

> _This project was developed with assistance from gemini._
