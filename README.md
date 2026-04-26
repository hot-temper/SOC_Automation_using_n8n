# SOC Automation using n8n

An automated Security Operations Center (SOC) workflow designed to streamline incident response by integrating **Wazuh** (SIEM/XDR) with **n8n** (workflow automation). This project focuses on automated alert triage, IOC extraction, and intelligent enrichment to reduce "alert fatigue."This system reduces Mean Time to Investigation (MTTI) to 15–25 seconds and eliminates manual alert handling, significantly improving SOC response efficiency and operational speed.

## 🚀 Overview

This repository contains the configuration files and workflows necessary to bridge the gap between threat detection and automated response. By leveraging n8n, security alerts from Wazuh are processed in real-time, enriched with external intelligence, and triaged using logical workflows.

## 📂 Project Structure

- **`n8n_Workflow_+_Results/`**: Contains exported n8n JSON workflow files and sample execution outputs.
- **`Wazuh_Integrations/`**: Scripts and configuration snippets for setting up custom integrations within the Wazuh manager.
- **`wazuh-ossec.conf`**: The main configuration file for the Wazuh manager, optimized for external API integration.
- **`Master_Wazuh_Alerts_120.txt`**: A collection of sample alerts used for testing and validating the automation logic.


## SOC Architectural Workflow

The framework integrates six primary components into a unified triage pipeline. Wazuh (v4.x, SIEM/XDR) collects endpoint logs via agents, performs anomaly detection, and produces structured JSON alerts. Suricata (NIDS) provides real-time network intrusion detection, forwarding alerts to Wazuh for correlation. n8n is the SOAR and AI orchestration engine — a visual, self-hosted, API-flexible workflow platform. TheHive manages incident case lifecycles. Cortex automates observable enrichment. Telegram delivers real-time analyst notifications with inline approve/reject action buttons.
<p align="center">
  <img src="Assets/----preliminary project idea workflow ----.svg" width="700"><br>
  <b>Figure 1: SOC Automation Workflow</b>
</p>


## n8n Automation Workflow Pipeline

The n8n automation pipeline executes in eight sequential stages: (1) Wazuh sends a structured JSON alert to the n8n webhook endpoint; (2) n8n asynchronously acknowledges receipt; (3) IOC extraction parses the alert for IPs, hashes, URLs, and domains using regex and LLM nodes; (4) if IOCs are present, five TI engines (AbuseIPDB, VirusTotal IP/Hash, AlienVault OTX, Hybrid Analysis) are queried in parallel; (5) TI results are aggregated into a structured enrichment report; (6) the enriched alert is submitted to Groq llama-3.3-70b with a few-shot-prompted MITRE ATT&CK system message, with Gemini 2.5-flash-lite as automatic fallback; (7) the LLM generates a structured triage report (verdict, risk score 0–100, MITRE mapping, P0–P3 actions, investigation steps); (8) the report is delivered to Telegram and a TheHive case is created for all TRUE_POSITIVE and NEEDS_INVESTIGATION verdicts.
<p align="center">
  <img src="Assets/n8n raw workflow .png" width="700"><br>
  <b>Figure 2: n8n Automation Workflow</b>
</p>



## 🛠️ Key Features

- **Automated Alert Triage**: Filter out noise and focus on high-fidelity alerts.
- **IOC Extraction**: Automatically extract IPs, Hashes, and URLs from incoming Wazuh alerts.
- **Correlation & Enrichment**: Integrating external threat intelligence feeds for confidence scoring.
- **Scalable Architecture**: Built using Docker-friendly tools like n8n for easy deployment in local or cloud environments.
  
## 📊 Performance Impact
* **Mean Time to Investigation (MTTI):** Reduced to **15-25 seconds**.
* **Manual Effort:** 0% manual handling for initial triage and enrichment.
* **Scalability:** Capable of processing hundreds of alerts per minute via n8n's asynchronous execution.

## 🔧 Getting Started

1. **Prerequisites**:
   - A running instance of **Wazuh Manager**.
   - **n8n** (Self-hosted via Docker recommended).
2. **Setup**:
   - Update your `ossec.conf` with the integration block provided in this repo.
   - Import the `.json` workflows from the `n8n_Workflow_+_Results` folder into your n8n instance.
   - Configure your environment variables (API keys for enrichment services).
