# Project Aegis 🛡️

### Automated Malware Collection, Triage, and Intelligence Orchestration

**Project Aegis** is a technical pipeline designed to automate the collection and triage of malware samples. It leverages Infrastructure-as-Code to deploy global sensors, offloads captured data to a cloud evidence locker, and processes binaries through a local containerized analysis engine (**Panoptik**).

---

## 🏗️ Core Architecture

### 1. The Sensor Network (Collection)

* **Infrastructure-as-Code (IaC):** **Terraform** is used to provision and manage global honeypot nodes on **DigitalOcean**.
* **Honeypot Nodes:** Droplets configured with **Cowrie** to capture SSH/Telnet authentication attempts, TTY logs, and malware payloads (scripts, droppers, binaries).
* **Data Transport:** Real-time synchronization of logs and artifacts to an **AWS S3** bucket via **Vector** and the **AWS API**.

### 2. The Panoptik Engine (Processing & Triage)

The "brain" of the system is a custom-built Python analysis orchestrator running **locally via Docker**.

* **Static Triage:** Automated extraction of file hashes, strings, and metadata.
* **Technical Attribution:** Integration of **Mandiant Capa** to map file capabilities to the **MITRE ATT&CK®** framework.
* **MalAPI Correlation:** Cross-referencing of Windows API imports against known malware techniques.
* **Orchestration:** The engine automatically downloads new samples from the S3 bucket, analyzes them in an isolated container, and outputs structured JSON results.

### 3. Intelligence Core & Enrichment (WIP)

* **Centralized Repository:** Future implementation of a **MISP** instance to correlate local sightings with external intelligence feeds.
* **API Enrichment:** Contextualization using **Shodan** and **GeoIP** to enrich raw IP data.
* **Deep Analysis:** Targeted **Reverse Engineering** of specific high-interest samples to extract advanced TTPs.

---

## 🔄 The CTI Intelligence Cycle

| Phase                       | Technical Implementation                                                                          |
|-----------------------------|---------------------------------------------------------------------------------------------------|
| **Planning and Direction**  | Identification of Intelligence Requirements (IRs) regarding priority telemetry needs.             |
| **Collection**              | Raw data gathering via Terraform-provisioned Droplets and AWS S3 synchronization.                 |
| **Processing**              | **Panoptik Engine** (Local Docker) automation for data normalization and triage.                  |
| **Analysis**                | Evaluation of technical attribution (MITRE ATT&CK) and manual Reverse Engineering.                |
| **Dissemination**           | Delivery of intelligence via structured JSON reports and future automated MISP/Blocklist exports. |
| **Feedback and Evaluation** | Ongoing assessment of intelligence utility to refine collection and tune analysis heuristics.     |

---

## 🛠️ Technical Stack

* **Languages:** Python 3.10+, PowerShell, Bash.
* **Infrastructure:** Terraform, AWS (S3), DigitalOcean.
* **Orchestration:** Docker (Local Analysis Engine).
* **Security Tools:** Mandiant Capa, PEFile, Libmagic.
* **Data Standards:** JSON, MITRE ATT&CK.

---

## 🚀 Roadmap

* [x] **Phase 1: Sensor Deployment** — Provisioned global multi-cloud honeypot nodes via Terraform.
* [x] **Phase 2: Panoptik Engine** — Built modular local orchestrator for automated triage.
* [ ] **Phase 3: Integration (Active)** — Finalizing the "Aegis Connector" to bridge Panoptik results into MISP.
* [ ] **Phase 4: Active Defense** — Engineering a dynamic blocklist exporter for automated firewall response.

---

## 👨‍💻 Author

**Jefferson Andrade**
*Cyber Threat Intelligence Researcher | Geopolitical & Strategic Analysis | OSINT*

---