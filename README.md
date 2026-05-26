### Project Aegis

**Automated Malware Collection, Processing, and Intelligence Orchestration**

Project Aegis is a technical pipeline designed to automate the collection of malware samples and attacker telemetry. It leverages Infrastructure-as-Code to deploy a sensor, offloads captured data to a cloud evidence locker, and processes raw payloads into secure forensics formats to aid cyber threat investigation efforts.

#### Core Architecture

**1. The Sensor Network (Collection)**

* **Infrastructure-as-Code (IaC):** Terraform is used to provision and manage the honeypot node on DigitalOcean.
* **Honeypot Node:** Droplet configured with Cowrie to capture SSH authentication attempts, TTY logs, and malware payloads (scripts, droppers, binaries).
* **Data Transport:** Synchronization of logs and artifacts to an AWS S3 bucket via Vector and the AWS API.

**2. The Forensics Processing Engine**
The core processing system is a custom-built Python orchestrator running serverless via AWS Lambda.

* **Forensics Data Generation:** Raw malware samples and payloads are processed in an isolated ephemeral environment and automatically converted into `.ISO` files for safe handling and subsequent analysis.

**3. Intelligence Core & Enrichment**

* **Threat Intelligence Platforms (TIP):** Enrichment of dropped malware and indicators by correlating local sightings with external intelligence feeds.
* **API Contextualization:** Utilizing GeoIP to enrich raw IP data.
* **Actionable Output:** Generation of dynamic blocklists for direct defensive integration.

---

#### The CTI Intelligence Cycle

| Phase                       | Technical Implementation                                                                                                     |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|
| **Planning and Direction**  | Identification of Intelligence Requirements (IRs) regarding priority telemetry needs.                                        |
| **Collection**              | Raw data gathering via Terraform-provisioned Droplets and AWS S3 synchronization.                                            |
| **Processing**              | AWS Lambda automation for converting raw payloads into secure `.ISO` forensics files.                                        |
| **Analysis**                | Extraction of attacker TTPs from honeypot telemetry and contextualized threat intelligence.                                  |
| **Dissemination**           | Public sharing of Cowrie honeypot datasets via secure Proton Drive links, automated Blocklist exports, and AlienVault pulse. |
| **Feedback and Evaluation** | Ongoing assessment of intelligence utility to refine collection and tuning.                                                  |

---

#### Community Intelligence Sharing

As part of the commitment to active defense and community collaboration, processed data from the Cowrie honeypot is shared for research and analysis.

* **Data Access:** [Proton Drive Secure Link](https://drive.proton.me/urls/CB4640NPVW#RcGTvYu1Lnvk)
* **Archive Password:** `Aegis-Intel!`

---

#### Technical Stack

* **Languages:** Python 3.10+, Bash.
* **Infrastructure:** Terraform, AWS (S3, Lambda, IAM), DigitalOcean.

---

#### Roadmap

* **Phase 1: Sensor Deployment** — Provisioned global multi-cloud honeypot and blocklist nodes via Terraform.
* **Phase 2: Forensics Engine** — Built serverless orchestrator for automated `.ISO` generation and data handling.
* **Phase 3: Integration** — Bridging collected data with Threat Intel Platforms for dropped malware enrichment.
* **Phase 4: Active Defense (Ready, project concluded)** — Engineering a dynamic blocklist exporter for automated firewall response.

**Author**
Jefferson Andrade
*Cyber Threat Intelligence Researcher | Geopolitical & Strategic Analysis | OSINT*