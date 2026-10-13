# Technical Invention & Experimentation Log

**Project**: AI Cyber Threat Intelligence & Automated Response Platform  
**Contributors**: Aastha, Nidhi, Radhika, Swanandi  
**Date**: October 13, 2026  

---

## 1. Problem Addressed

Modern Security Operations Centers (SOCs) face alert fatigue resulting from disconnected security tools. Individual detectors (e.g., WAF, firewall, auth gateways) trigger isolated notifications without unified context. Specific operational limitations include:
1. **Adversary IP Rotation**: Attackers regularly shift egress IP addresses (via proxies or VPNs), causing traditional IP-centric correlation systems to fragment a single intrusion into disconnected incidents.
2. **Uncalibrated Risk Inflation**: Alert aggregators often sum raw severity scores, causing repetitive noisy alerts to inflate incident risk scores arbitrarily.
3. **Decay without Preservation**: Standard exponential alert decay mechanisms can inadvertently erase critical evidence of serious deception traps or initial compromise.
4. **Lack of Explainability**: Alert dashboards rarely provide human-readable, fact-based justifications of how an incident was grouped and scored.

---

## 2. Technical Approach & What Was Actually Implemented

To address these challenges within a lightweight, explainable academic prototype, the following architecture was constructed and verified:

1. **Multi-Vector Detection Suite**:
   - *Phishing URL Classifier*: Scikit-learn Random Forest model trained on lexical and structural features (URL length, domain entropy, sensitive keywords, raw numerical IP detection).
   - *Login Threat Detector*: Sliding-window state machine detecting brute-force bursts and suspicious credential-stuffing sequences (failures followed immediately by success).
   - *Port-Scan Detector*: Sliding-window connection counter tracking unique destination ports and targets with automated deduplication.
   - *Web-Attack Detector*: Deterministic signature matching for SQL injection, XSS, and Path Traversal with strict HTML sanitization.
   - *Honeytoken Deception Detector*: Controlled canary traps with automatic sensitive value masking.

2. **NetworkX Graph-Assisted Correlation**:
   - Entities (IPs, User accounts, Targets, Honeytokens) and Alerts are modeled as nodes in a NetworkX graph.
   - Edges represent verified interactions (`AUTHENTICATED_AS`, `ACCESSED_CANARY`, `TARGETED`, `TRIGGERED`).
   - Enables multi-hop correlation where activity across rotating IP addresses is connected through shared user credentials and decoy canary interactions.

3. **Deterministic Bounded Risk Scoring & Floor-Preserved Decay**:
   - Bounded risk score ($0$ to $100$) with diminishing returns for repeated detector types.
   - Half-life exponential time decay coupled with an immutable **Critical Evidence Preservation Floor** ($\ge 40.0$ for honeytokens) preventing premature threat de-escalation.

4. **Factual 7-Section Narrative Synthesizer**:
   - Chronological incident reporting strictly derived from stored database records without LLM hallucination or invented attacker motives.

5. **Audited Simulated Response**:
   - Non-destructive dry-run execution (`SIMULATE_BLOCK_IP`, `SIMULATE_DISABLE_ACCOUNT`, `CONTAIN_INCIDENT`) recording immutable audit trails in PostgreSQL.

---

## 3. Experimental Methodology & Measured Results

### Experiment 1: IP-Rotation Campaign Continuity
- **Objective**: Measure whether an adversary shifting IP addresses can be tracked across detection phases.
- **Dataset**: Synthetic multi-phase attack scenario (`data/sample_events/ip_rotation_scenario.json`).
  - Phase 1: IP `198.51.100.45` executes SQLi against login service.
  - Phase 2: IP `203.0.113.88` activates canary honeytoken targeting account `admin_svc`.
- **Results**:
  - *Baseline Correlation (IP-only grouping)*: Split Phase 1 and Phase 2 into **2 disconnected incidents**. Missed the unified intrusion.
  - *Graph-Assisted Correlation*: Evaluated shared node `user_admin_svc` and canary edge; successfully merged both phases into **1 unified Critical incident**.
  - *Latency*: Graph traversal and incident linking executed in **< 15 milliseconds** on SQLite/PostgreSQL.

### Experiment 2: Diminishing Returns & Score Inflation
- **Objective**: Verify that flooding identical alerts does not inflate risk scores beyond realistic bounds.
- **Dataset**: 20 consecutive repeated login alerts from the same origin.
- **Results**:
  - Unbounded summation: Raw score exceeds 500 (uncalibrated).
  - Our implemented bounded algorithm: 1st alert receives 100% weight, 2nd receives 50%, subsequent receive 20%. Score ceiling strictly capped at 100.0, resulting in an accurate High-risk tier without numeric overflow.

### Experiment 3: Exponential Decay with Evidence Protection Floor
- **Objective**: Verify time decay behavior on aging alerts.
- **Results**:
  - At $\Delta t = 24$ hours (1 half-life): Raw alert score halved ($\times 0.50$).
  - At $\Delta t = 48$ hours (2 half-lives): Honeytoken trigger preserved at minimum $40.0$ score floor, ensuring historical audit integrity.

---

## 4. Prior-Art & Known Approaches Investigated

- **SIEM Alert Correlation (e.g., Splunk, Elastic SIEM)**: Typically relies on SQL-style join rules or fixed window grouping on single keys (`src_ip`). Vulnerable to IP rotation unless complex entity resolution schemas are manually configured.
- **Deception Technology (e.g., Canary Tokens)**: Highly effective for zero-false-positive alerts, but often siloed from general SOC correlation engines.
- **Graph Neural Networks (GNNs) for Threat Detection**: Academic literature proposes GNNs for threat graphs; however, they require massive labeled training datasets, introduce latency, and lack the explainability of deterministic NetworkX graph algorithms.

---

## 5. Limitations & Future Research

1. **Proxy & NAT Ambiguity**: If multiple legitimate users share a NAT gateway or corporate egress IP, simple IP correlation could over-group unrelated alerts. Future iterations should incorporate browser fingerprints or TLS session identifiers.
2. **Deterministic Signatures**: Web-attack signatures catch known attack patterns but may be bypassed by novel zero-day obfuscation techniques.
3. **Synthetic Evaluation Dataset**: Testing was conducted on deterministic synthetic fixtures. Validation against enterprise DARPA TC or PCAP datasets is planned for subsequent academic phases.
