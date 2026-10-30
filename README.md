# DNS Steganography & Covert Channel Analyzer
### An Educational Network Security Simulation & Traffic Analysis Lab for Computer Networks Coursework

[![Node.js Version](https://img.shields.io/badge/node.js-v18%2B-green.svg)](https://nodejs.org)
[![RFC Standard](https://img.shields.io/badge/RFC-1035%20DNS-cyan.svg)](https://datatracker.ietf.org/doc/html/rfc1035)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Simulation Status](https://img.shields.io/badge/Security-Local%20Simulation%20Only-emerald.svg)](#important-safety-and-ethical-disclaimer)

---

## 📌 Project Overview

**DNS Steganography & Covert Channel Analyzer** is an educational, lab-based web platform designed to demonstrate fundamental computer networking concepts, DNS packet dissection, covert communications, Shannon entropy calculations, and rule-based anomaly detection.

In enterprise and academic computer networks, the **Domain Name System (DNS, RFC 1035)** operates over **UDP port 53** to translate human-readable domain names into IP addresses. Because DNS resolution is critical for standard network operations, DNS traffic is routinely permitted through firewalls and network address translation (NAT) devices with minimal egress filtering. Consequently, covert channel mechanisms and data exfiltration techniques frequently abuse DNS queries to hide data in domain labels.

This project simulates how secret messages can be encoded, segmented into DNS-compliant labels, transmitted through a synthetic network pipeline, analyzed for anomalous deviations against benign baseline traffic, and reconstructed at the receiver.

> 🔒 **Important Safety & Ethical Disclaimer:**
> This tool is strictly a **local in-memory simulation / laboratory analyzer**. It does **NOT** transmit packets over the public Internet, query external DNS resolvers, or perform real-world malware, persistence, or data exfiltration. All operations are confined to simulated objects and local educational visualizations.
>
> Prominently displayed: **SIMULATED — NO REAL DNS REQUEST SENT** and **SIMULATION MODE ONLY**.

---

## 🏗️ Project Architecture

```text
User Input (Secret Plaintext Message)
       ↓
Web Interface (HTML5, Glassmorphism CSS3, Modular ES6 JS)
       ↓
Encoding Engine (Base64, Hexadecimal, Binary, Base32 + Chunking)
       ↓
DNS Traffic Simulator (RFC 1035 Datagram Modeling + Paired Response Generator)
       ↓
Packet Generator (Transaction IDs, Flags, Question Section, Wire Hex Octets)
       ↓
Network Protocol Stack (L7 DNS, L4 UDP, L3 IPv4, L2 Ethernet II)
       ↓
Traffic Analyzer (Shannon Character Entropy, Subdomain Length, Unusual Chars)
       ↓
Detection Engine (Transparent Rule-Based Suspicion Scoring: 0–100)
       ↓
Visualization Dashboard (Dissector Tree, Resolution Trace, Side-by-Side Comparison Charts, Packet Log)
```

---

## 🚀 Key Features

### 1. Realistic Simulated DNS Domains
- **Configurable Base Domain**: Set the target domain (default: `example.com`).
- **Quick-Select Presets**: `example.com`, `example.net`, `example.org`, `tunnel.example` — reserved documentation domains (RFC 2606). A real covert channel only works when the queries reach an authoritative nameserver the *receiver* controls, so simulated covert traffic never uses real brand domains.
- **Query Format**: Formatted as `pkt01-<chunk>.example.com` (e.g. `pkt01-Q09NUFVURVIgTkVUV09SS1MgUFJPSkVDVA.example.com`).
- **DNS-Valid Labels**: Every label uses only letters, digits, `-` and `_`, and stays within 63 octets. Base64 uses the URL-safe alphabet (RFC 4648 §5) without `=` padding, because `+`, `/` and `=` are not valid in hostname labels. Base64 is still case-sensitive while DNS is case-insensitive — one reason real-world DNS tunnels prefer Base32 or hex.
- **Safety Labeling**: Prominently displays `SIMULATED — NO REAL DNS REQUEST SENT`.

### 2. Simulated DNS Resolution Flow (Visual Computer Networks Model)
- Step-by-step visual animation demonstrating iterative and recursive DNS resolution:
  $$\text{Client} \xrightarrow{\text{QUERY SENT}} \text{DNS Resolver} \xrightarrow{\text{FORWARDING}} \text{Root DNS (.)} \xrightarrow{\text{TLD REFERRAL}} \text{TLD DNS (.com)} \xrightarrow{\text{AUTH REFERRAL}} \text{Authoritative DNS} \xrightarrow{\text{ANSWER}} \text{DNS Response} \xrightarrow{\text{RESOLVED}} \text{Client}$$
- Animated packet indicators and live status tags (`QUERY SENT`, `FORWARDING`, `AUTHORITY FOUND`, `RESPONSE RECEIVED`).

### 3. Paired DNS Request & DNS Response Inspection
- **DNS Request**: Transaction ID, Flags (`0x0100`, QR=0, RD=1), QDCOUNT, QNAME, QTYPE, QCLASS.
- **DNS Response**: Matching Transaction ID, Response Flags (`0x8180`, QR=1, AA=1, RA=1, RCODE=0), QDCOUNT, ANCOUNT=1, QNAME, QTYPE, QCLASS, and Simulated Answer (fictional RFC 5737 TEST-NET address e.g. `192.0.2.14`).
- **Visual Flow**: `DNS Query (Client) ➔ DNS Server ➔ DNS Response (Server)`.
- **RFC 1035 Dissector**: Interactive tree breakdown of header bitfields (QR, Opcode, AA, TC, RD, RA, Z, RCODE) and wire-format hex dump.

### 4. Interactive Network Protocol Stack
- Explores encapsulation across the 4 core layers of Computer Networking:
  1. **Application Layer (L7)**: DNS (RFC 1035) — Payload encapsulation in domain labels.
  2. **Transport Layer (L4)**: UDP (RFC 768) — 8-byte UDP header, destination port 53, connectionless datagram.
  3. **Internet Layer (L3)**: IPv4 (RFC 791) — 20-byte IP header, Protocol 17, source host to resolver.
  4. **Network Access Layer (L2)**: Ethernet II / Wi-Fi (IEEE 802.3/802.11) — MAC framing and EtherType `0x0800`.
- Click on any layer card to inspect header fields and see what happens to the packet at that stage.

### 5. Packet Loss Simulation & Resilient Decoder
- **Packet Loss Rate Slider**: Adjust packet loss rate from `0%` to `30%` (step 5%).
- Packets are randomly marked as `DELIVERED` or `LOST`.
- **Packet Loss Diagnostics**:
  - `Packets Generated: X | Packets Delivered: Y | Packets Lost: Z`
  - When packet loss occurs, the decoder detects missing sequence numbers (e.g. `Missing packets: 02, 05`).
  - Displays **`Reconstruction Status: FAILED`** when required chunks are dropped.
  - Displays **`Reconstruction Status: SUCCESS`** when all packets arrive.
  - Demonstrates UDP connectionless unreliability and its impact on covert channel integrity.

### 6. Anomaly Detection & Scoring Engine
- Computes statistical indicators:
  - **Shannon Character Entropy**:
    $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  - **Average Query & Subdomain Length**
  - **Unusual Character Ratio** (digits, uppercase/lowercase alternation, padding `=`)
  - **Payload-to-Domain Ratio**
  - **Non-Cached Query Stream Uniqueness**
- **Composite Suspicion Score (0–100)**:
  - `0 - 30`: Normal (Benign browsing)
  - `31 - 60`: Unusual (Minor structural deviations)
  - `61 - 80`: Potentially Suspicious (Elevated entropy, long labels)
  - `81 - 100`: Highly Suspicious (High-density covert payloads)
- **Explainable Diagnostics**: Detailed breakdown table showing each rule triggered, observed value, threshold, and points added.

### 7. Normal vs Covert Comparison Dashboard
- Side-by-side comparison against a small synthetic baseline of 15 typical benign queries (`data/sample-traffic.json`; hand-written to resemble ordinary traffic, not a real capture).
- Interactive Chart.js visual analytics:
  - Query Length Distribution Chart
  - Shannon Entropy Comparison Chart
  - Suspicion Score Breakdown Chart
  - Payload Size vs Protocol Overhead Doughnut Chart

### 8. Filterable Packet Log & Export
- Real-time tabular log of all simulated packets.
- Delivery status tracking (`DELIVERED` vs `LOST`).
- Live search by query name, chunk, delivery, or anomaly status.
- Sortable columns (Packet #, Delivery, Timestamp, Query Name, Length, Entropy).
- One-click **Export as CSV** or **Export as JSON**.
- One-click **Inspect** button to immediately examine any packet in the dissector.

---

## 📂 Repository Structure

```text
dns-steganography-tool/
│
├── server/
│   ├── server.js          # Express server with REST APIs & static file hosting
│   ├── simulator.js       # Synthetic RFC 1035 DNS packet modeler, Response generator & Protocol Stack
│   ├── encoder.js         # Base64, Hex, Binary, Base32 encoders & chunking logic
│   ├── decoder.js         # Query parser, chunk reassembler, & packet-loss detector
│   ├── detector.js        # Shannon entropy & rule-based anomaly detection engine
│   ├── scenarios.js       # Six deterministic, seeded replay scenarios for the Investigation Lab
│   ├── dataset.js         # Labelled synthetic dataset generator & stratified scenario split
│   └── evaluator.js       # Confusion-matrix metrics, threshold calibration, detector comparison
│
├── public/
│   ├── index.html         # Cybersecurity SOC dashboard layout
│   ├── style.css          # Glassmorphism dark theme & cyber styling
│   ├── script.js          # Client state controller, animations, & Chart.js renderer
│   └── chart.min.js       # Local Chart.js library (100% offline support)
│
├── data/
│   └── sample-traffic.json # Baseline normal DNS queries dataset (15 realistic queries)
│
├── tests/
│   ├── test-api.js        # Unit test suite (encoders, decoders, packets, responses, loss)
│   ├── test-server-integration.js # Integration test suite (all REST API endpoints)
│   ├── test-evaluation.js # Evaluation-lab metric tests
│   ├── test-scenarios.js  # Scenario replay tests
│   ├── test-ui-dom.js     # Headless click-test of every UI control
│   ├── test-fixes.js      # Regression tests: stratified split, DNS-valid labels, detector case handling
│   └── eval-multiseed.js  # Multi-seed evaluation summary (npm run eval:seeds)
│
├── package.json           # Node.js dependencies & execution scripts
└── README.md              # Project documentation & presentation guide
```

---

## ⚡ Quickstart & Installation

### Prerequisites
- **Node.js** (v18.0.0 or higher recommended)
- **npm** (bundled with Node.js)

### 1. Install Dependencies
In your terminal, navigate to the project directory:
```bash
npm install
```

### 2. Run Automated Tests
Verify all encoders, decoders, packet generators, responses, and packet loss detection:
```bash
npm test
```
*Expected Output:*
```text
--- Starting Automated Tests ---
[PASS] Round-trip encoding/decoding (base64): "COMPUTER NETWORKS PROJECT" -> "Q09NUFVURVIgTkVUV09S..." -> "COMPUTER NETWORKS PROJECT"
[PASS] Round-trip encoding/decoding (hex): "COMPUTER NETWORKS PROJECT" -> "434f4d5055544552204e..." -> "COMPUTER NETWORKS PROJECT"
[PASS] Round-trip encoding/decoding (binary): "COMPUTER NETWORKS PROJECT" -> "01000011010011110100..." -> "COMPUTER NETWORKS PROJECT"
[PASS] Round-trip encoding/decoding (base32): "COMPUTER NETWORKS PROJECT" -> "INHU2UCVKRCVEICOIVKF..." -> "COMPUTER NETWORKS PROJECT"
[PASS] Pipeline generated 5 chunks on google.com (Sample query: "pkt01-Q09NUFVU.google.com")   <- this unit test passes google.com explicitly
[PASS] Successfully reconstructed original message from chunked queries!
[PASS] Shannon Entropy: "google" = 1.918, "aGVsbG8xMjM0NTY3OA==" = 4.022
[PASS] RFC 1035 Simulated Packet generated: TxID=0xD35A, WireBytes=43
[PASS] Covert Stream Score: 90/100 (Highly Suspicious)
[PASS] Normal Traffic Score: 0/100 (Normal)
[PASS] Paired DNS Response generated: TxID=0xD35A, Answer=192.0.2.2
[PASS] Network Protocol Stack & Resolution Trace modeled (Layers: Application, Transport, Internet, Network Access)
[PASS] Packet Loss 0%: All 3 packets delivered, Reconstruction: SUCCESS
[PASS] Packet Loss Simulation: 1 packets lost, Missing: [04], Status: FAILED

>>> ALL 8 EXTENDED TEST SUITES PASSED CLEANLY! <<<
Test server running on port 3100
[PASS] GET /api/health: online
[PASS] POST /api/encode: 2 chunks generated
[PASS] POST /api/decode: Reconstructed "HELLO NETWORKS"
[PASS] POST /api/simulate: 3 synthetic packets modeled
[PASS] GET /api/normal-traffic: 15 baseline queries loaded
[PASS] POST /api/compare: 6 comparative metrics computed

>>> ALL END-TO-END SERVER INTEGRATION TESTS PASSED! <<<
Test server closed.
```

### 3. Start the Web Server
```bash
npm start
```
Open your web browser and navigate to:
```text
http://localhost:3000
```

---

## 🎓 College Demonstration Guide

Follow this walkthrough during an academic evaluation or lab presentation:

1. **One-Click Demo & Realistic Domain:**
   - Click the **"⚡ Run Demo"** button on the top navigation bar.
   - Note the default domain is `example.com`, generating queries like `pkt01-Q09NUFVURVIgTkVU.example.com`.
   - Observe the safety banner: **`SIMULATED — NO REAL DNS REQUEST SENT`**.
   - Watch the animated packet flow across the transmission pipeline and the **Simulated DNS Resolution Flow** (Client ➔ Resolver ➔ Root ➔ TLD ➔ Authoritative ➔ Response).

2. **Network Protocol Stack Layer Inspection:**
   - On the Dashboard, scroll to the **Network Protocol Stack** section.
   - Click each layer (Application/DNS, Transport/UDP, Internet/IPv4, Network Access/Ethernet) to demonstrate how protocol encapsulation works in Computer Networks.

3. **Packet Loss Simulation & UDP Unreliability:**
   - Navigate to the **Stego Simulator** tab.
   - Move the **Packet Loss** slider to `20%` and click **"Start Simulation"**.
   - Notice in the chunk list that dropped packets are marked with `LOST` and red strikethroughs.
   - Point out the **`Reconstruction Status: FAILED`** alert and the list of missing sequence numbers (e.g. `Missing packets: 03`).
   - Move the slider back to `0%` and rerun to show **`Reconstruction Status: SUCCESS`**.

4. **Inspect Paired DNS Request and DNS Response:**
   - Click the **Packet Inspector** tab.
   - Compare the **DNS Request** (QR=0, RD=1) and **DNS Response** (QR=1, AA=1, RA=1, Simulated Answer `192.0.2.x`).
   - Highlight that the Transaction ID in the Response matches the Request ID, as specified in RFC 1035.

5. **Explain Anomaly Detection & Defensive Heuristics:**
   - Click the **Anomaly Detection** tab.
   - Show how the **Shannon Entropy** calculation flags high-entropy labels ($H > 3.8\text{ bits/char}$) vs normal domains ($H \approx 2.4$).
   - Review the **Transparent Rule Contributions** table.

6. **Compare Normal vs Covert Traffic & Export Data:**
   - Switch to the **Traffic Comparison** tab to display the comparative charts (Query Length, Entropy, and Protocol Overhead).
   - Switch to the **Packet Log** tab, filter by `Delivered Only` or `Lost Only`, and click **"Export CSV"** to demonstrate SIEM log exports.

---

## 📊 Evaluation Methodology & Results

The Evaluation Lab compares two detectors on a **labelled synthetic dataset**:

- **Method A — Multi-feature rule-based detector**: subdomain length, Shannon entropy, binary-bitstream signature, unusual-character ratio and payload-to-domain ratio; score ≥ 50 ⇒ covert.
- **Method B — Entropy-only baseline**: entropy > threshold ⇒ covert, with the threshold calibrated (F1-maximising sweep) on a separate calibration set.

**Split:** samples are grouped into scenarios, and whole scenarios are assigned to either calibration or evaluation (no leakage). The split is **stratified by label**, so both the normal and covert classes always appear in both sets. (An unstratified split could leave the calibration set with only covert samples, which collapses the entropy threshold to its minimum.)

**Reporting:** a single seed contains only a handful of covert scenarios, so one run can be lucky or unlucky. Results are therefore reported as mean ± standard deviation over 20 seeds (`npm run eval:seeds`):

| Metric (20 seeds × 100 samples) | Rule-based (multi-feature) | Entropy-only baseline |
|---|---|---|
| Precision | 0.724 ± 0.095 | 0.417 ± 0.151 |
| Recall | 0.882 ± 0.164 | 0.742 ± 0.354 |
| F1-score | 0.791 ± 0.127 | 0.555 ± 0.185 |
| False-positive rate | 0.313 ± 0.086 | 0.843 ± 0.137 |

**Interpretation:** entropy alone cannot separate the classes, because low-entropy encodings (binary ≈ 2.2 bits/char, hex ≈ 3.1) overlap with legitimately high-entropy internal names (Kubernetes service records, LDAP SRV records, telemetry IDs ≈ 3.6–3.9). Combining several structural features raises F1 and cuts false positives substantially, but the false-positive rate is still around 30%, which illustrates why real deployments add context such as per-domain query volume, timing and reputation.

> These figures describe the synthetic scenarios only. They are not a claim about real-world detection performance.

---

## 🛡️ Defensive Mitigations in Real Networks

In enterprise networks, security teams employ several strategies to defend against covert DNS abuse:
- **Response Policy Zones (RPZ)**: DNS firewalls blocking high-entropy or recently registered domain patterns.
- **Deep Packet Inspection (DPI)**: Next-Generation Firewalls analyzing query length and burst frequency.
- **Egress Restriction**: Blocking direct outbound UDP/TCP 53 (and DNS-over-HTTPS endpoints) so clients cannot bypass the monitored resolver.
- **Domain Reputation & Volume Analytics**: Flagging a single parent domain that receives an unusually high number of unique subdomains.

> Note: **DNSSEC (RFC 4033)** is sometimes listed here by mistake. DNSSEC authenticates DNS *responses*; it does nothing to stop data being carried inside *query names*, so it is not a defence against DNS covert channels.
- **Internal Recursive Proxies**: Forcing all internal clients through monitored DNS resolvers with query-rate limits (QPS).

---

## 📄 License
This educational project is distributed under the MIT License. Designed for Computer Networks laboratory instruction and research.
