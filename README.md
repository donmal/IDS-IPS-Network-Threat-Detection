# IDS/IPS Network Threat Detection
| Hack-the-Box Academy |

## Project Overview

This repository documents a series of practical cybersecurity investigations focused on detecting suspicious network activity, developing and validating intrusion detection signatures, and extracting actionable evidence from packet captures (PCAPs). The work combines **Suricata** and **Snort** for rule-based intrusion detection with **Zeek** for protocol-aware network security monitoring and forensic analysis.

The investigations were completed in a controlled Hack The Box Academy lab environment and are presented as reproducible, evidence-led case studies relevant to **SOC Analyst**, **Blue Team**, and **Detection Engineering** workflows.

> **Scope:** This portfolio demonstrates offline PCAP analysis and IDS rule validation. It does not claim that a production inline IPS deployment, successful exploitation, malware execution, or data exfiltration was independently confirmed unless explicitly supported by the corresponding investigation evidence.

## Investigation Portfolio

| Section | Investigation | Focus | Key validated result |
| --- | --- | --- | --- |
| **01** | [Suricata Detection Engineering](01-Suricata-Detection-Engineering/README.md) | Custom signatures, SMB exploitation patterns, TLS JA3 fingerprints, and WMI-related traffic | MS17-010 `offset:4`; Trickbot JA3 `72a589da586844d7f0818ce684948eea`; WMI match keyword `Create` |
| **02** | [Snort Intrusion Detection & Attack Signatures](02-Snort-Intrusion-Detection-and-Attack-Signatures/README.md) | HTTP header inspection, Log4Shell payload detection, Kerberos ASN.1/RC4 byte matching | Log4Shell sticky buffer `http_header`; RC4 etype 23 encoded as hex `17` |
| **03** | [Zeek Network Security Monitoring & Exploit Investigation](03-Zeek-Network-Security-Monitoring-and-Exploit-Investigation/README.md) | PrintNightmare DCE/RPC analysis, REvil/Kaseya connection accounting, Neutrino/Gootkit certificate inspection | `dce_rpc.log`; **2,311** outbound originator bytes; `certificate.subject` |

**Investigation Note**: Each section documents a separate set of laboratory scenarios. Findings are based on the available PCAPs, IDS alerts, and network telemetry; they should not be interpreted as evidence of a single continuous intrusion.

## Objectives

- Investigate suspicious network activity using recorded PCAP evidence.
- Understand the differences between **signature-based detection** and **protocol-aware network telemetry**.
- Create, adjust, and test IDS rules against representative traffic captures.
- Identify relevant protocol buffers, binary patterns, byte offsets, and TLS fingerprints.
- Extract, filter, and correlate Zeek logs to answer concrete investigation questions.
- Record evidence, limitations, and follow-up detection opportunities in a clear analyst report.

## Tools and Technologies

| Category | Tools / concepts | Application in this repository |
| --- | --- | --- |
| Intrusion detection | **Suricata**, **Snort 3** | Signature inspection, rule tuning, offline PCAP replay, and alert validation |
| Network security monitoring | **Zeek** | Generate and investigate `conn.log`, `dce_rpc.log`, `dns.log`, `ssl.log`, and `x509.log` |
| Packet inspection | **Wireshark**, PCAP | Inspect Kerberos encryption types, hexadecimal bytes, and protocol context |
| Detection logic | `content`, `offset`, `http_header`, JA3, ASN.1 | Build or correct signatures against the intended traffic structures |
| CLI investigation | Linux shell, `grep`, `zeek-cut`, `sort`, `datamash`, `jq`, `nano` | Filter logs, extract fields, aggregate bytes, and review rules |
| Lab access | SSH, SCP | Access the lab host and transfer PCAPs for local inspection |

## Investigation Highlights

### 01 — Suricata Detection Engineering

**EternalBlue / MS17-010:** Investigated SMB exploit-related traffic and adjusted the `offset` of signature SID `2024217`. The recorded test identified **`offset:4`** as the minimum validated value that produced the expected alert in the lab.

**Detection Context**: The validated offset applies to the tested signature and packet capture. It should not be treated as a universal offset for detecting MS17-010 exploitation across different Suricata rules or network environments.

**Trickbot TLS / JA3:** Extracted the JA3 digest **`72a589da586844d7f0818ce684948eea`**, updated the corresponding rule, and reviewed matching alerts on multiple observed destination ports. A JA3 match is a fingerprinting indicator, not proof of maliciousness by itself.

**WMI-related traffic:** Updated a Suricata rule with the keyword **`Create`** and validated the resulting **WMI Execution Detected** alert. The network signature does not independently prove that a remote process executed on an endpoint.

[Read the Suricata investigation](01-Suricata-Detection-Engineering/README.md)

### 02 — Snort Intrusion Detection & Attack Signatures

**Log4Shell:** Activated a local Snort rule and applied the **`http_header;`** sticky buffer before the content match so JNDI-style payloads could be detected within HTTP request headers, including `User-Agent` and `Authorization`.

**Detection Context**: Identifying a JNDI-style payload in HTTP traffic indicates a potential exploitation attempt. It does not independently confirm that the target application was vulnerable or that remote code execution succeeded.

**Kerberos RC4 detection:** Inspected `wannamine.pcap` in Wireshark, identified Kerberos encryption type **23 (RC4-HMAC)**, and replaced the placeholder in `|A0 03 02 01 XX|` with hexadecimal **`17`**. A matching byte sequence is an investigative indicator and is not, on its own, confirmation of Overpass-the-Hash.

[Read the Snort investigation](02-Snort-Intrusion-Detection-and-Attack-Signatures/README.md)

### 03 — Zeek Network Security Monitoring & Exploit Investigation

**PrintNightmare:** Parsed the capture with Zeek and identified spooler-related DCE/RPC activity in **`dce_rpc.log`**, including the `\\pipe\\spoolss` named pipe and `RpcAddPrinterDriverEx` calls.

**Detection Context**: These RPC artifacts are relevant to investigating potential PrintNightmare exploitation, but the presence of spooler-related RPC calls alone does not confirm successful exploitation.

**REvil/Kaseya:** Correlated connection records for victim **`192.168.100.154`** communicating with **`178.23.155.240`**. Summing `orig_bytes` across the two observed connections (**1,702 + 609**) yielded **2,311 bytes transmitted**. This is a directional traffic-volume measurement, not proof of data exfiltration.

**Neutrino/Gootkit:** Examined `x509.log` and identified **`certificate.subject`** as the field containing **`MyCompany Ltd`** in the certificate distinguished name.

[Read the Zeek investigation](03-Zeek-Network-Security-Monitoring-and-Exploit-Investigation/README.md)

## Detection and Investigation Workflow

```text
Recorded network traffic (.pcap)
             |
             v
    Identify relevant protocol
             |
       +-----+------+
       |            |
       v            v
 Suricata / Snort   Zeek
 Signature matching Protocol parsing
       |            |
       v            v
 Alerts / rule SIDs Structured .log files
       |            |
       +-----+------+
             |
             v
 Validate against packet / log evidence
             |
             v
 Document findings, caveats, and next steps
```
This workflow emphasizes validation of detection results against the underlying network evidence before drawing conclusions about attacker activity or exploitation outcomes.

## Repository Structure

```text
IDS-IPS-Network-Threat-Detection/
├── README.md
├── 01-Suricata-Detection-Engineering/
│   ├── README.md
│   └── images/
├── 02-Snort-Intrusion-Detection-and-Attack-Signatures/
│   ├── README.md
│   └── images/
└── 03-Zeek-Network-Security-Monitoring-and-Exploit-Investigation/
    ├── README.md
    └── images/
```

Each section contains a detailed technical report with investigation objectives, methodology, commands, evidence references, findings, and detection considerations. Screenshots are stored alongside their respective investigation and referenced using relative paths.

## Key Skills Demonstrated

| Skill | Evidence from the investigations |
| --- | --- |
| Signature development and tuning | Suricata offsets and content matching; Snort HTTP sticky buffers and Kerberos byte patterns |
| Protocol-aware analysis | SMB, DCE/RPC, HTTP headers, TLS, Kerberos, X.509 certificates |
| Network forensic triage | PCAP replay, Wireshark hex inspection, Zeek log selection and filtering |
| Traffic accounting | Directional `orig_bytes` aggregation from `conn.log` |
| Detection validation | Matching alerts and log entries back to their relevant rules and traffic |
| Evidence-based reporting | Documented investigation findings, supporting technical evidence, and explicit analytical limitations |

The investigations also demonstrate the importance of distinguishing between observed network activity, signature matches, suspected attacker techniques, and independently confirmed outcomes.

## Security and Evidence Notes

- All exercises were conducted in an **authorized training environment**.
- IP addresses, hostnames, and sample identifiers are retained only where relevant to the provided lab evidence.
- Original PCAPs and potentially restricted lab materials are **not included** in this repository.
- Network indicators must be interpreted in context: **a rule match, an RPC call, an RC4 etype, or a certificate string alone does not prove compromise**.
- The investigations emphasize **detection and analysis**; inline IPS prevention was not tested as part of the documented results.

## Conclusion

Together, these three sections demonstrate a practical progression from **building and validating network detection signatures** to **investigating protocol-level evidence and structured network logs**. The central approach is consistent across the repository: select the right telemetry, inspect the underlying traffic, validate the finding, and communicate both the result and its limitations.

From a SOC analyst perspective, these exercises reinforced the importance of selecting appropriate network telemetry, developing targeted detection logic, validating alerts against packet-level evidence, and documenting findings without overstating the conclusions supported by the available data.

---

**Focus areas:** SOC Operations · Blue Team · Network Security Monitoring · Intrusion Detection · Detection Engineering · PCAP Analysis

