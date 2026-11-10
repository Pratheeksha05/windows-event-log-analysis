# Windows Event Log Analysis Using Python

## Project Overview

This project focuses on analyzing Windows Security Event Logs to identify and understand authentication activities, including successful and failed login attempts.

Python is used to parse exported Windows Event Logs in XML format, extract important security information, summarize authentication activity, and detect potential brute-force login patterns.

The project demonstrates basic Windows log analysis and security monitoring concepts relevant to a Security Operations Center (SOC) Analyst role.

## Technologies Used

- **Operating System:** Windows 11
- **Programming Language:** Python 3
- **Code Editor:** Visual Studio Code
- **Log Source:** Windows Security Event Logs
- **Data Formats:** EVTX, XML, CSV
- **Python Libraries:**
  - `xml.etree.ElementTree` – XML parsing
  - `csv` – CSV report generation
  - `collections.Counter` – Event counting and summaries
  - `datetime` – Timestamp processing and time-window analysis

## Windows Event IDs Analyzed

| Event ID | Description |
|---|---|
| 4624 | Successful Logon |
| 4625 | Failed Logon |

## Key Features

- Extracts successful and failed Windows logon events.
- Parses XML-formatted Windows Security Event Logs.
- Extracts usernames, timestamps, logon types, source IP addresses, and process information.
- Summarizes authentication activity.
- Groups failed logons by username and source IP.
- Analyzes authentication activity by logon type.
- Detects potential brute-force login patterns.
- Generates a CSV security report for further analysis.

## Brute-Force Detection Logic

The project implements a basic brute-force detection mechanism using a configurable time window.

**Detection rule:**
- Monitors failed login attempts by source IP address.
- Identifies 5 or more failed login attempts within a 5-minute window.
- Generates a High severity alert when the threshold is reached.

The threshold is an educational project rule and can be adjusted depending on monitoring requirements.

## Project Implementation

1. Collected Windows Security Event Logs using Windows Event Viewer.
2. Filtered authentication events using Event IDs 4624 and 4625.
3. Exported the filtered events in EVTX format.
4. Converted the exported event logs into XML using the Windows `wevtutil` command.
5. Developed a Python script to parse and extract event information.
6. Classified successful and failed authentication events.
7. Generated authentication activity summaries.
8. Implemented a five-minute sliding-window brute-force detection mechanism.
9. Exported analyzed event records into a CSV security report.
10. Tested the detection logic using simulated failed login events.

## Results

The collected Windows Security Event Logs produced the following results:

| Metric | Result |
|---|---:|
| Successful Logon Events | 718 |
| Failed Logon Events | 1 |
| Total Events Analyzed | 719 |
| Interactive Logons (Type 2) | 70 |
| Service Logons (Type 5) | 647 |
| Other/Unknown Logons (Type 0) | 2 |

### Failed Logon Analysis

- **Username:** [redacted local account]
- **Source IP:** 127.0.0.1
- **Logon Type:** Interactive (Type 2)
- **Failure Status:** 0xC000006D
- **Failure SubStatus:** 0xC000006A

The failed login was generated intentionally during a controlled local testing exercise. It represents an incorrect password attempt, not evidence of a real attack.

### Brute-Force Detection Testing

- Actual collected logs: No brute-force activity detected.
- Simulated test: Successfully detected 5 failed login attempts from a test IP address within 5 minutes.
- Alert Severity: High.

## Output

The Python script generates:

`security_report.csv`

The report contains extracted event details, including:

- Event ID
- Timestamp
- Username
- Logon Type
- Source IP
- Status and SubStatus
- Workstation
- Process Name
- Event Classification

## How to Run the Project

### Prerequisites

- Windows operating system
- Python 3 installed
- Visual Studio Code or another Python editor

### Steps

1. Export Windows Security Event Logs using Event Viewer.
2. Convert the exported EVTX files into XML using `wevtutil`.
3. Place the XML files in the project directory.
4. Open the project directory in Visual Studio Code.
5. Run the Python script:

```bash
python analyze_logs.py
```

6. View the authentication summaries in the terminal.
7. Open `security_report.csv` to inspect the analyzed records.

## Project Limitations

- This project analyzes exported Windows Event Logs rather than monitoring events in real time.
- The brute-force detection threshold is configurable and intended for educational demonstration.
- Detection is based on failed login frequency by source IP and does not establish whether an IP address is malicious.
- The analysis is limited to the collected Windows Security Event Logs.

## Skills Demonstrated

- Windows Event Log Analysis
- Authentication Monitoring
- Python Scripting
- XML Parsing
- CSV Report Generation
- Brute-Force Detection Logic
- Security Event Investigation
- Basic SOC Analysis

## Disclaimer

This project was developed for educational and cybersecurity learning purposes. Testing was performed using locally generated Windows Security Events and simulated data. No unauthorized access or attacks were performed.
