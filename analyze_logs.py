import xml.etree.ElementTree as ET
import csv
from datetime import datetime, timedelta
from collections import Counter


NAMESPACE = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

def read_events(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        xml_data = file.read()

    root = ET.fromstring(f"<Events>{xml_data}</Events>")

    return root.findall("ns:Event", NAMESPACE)

failed_events = read_events("failed_logons.xml")
successful_events = read_events("successful_logons.xml")

print("\nTotal successful logon events:", len(successful_events))

print("Total failed logon events:", len(failed_events))

def extract_event_data(event):
    event_id = event.find("ns:System/ns:EventID", NAMESPACE).text

    time_created = event.find(
        "ns:System/ns:TimeCreated", NAMESPACE
    ).attrib["SystemTime"]

    event_data = {}

    for item in event.findall("ns:EventData/ns:Data", NAMESPACE):
        event_data[item.attrib["Name"]] = item.text

    return {
        "EventID": event_id,
        "TimeCreated": time_created,
        "Username": event_data.get("TargetUserName", "N/A"),
        "LogonType": event_data.get("LogonType", "N/A"),
        "SourceIP": event_data.get("IpAddress", "N/A"),
        "Status": event_data.get("Status", "N/A"),
        "SubStatus": event_data.get("SubStatus", "N/A"),
        "Workstation": event_data.get("WorkstationName", "N/A"),
        "ProcessName": event_data.get("ProcessName", "N/A")
    }

print("\nExtracted Event Details:")

for event in failed_events:
    details = extract_event_data(event)

    for key, value in details.items():
        print(f"{key}: {value}")

def classify_event(event_details):
    if event_details["EventID"] == "4625":
        return "Failed Logon"

    elif event_details["EventID"] == "4624":
        return "Successful Logon"

    else:
        return "Other Event"

print("\nEvent Classification:")

for event in failed_events:
    details = extract_event_data(event)
    classification = classify_event(details)

    print(f"{details['EventID']} - {classification}")

all_events = failed_events + successful_events

event_records = []

for event in all_events:
    details = extract_event_data(event)
    details["Classification"] = classify_event(details)
    event_records.append(details)

classification_counts = Counter(
    record["Classification"] for record in event_records
)

print("\nAuthentication Activity Summary:")
print("Successful Logons:", classification_counts["Successful Logon"])
print("Failed Logons:", classification_counts["Failed Logon"])
print("Total Events:", len(event_records))

failed_usernames = [
    record["Username"]
    for record in event_records
    if record["Classification"] == "Failed Logon"
]

username_counts = Counter(failed_usernames)

print("\nFailed Logons by Username:")

for username, count in username_counts.items():
    print(f"{username}: {count}")

failed_ips = [
    record["SourceIP"]
    for record in event_records
    if record["Classification"] == "Failed Logon"
]

ip_counts = Counter(failed_ips)

print("\nFailed Logons by Source IP:")

for ip, count in ip_counts.items():
    print(f"{ip}: {count}")

logon_type_names = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "10": "RemoteInteractive (RDP)"
}

logon_type_counts = Counter(
    record["LogonType"] for record in event_records
)

print("\nLogon Activity by Type:")

for logon_type, count in logon_type_counts.items():
    name = logon_type_names.get(logon_type, "Other/Unknown")
    print(f"Type {logon_type} - {name}: {count}")

failed_logon_types = Counter(
    record["LogonType"]
    for record in event_records
    if record["Classification"] == "Failed Logon"
)

print("\nFailed Logons by Logon Type:")

for logon_type, count in failed_logon_types.items():
    name = logon_type_names.get(logon_type, "Other/Unknown")
    print(f"{name}: {count}")

def detect_brute_force(records):
    failed_records = [
        record for record in records
        if record["Classification"] == "Failed Logon"
    ]

    ip_events = {}

    for record in failed_records:
        ip = record["SourceIP"]

        timestamp = datetime.fromisoformat(
            record["TimeCreated"].replace("Z", "+00:00")
        )

        ip_events.setdefault(ip, []).append(timestamp)

    alerts = []

    for ip, timestamps in ip_events.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end = window_start + timedelta(minutes=5)

            attempts = [
                timestamp for timestamp in timestamps
                if window_start <= timestamp <= window_end
            ]

            if len(attempts) >= 5:
                alerts.append({
                    "SourceIP": ip,
                    "FailedAttempts": len(attempts),
                    "Severity": "High"
                })
                break

    return alerts

brute_force_alerts = detect_brute_force(event_records)

print("\nBrute Force Detection Results:")

if brute_force_alerts:
    for alert in brute_force_alerts:
        print(
            f"ALERT: IP {alert['SourceIP']} - "
            f"{alert['FailedAttempts']} failed attempts - "
            f"Severity: {alert['Severity']}"
        )
else:
    print("No brute-force activity detected.")

# Generate CSV Security Report

fieldnames = [
    "EventID",
    "TimeCreated",
    "Username",
    "LogonType",
    "SourceIP",
    "Status",
    "SubStatus",
    "Workstation",
    "ProcessName",
    "Classification"
]

with open("security_report.csv", "w", newline="", encoding="utf-8") as csvfile:

    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()

    writer.writerows(event_records)

print("\nSecurity report generated: security_report.csv")