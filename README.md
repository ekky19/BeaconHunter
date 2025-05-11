# BeaconHunter
A PowerShell-based script to analyze network logs from CSV files and detect potential beaconing behavior. Supports VirusTotal integration for IP reputation checks.

Beaconing Detection Script Overview
Author: Ekrem Ozdemir
Compatible with Windows PowerShell 5.1 and above
________________________________________
🎯 Purpose
To analyze firewall logs or CSV-based network data and identify whether certain source-destination IP pairs are beaconing — i.e., communicating at consistent time intervals.
________________________________________
Common Use Case:
You're a SOC analyst reviewing outbound connections from internal assets. You want to quickly identify signs of C2 (Command and Control) beaconing—such as highly regular connection intervals or known malicious IPs—in your network telemetry. By feeding this script a properly formatted CSV export (from a SIEM, firewall, or proxy), you can automate detection and reputation checking in one go.
________________________________________
📁 Input
•	CSV file with at least 3 columns: Timestamp, SourceIP, DestinationIP
•	Can also support 7-column format with extra fields: SourcePort, DestinationPort, Asset, User

📊 CSV Format for BeaconHunter Script
| timestamp           | source_address  | source_port  | destination_address  | destination_port  | asset          | user    |
| ------------------- | --------------- | ------------ | -------------------- | ----------------- | -------------- | ------- |
| 1900-09-19T09:00:00 | 192.168.1.10    | 12345        | 8.8.8.8              | 123               | Server-01      | alice   |
________________________________________
⚙️ Script Logic
1. Environment Setup
-	Locates its own script folder
-	Sets output file in same folder using the CSV filename
2. CSV Processing
-   Skips header and summary rows (e.g., containing "All Values", or set your own word)
-	Handles both 3-column and 7-column CSV formats
-	Treats 4–6 columns as 3-column mode
3. Timestamp Parsing
-	Supports multiple timestamp formats like:
-	2025-05-06T08:00:00
-	2025-05-06T08:00:00.123Z
-	Invalid rows are skipped
4. Beaconing Detection Logic
-	Sorts communication events by timestamp
-	Calculates time differences (intervals) between events
-	Identifies the most common interval (mode)
-	Calculates percentage of intervals within ±10 seconds of the mode
-	If ≥80% of the intervals match → flagged as beaconing
5. Classification
-	If consistent pattern is found:
	✅ Marked as BEACONING DETECTED
-	If intervals are irregular or too few data points:
	⚠️ Marked as BEACONING NOT DETECTED
6. Enrichment & Output
-	Adds VirusTotal URL lookup for detected destination IPs
	    🔐 To enable IP reputation checks, enter your own VirusTotal API key in the script.
           You can get a free key from virustotal.com.
-	Outputs colored results in terminal
-	Writes full log to a .txt file in the same folder
________________________________________
❓ Can BEACONING be on random times?
Short answer: No.
Beaconing implies a regular or semi-regular communication interval. Random communication times usually indicate normal activity or non-automated behavior.
However...
Some malware uses jitter — introducing small variations in timing to avoid detection.
Example:
•	Beacon every 60 ± 10 seconds
🧪 Jittered Beaconing Support
•	Tolerates ±10 second differences in intervals
•	Helps detect beacons that avoid exact timing to bypass detection
📌 RFI Summary (If Beaconing Found)
At the top of the output file:
============ REQUEST FOR INFORMATION ============
XXX MDR team reviewed the available firewall logs from the dataset <filename>, and identified beaconing activity.
Details:
- 192.168.1.10 → 10.0.0.5, every 60s (100% consistent)

🟡 "not enough data" meaning:
This message appears when a source-destination IP pair doesn't have enough connection records to confidently analyze timing patterns.
➤ Specifically: The script requires at least 4 timestamps for a given pair to calculate at least 3 intervals (differences between times). If there are fewer than 4 events, you’ll see:
192.168.1.20 -> 10.0.0.10 (not enough data)
📌 Why? 
With only 2 or 3 events, it’s statistically weak to say if a consistent pattern (beaconing) exists.

🟢 "80%+ identical intervals" meaning:
This is the consistency threshold the script uses to flag beaconing.
➤ Specifically:
After calculating time gaps between events, it finds the most common interval.
If that interval appears in 80% or more of the total intervals, the script considers it likely beaconing.
🧠 Example:
Time intervals: [60, 60, 60, 60, 300]
Most common interval = 60s → appears 4 out of 5 times = 80%
✅ So this would be detected as beaconing.
________________________________________
✅ Summary
This script is a flexible tool for identifying beaconing behavior in network logs with minimal dependencies, ready for real-world SOC environments.
________________________________________

