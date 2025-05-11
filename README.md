# BeaconHunter

A PowerShell-based script to analyze network logs from CSV files and detect potential beaconing behavior. Supports VirusTotal integration for IP reputation checks.

**Beaconing Detection Script Overview**  
Author: Ekrem Ozdemir  
Compatible with Windows PowerShell 5.1 and above  

---
![image](https://github.com/user-attachments/assets/827dbe5f-cfbe-493c-98be-28cedb3c8362)


### 🎯 Purpose  
To analyze firewall logs or CSV-based network data and identify whether certain source-destination IP pairs are beaconing — i.e., communicating at consistent time intervals.

---

### 🧠 Common Use Case  
You're a SOC analyst reviewing outbound connections from internal assets. You want to quickly identify signs of C2 (Command and Control) beaconing — such as highly regular connection intervals or known malicious IPs — in your network telemetry.  
By feeding this script a properly formatted CSV export (from a SIEM, firewall, or proxy), you can automate detection and reputation checking in one go.

---

### 📁 Input  
- CSV file with at least 3 columns: `timestamp`, `source_address`, `destination_address`  
- Can also support 7-column format with extra fields: `source_port`, `destination_port`, `asset`, `user`

---

### 📊 CSV Format for BeaconHunter Script

```text
| timestamp           | source_address | source_port | destination_address  | destination_port | asset         | user    |
|---------------------|----------------|-------------|----------------------|------------------|---------------|---------|
| 2025-05-08T08:00:00 | 192.168.1.10   | 12345       | 8.8.8.8              | 123              | Server-01     | alice   |
````

---

### ⚙️ Script Logic

**1. Environment Setup**

* Locates its own script folder
* Sets output file in same folder using the CSV filename

**2. CSV Processing**

* Skips header and summary rows (e.g., containing "All Values", or set your own word)
* Handles both 3-column and 7-column CSV formats
* Treats 4–6 columns as 3-column mode

**3. Timestamp Parsing**

* Supports formats like:

  * `2025-05-06T08:00:00`
  * `2025-05-06T08:00:00.123Z`
* Invalid rows are skipped

**4. Beaconing Detection Logic**

* Sorts communication events by timestamp
* Calculates time differences between events
* Finds the most common interval (mode)
* If ≥80% of intervals are within ±10 seconds → flagged as beaconing

**5. Classification**

* ✅ `BEACONING DETECTED` — if pattern is consistent
* ⚠️ `BEACONING NOT DETECTED` — if too few data points or irregular

**6. Enrichment & Output**

* Adds VirusTotal lookup links for destination IPs

  > 🔐 *To enable IP reputation checks, enter your own VirusTotal API key in the script.*
  > Get one free from [virustotal.com](https://www.virustotal.com)
* Colored output in terminal
* Full report saved as `.txt` in script folder

---

### ❓ FAQ

**Q: Can beaconing happen at random times?**
No — beaconing implies regular or semi-regular timing.
However, some malware uses *jitter* to avoid exact intervals.

**🧪 Jittered Beaconing Support**

* Allows ±10 second variation tolerance
* Detects jitter-based beacons like: `every 60 ± 10 seconds`

---

### 📌 RFI Summary (Sample Output)

```
============ REQUEST FOR INFORMATION ============
MDR team reviewed the firewall logs from <filename> and identified beaconing activity:

Details:
- 192.168.1.10 → 10.0.0.5, every 60s (100% consistent)
```

---

### 🟡 “not enough data” Meaning

Displayed when fewer than 4 timestamps exist for a source-destination pair.
➤ At least 3 intervals are needed to confirm a pattern.

---

### 🟢 “80%+ identical intervals” Meaning

If the same interval appears in ≥80% of all intervals, it’s considered beaconing.

**Example:**
Intervals = `[60, 60, 60, 60, 300]`

* Mode = `60s`, appears 4 out of 5 → **80% match**
  ✅ Beaconing detected.

---

### ✅ Summary

A flexible and practical tool to identify beaconing in network logs.
Perfect for SOC analysts who want quick, scriptable detection with optional VirusTotal enrichment.
