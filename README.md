# Android Triage Professional v3.0

## Overview

**Android Triage Professional** is a high-performance, Go-based forensic acquisition tool designed for incident responders and penetration testers. It automates the collection of volatile and non-volatile data from Android devices via ADB (Android Debug Bridge), ensuring chain-of-custody integrity with automated hashing and reporting.

The tool focuses on **smart acquisition**, prioritizing high-value user artifacts (communications, timeline, location) over redundant system noise, making it efficient for time-critical investigations.

## Key Features

*   **Optimized Performance:**
    *   **Fast Device Profiling:** Uses batched ADB commands (`getprop`) to fetch device details in milliseconds.
    *   **Concurrent Hashing:** Utilizes a worker pool to calculate SHA-256 hashes of acquired files in parallel, significantly reducing post-acquisition processing time.
    *   **Smart Triage:** Prioritizes volatile data and user artifacts, skipping massive system dumps unless explicitly requested.
*   **Forensic Integrity:**
    *   Automated SHA-256 hashing of all acquired files.
    *   JSON metadata generation for every acquisition step.
    *   Chain of Custody preserved with detailed logging (Serial, IMEI, Time).
*   **Comprehensive Reporting:**
    *   Generates an interactive HTML report.
    *   Produces machine-readable JSON summaries.

---

## Menu Options Explained

Below is a detailed breakdown of each forensic module available in the interactive menu.

### 1. Device Information
*   **Purpose:** Establishes the "Who" and "What" of the target device for the Chain of Custody.
*   **Data Collected:** Manufacturer, Model, Android Version, SDK Level, Serial Number, IMEI 1 & 2, Build ID, Kernel Version, Security Patch Level, Root Status, and Encryption State.
*   **Forensic Value:** Essential for verifying device identity in reports and determining vulnerability scope (e.g., rooting exploitability).

### 2. Live Commands Execution (Triage)
*   **Purpose:** Captures **volatile data** that resides in RAM or changes rapidly. This is the digital equivalent of "checking the pulse" of the device.
*   **Data Collected:** 
    *   Running Processes (`ps`, `top`): Identifies malware or suspicious apps currently active.
    *   Network Connections (`netstat`): Reveals active C2 (Command & Control) connections or data exfiltration.
    *   Open Files (`lsof`): Shows what files are currently being accessed.
    *   System State (`uptime`, `mount`, `df`): Checks disk usage and mount points.
*   **Optimization:** Static hardware info (like CPU architecture) has been stripped out to focus purely on active, volatile forensic evidence.

### 3. Package Manager Analysis
*   **Purpose:** Inventories all software installed on the device.
*   **Data Collected:** Lists of all packages (User, System, Disabled, Third-Party) with their installation paths and associated permissions.
*   **Forensic Value:** Critical for identifying installed malware, unauthorized apps (Shadow IT), or evidence of tampering (e.g., "Magisk" or "SuperSU").

### 4. Dumpsys Comprehensive Collection
*   **Purpose:** Dumps the internal state of Android system services.
*   **Data Collected:** 
    *   **UsageStats:** A timeline of app usage (what was opened, for how long, and when). **(Critical Evidence)**
    *   **BatteryStats:** Historical record of device activity, often revealing behavior even if logs are cleared.
    *   **Accounts:** Google/other accounts signed into the device.
    *   **Location:** Last known GPS/Network location caches.
*   **Forensic Value:** Provides a behavioral timeline of the user. Perfect for proving "The user was on WhatsApp at 10:00 PM."

### 5. Content Provider Extraction
*   **Purpose:** Extracts user data exposed via Android's content provider API (requires standard ADB shell permissions).
*   **Data Collected:** 
    *   **Communications:** SMS (Inbox/Sent), MMS, Call Logs.
    *   **Personal:** Contacts, Calendar Events, User Dictionary.
    *   **Browser:** Bookmarks and Searches (if using default browser providers).
*   **Forensic Value:** The "Gold Mine" for non-rooted extraction. Contains the actual content of user communications and relationships.

### 6. SD Card Acquisition
*   **Purpose:** Acquires files from the emulated external storage (`/sdcard`).
*   **Data Collected:** Photos (DCIM), Downloads, WhatsApp Media/Backups, Documents, and App Data stored in public directories.
*   **Forensic Value:** Primary source of user-generated content (images, videos, documents).

### 7. System Partition Acquisition
*   **Purpose:** Dumps the read-only OS partition (`/system`).
*   **Data Collected:** System apps (`/system/app`), Framework files, Libraries, and Binaries.
*   **Forensic Value:** Primarily for **Malware Analysis** (detecting trojanized system apps) or verification of system integrity.
*   **Note:** High storage requirement. Not usually needed for standard user investigations.

### 8. APK File Extraction
*   **Purpose:** Extracts the actual installer files (`.apk`) for all installed apps.
*   **Data Collected:** The binary APK files themselves.
*   **Forensic Value:** Allows for reverse engineering of suspicious apps to find hardcoded secrets or malicious logic.

### 9. ADB Backup (Full Device)
*   **Purpose:** triggers Android's legacy backup mechanism (`backup.ab`).
*   **Data Collected:** App private data (databases, preferences) for apps that allow backup.
*   **Forensic Value:** The *only* way to get private app data (like non-cloud chat databases) on a non-rooted device.
*   **Note:** High failure rate; requires user to tap "Back up my data" on the device screen.

### 10. Bugreport Generation
*   **Purpose:** Triggers the system-wide `bugreport` utility.
*   **Data Collected:** A massive `.zip` containing kernel logs (`dmesg`), system logs (`logcat`), dumpsys output, and traces.
*   **Forensic Value:** Excellent fallback/safety net. If other tools fail, the bugreport often contains the evidence buried in deep logs.

### 11. File System Dump (Complete)
*   **Purpose:** An aggressive attempt to pull *everything* accessible via ADB.
*   **Data Collected:** Combines SD Card, System, and Data partitions (where accessible).
*   **Note:** Highly redundant if you have already run options 6, 7, and 8.

### 12. Run All Acquisitions (Smart Mode)
*   **Purpose:** One-click automation for a standard forensic triage.
*   **Scope:** Runs Options 1, 2, 3, 4, 5, 6, and 10 sequentially.
*   **Optimization:** **Excludes** System Partition and APK Extraction to save time and storage, focusing 100% on **User Evidence**.
*   **Output:** Generates a structured directory with all acquired data hashed and organized.

### 13. Generate Report
*   **Purpose:** Synthesizes all collected data into a human-readable format.
*   **Output:** 
    *   `forensic_report.html`: Visual report with device stats, acquisition summaries, and file hashes.
    *   `summary.json`: Machine-readable summary for ingestion into other tools.

---

## Usage

1.  Enable **USB Debugging** on the target Android device.
2.  Connect the device via USB.
3.  Run the tool:
    ```bash
    go build main.go
    ```
4.  Follow the interactive menu.

## Requirements
*   **ADB (Android Debug Bridge):** Must be installed and in your system PATH.
*   **OS:** Windows, Linux, or macOS.