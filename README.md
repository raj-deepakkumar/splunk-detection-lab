# Splunk Detection Lab

## Overview
This repository contains my hands-on lab work for Splunk SPL (Search Processing Language). I set up Splunk Enterprise (Free version) locally, loaded sample email server logs (57,912 events), and wrote SPL queries to analyze the data for SOC operations.

## Lab Setup
- **Tool:** Splunk Enterprise 9.x (Free License)
- **Data Source:** Sample mail server logs (sendmail sourcetype)
- **Total Events:** 57,912

## Searches

### 1. Basic Event Count
- **File:** `searches/basic_count.spl`
- **Query:** `index=* | stats count`
- **Purpose:** To calculate the total number of indexed events. This is the foundation of understanding data volume before writing detections.

### 2. Filtering Spam Events
- **File:** `searches/spam_filter.spl`
- **Query:** `index=* spam | stats count`
- **Purpose:** To filter raw events for the keyword "spam" and count the matching events. This helps in identifying the volume of malicious or unwanted traffic.

### 3. Extracting Email Recipients via Regex (Advanced)
- **File:** `searches/extract_recipients.spl`
- **Query:** `index=* sourcetype=sendmail | rex field=_raw "to=<(?<recipient_email>.*?)>" | stats count by recipient_email | sort -count`
- **Purpose:** Uses regex (`rex` command) to parse unstructured raw email logs to extract recipient email addresses. Then aggregates the count to find the most targeted users (potential victims of a phishing/spam campaign).
- **Troubleshooting Note:** Initially, a broad search caused the `rex` command to drop all events that didn't contain the email format. I fixed this by filtering by `sourcetype=sendmail` first, ensuring the regex only ran on relevant logs.

## Findings
- Top targeted recipient: `spamme@splunkit.com` with 3,318 sendmail log events.
- Other recipients: `root@splunk3.splunkit.com` (752), `mark@splunk.com` (247), `splunk@localhost` (247).

## Roadmap
- [ ] Break results down by sender and time (`timechart`)
- [ ] Add detection searches for suspicious patterns
- [ ] Document findings with screenshots
