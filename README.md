# Splunk Detection Lab

Hands-on lab work for Splunk SPL (Search Processing Language) in a SOC context.

## Lab setup

- Tool: Splunk Enterprise (free license), running locally
- Data: sample mail server logs (sendmail sourcetype)
- Total events indexed: 57,912

## Searches

### 1. Basic event count

File: `searches/basic_count.spl`

    index=* | stats count

Counts all indexed events. This is the first check to understand the data volume before writing detections.

### 2. Spam keyword filter

File: `searches/spam_filter.spl`

    index=* spam | stats count

Filters raw events containing the keyword "spam" and counts the matches, to estimate how much unwanted mail traffic is in the data.

## Roadmap

- Break results down by sender, host and time (`stats count by`, `timechart`)
- Add detection searches for suspicious patterns
- Document findings with screenshots
