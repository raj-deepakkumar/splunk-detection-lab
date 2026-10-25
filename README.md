# Splunk Detection Lab

Hands-on Splunk SPL lab for SOC operations: log parsing with regex, aggregation, and threshold-based detections on mail server logs.

## Dataset Source

- Data: Splunk's built-in sample data (`sample_app\logs\maillog` and `maillog.1`). Credit to Splunk for providing this dataset for learning purposes.
- Loaded into `index=sample`, sourcetype `sendmail`: 57,912 events from March 29 to April 8, 2010 (set the time range to "All time")
- Tool: Splunk 4.1.1 (free license), running locally on Windows
- Note on indexes: every search here names its index and sourcetype instead of using `index=*`. In a real environment, data lives in dedicated indexes (for example an email security index), which keeps searches fast and reduces noise.

## Searches

- `searches/extract_recipients.spl`: extracts recipient addresses with `rex` and ranks them by log volume
- `searches/search_1_sender_timechart.spl`: hourly mail volume for the top 5 senders (`timechart`)

## Detections

### Detection 1: Spam volume per user

File: `searches/detection_1_spam_threshold.spl`

    index=sample sourcetype=sendmail "identified spam"
    | rex field=_raw "for (?<spam_user>[^:]+):"
    | stats count by spam_user
    | where count > 50

Counts SpamAssassin (`spamd`) "identified spam" log lines per user and alerts when a user crosses 50.

### Detection 2: Possible mail bombing

File: `searches/detection_2_mail_bombing.spl`

    index=sample sourcetype=sendmail
    | rex field=_raw "to=<(?<recipient_email>.*?)>"
    | stats count by recipient_email
    | where count > 1000

Alerts when one recipient appears in more than 1000 delivery log lines.

## MITRE ATT&CK Mapping

| Detection | Related technique | Note |
|-----------|-------------------|------|
| Detection 1: spam volume | T1566 Phishing | Flags spam volume only, not malicious links or attachments |
| Detection 2: mail bombing | T1499 Endpoint Denial of Service | Flooding of one mailbox with delivery events |

## Findings

- Top sender by log lines: `spammer@spamdomain.com` (2,969)
- Detection 1 fires for user `spamme` (2,649 spam identifications)
- Detection 2 fires for `spamme@splunkit.com` (3,318 log events); the next recipient has 752
- Counts are sendmail log lines, not unique emails

## Lessons learned

- A search that returns no events is not a working detection: the first spam rule used a `from=` pattern, but the spam log lines come from `spamd` and have no sender field, so it returned nothing. I rewrote it around the `spamd` log format.
- Always check the real index and sourcetype first (`index=sample`, not `index=main`).
- Threshold values (50 and 1000) were chosen from this dataset and should be tuned per environment.

## Roadmap

- [ ] Add screenshots of results
- [ ] Add more detections (failed delivery spikes, unusual sender domains)
- [ ] Map detections to a fuller ATT&CK matrix
