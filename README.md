# Splunk Detection Lab

Hands-on Splunk SPL lab for SOC operations: log parsing with regex, aggregation, and threshold-based detections on mail server logs.

## Lab setup

- Tool: Splunk 4.1.1 (free license), running locally on Windows
- Dataset: Splunk's built-in sample data (`sample_app\logs\maillog`), loaded into `index=sample`
- Sourcetype: `sendmail`, 57,912 events (March 29 to April 8, 2010)
- Credit: sample dataset provided by Splunk for learning purposes
- Note: time range must be set to "All time", since the events are from 2010

## Searches

| File | Purpose |
|------|---------|
| `searches/basic_count.spl` | Total event count |
| `searches/spam_filter.spl` | Count of events containing "spam" |
| `searches/extract_recipients.spl` | Extract recipients with `rex`, rank by volume |
| `searches/search_1_sender_timechart.spl` | Hourly mail volume per sender (`timechart`) |

## Detections

### Detection 1: Spam volume per user
File: `searches/detection_1_spam_threshold.spl`

    index=sample sourcetype=sendmail "identified spam"
    | rex field=_raw "for (?<spam_user>[^:]+):"
    | stats count by spam_user
    | where count > 50

Counts SpamAssassin (`spamd`) "identified spam" log lines per user and alerts when a user crosses 50. Related ATT&CK technique: T1566 (Phishing). This rule flags spam volume only, not malicious content.

### Detection 2: Possible mail bombing
File: `searches/detection_2_mail_bombing.spl`

    index=sample sourcetype=sendmail
    | rex field=_raw "to=<(?<recipient_email>.*?)>"
    | stats count by recipient_email
    | where count > 1000

Alerts when one recipient appears in more than 1000 delivery log lines. Related ATT&CK technique: T1499 (Endpoint Denial of Service).

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
