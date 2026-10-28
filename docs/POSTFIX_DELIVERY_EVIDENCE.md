# Postfix delivery evidence (0.6.0-alpha.4 development)

For an administrator reviewing an email scanned through the Postfix Milter, **View Postfix log evidence** looks up the queue ID recorded for that scan. This feature is read-only and does not change Postfix state.

Set `SPAMGATE_POSTFIX_LOG_PATH` to the path of a **local readable regular file** containing Postfix's standard syslog output, for example `/var/log/mail.log` on a host that uses that path. The path is set by the administrator when launching the application, never by a browser request. If SpamGate is containerized, mount only the necessary logfile read-only at an explicit location and set the variable to that location; avoid mounting an entire `/var/log` directory. The service account must have permission to read the file. No logs are imported or replicated into SpamGate history.

Only administrators may call `GET /api/v1/messages/{id}/delivery-evidence`. The response contains up to 100 matching entries from the last 4 MiB of the configured log, each matched against the exact recorded queue ID and Postfix daemon prefix. No body, header export, commands, or destructive operations are supported. A non-regular file or symlink is rejected.

**Limitations:** Log rotation and tail bounds may hide older entries. A missing entry is not a negative delivery proof. `status=sent` confirms what Postfix recorded for that next hop, NOT final mailbox placement. Received/forwarded messages can get new queue IDs and require separate correlation. Queue IDs may be reused over time, so dates and recipients must be examined by the administrator before treating an event as related. The view is deliberately not a delivery certification system.

Remaining release blockers include independent Postfix/Dovecot end-to-end scenarios, quarantine and multi-recipient transaction qualification, threat intelligence provider health and licensing, ML calibration, Windows endpoint runtime validation, and upgrade/rollback assurance. This development build is not cleared to replace an existing production filtering system.
