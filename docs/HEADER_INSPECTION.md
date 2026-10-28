# SpamGate — Raw header inspection

## Scope

- In **All Messages**, **Review Mail**, or the Home message table, open a scanned email and choose **View raw email headers**.
- The panel displays the *inbound* header block captured by SpamGate during scanning, in original field order and folding. There is a compact summary of key fields plus full escaped raw text, with Copy and Save .txt controls.
- **It does not retain or display the message body, HTML, attachments, or URLs in the body** for this feature. Do not confuse an inbound snapshot with a final message in a mailbox; Postfix/Dovecot can add headers later.
- Header inspection requires an authenticated **administrator**. Header values can include internal network paths, tracking identifiers, or recipient addresses not visible to a mailbox-only account.
- A captured header block is bounded to 256 KiB. Oversize header blocks are labeled truncated. The file permissions are 0600 in the `headers/` subdirectory under the configured data root, which is created with 0700 permissions.
- The header snapshot is kept out of `events.jsonl`, ordinary message-list JSON, and history exports. It follows the same retention/eviction policy as its corresponding history event. Backup and restore of the stopped data directory include it.
- **Old messages:** if a quarantined original still exists, headers may be recovered from it. Accepted messages scanned by older versions did not retain raw headers; those cannot be reconstructed from a score or a message ID.
- The viewer presents raw headers as inert text, never as HTML, and does not infer that externally supplied `Authentication-Results`, SPF, ARC, or DKIM claims are trustworthy.

## API

`GET /api/v1/messages/{scan_id}/headers` (administrator cookie or administrator-scoped API token). Returns JSON: `raw`, `source`, `bytes`, and `truncated`. Returns 404 if the snapshot/original is unavailable; returns 403 for mailbox-only sessions.

## Investigation flow

1. Find a message by subject, Message-ID, Postfix queue ID, sending IP, detector symbol, or recipient in **All Messages**.
2. Inspect verdict and scoring evidence.
3. Select **View raw email headers** to review `Received`, `Return-Path`, `DKIM-Signature`, `Authentication-Results`, and ARC claims as observed during scanning.
4. Compare the reported sending IP and Postfix queue ID against Postfix logs. Do not assume an `X-SpamGate-*` header added to a *delivered* message is already present in the captured inbound header block.
