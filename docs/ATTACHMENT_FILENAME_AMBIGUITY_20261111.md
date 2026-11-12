# Attachment filename ambiguity guard — 2026-11-11

Scope: classifier evidence for issue #5; no automatic mail-server configuration changes.

Decoded MIME filenames can include directory separators, NUL/control characters and Unicode line separators. Previously attachmentNameFindings stripped directory components with path.Base before assessing them, and did not record control characters. This change records ATTACHMENT_NAME_PATH and ATTACHMENT_NAME_CONTROL as scored suspicion evidence before the basename is used for extension checks. Ordinary filename extensions continue to be evaluated; executable signature detection is unchanged. The existing attachmentLabel sanitizer continues to protect diagnostic text.

Regression coverage: Unix and Windows path components, NUL, Unicode line separator, benign filename, and MIME multipart integration. Tests must run on exact HEAD; a committed test is not a pass.

These findings are not standalone proof of malware. False-positive rates must be measured against real tenant-labelled corpora before enforcement thresholds change. Real Postfix/Dovecot disposition, delivery, authentication, tenant policy, browser UI, backup/restore and update/rollback qualification remain separate open gates.
