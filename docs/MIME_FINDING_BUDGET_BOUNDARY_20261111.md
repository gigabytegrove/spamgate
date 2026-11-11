# MIME finding budget boundary correction — 2026-11-11

## Confirmed defect
The previous appendFinding implementation replaced the twentieth legitimate finding with MIME_FINDINGS_TRUNCATED immediately when the nineteenth entry already existed. Thus a message with exactly twenty findings falsely claimed that evidence had been omitted, and lost a real finding. This is an observability false positive.

## Change
The first twenty findings are now retained unchanged. Only when a twenty-first finding arrives is slot twenty replaced with a single MIME_FINDINGS_TRUNCATED marker. Subsequent findings leave that marker intact. This keeps output bounded to twenty records without falsely claiming truncation at the exact limit.

## Regression
The new mime_finding_budget_boundary_test.go builds real MIME multipart messages with 19, 20, 21 and 30 executable-signature attachments. It checks exact output count, marker position, and absence of false truncation for 19/20 findings.

## Qualification limitations
Source committed directly via GitHub because the runner cannot resolve github.com for a local clone. Committing tests is not proof they executed; verify exact HEAD CI and production mail-host evidence separately. No scoring, SMTP disposition, running mail-server settings, supervisor, systemd units, Postfix/Dovecot paths, or architecture were changed. All production issues #1–#9 remain open pending their independent acceptance gates.
