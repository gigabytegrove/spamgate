# Cold restore cancellation — 2026-11-19

RestoreColdContext adds cancellation to the standalone authenticated cold restore path. RestoreCold remains backward compatible and delegates to context.Background(). A canceled context returns context.Canceled without publishing the staging tree. Streaming checks cancellation before and after source reads, between files, and immediately before atomic publication. The staging directory is removed on prepublication failure.

Limitations: cancellation cannot interrupt a filesystem read already blocked in the kernel. A cancellation racing the final rename cannot undo an already published restore. Publication fsync errors may occur after a successful rename; callers must inspect the destination before retrying. This change does not integrate the standalone backupverify package with the production backup subsystem or qualify a real mail host.

Locked architecture: /opt/spamgate/spamgate foreground launcher; spamgate-worker; /opt/spamgate/data persistent; Postfix Milter ports 38470/38472; no Docker substitution or automatic running mail-server changes.

The October 31 beta target has passed. Issues #1–#9 and end-to-end mail-host, regression, cold restore and rollback acceptance remain open. Source commits alone do not constitute successful CI or beta qualification.
