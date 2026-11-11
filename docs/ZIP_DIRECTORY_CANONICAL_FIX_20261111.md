# ZIP canonical directory regression (2026-11-11)

The archiveguard canonical-path check previously compared `path.Clean("folder/")` with `"folder/"`, rejecting legitimate ZIP directory entries. This also broke the existing `TestAcceptCanonicalDirectoryAndFile` regression.

Directory entries now remove exactly one trailing slash *for canonical comparison only*. All original entry checks remain in force: a directory must end in a slash, have zero uncompressed bytes, and cannot contain traversal, repeated separators, dot segments, or duplicate canonical names. Directory/file name collisions remain rejected. No files are extracted and no mail disposition is changed.

This fixes the read-only ZIP inspection primitive, not live classifier integration. ZIP malware scanning, recursive nested archives, explicit unscanned outcomes, false-positive evaluation, and real-host acceptance remain open. Run `go test ./internal/archiveguard` and the full engineering qualification workflow before considering this commit verified.
