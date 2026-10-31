package backup

// Runtime flock files are deliberately not part of SpamGate's persistent
// application state. Never copy them into a backup or restore them from older
// archives: an inode created by a different UID can block the unprivileged
// native worker after an otherwise successful cold restore.
//
// Keep these exact paths synchronized with the native worker and its helpers.
// Do not use basename or suffix matching: forensic .pending-* originals and
// user-managed files must remain in the backup.
func runtimeLockPath(path string) bool {
    switch path {
    case ".worker.lock",
        ".events-journal.lock",
        ".postfix-hold-release.lock",
        "delivery-queue/.delivery-worker.lock",
        "delivery-queue/.delivery-intake.lock":
        return true
    default:
        return false
    }
}
