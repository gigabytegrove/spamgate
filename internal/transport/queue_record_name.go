package transport

import "strings"

// validQueueRecordName permits only the canonical lowercase hexadecimal
// queue identity plus the .json suffix. This is stricter than merely rejecting
// traversal: arbitrary child names must never reach the spool reader.
func validQueueRecordName(name string) bool {
    return len(name) == 37 && strings.HasSuffix(name, ".json") && validQueueID(name[:32])
}
