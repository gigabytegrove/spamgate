package core

// ZIP inspection is metadata-first. Limited member reads detect executables
// concealed behind harmless filenames and nested ZIPs without expanding an
// attacker-controlled archive into memory or writing files to disk.
import (
    "archive/zip"
    "bytes"
    "fmt"
    "io"
    "os"
    "path"
    "strings"
)

const (
    archiveMaxEntries = 100
    archiveMaxExpanded = uint64(30 << 20)
    archiveMaxMemberRead = 2 << 20
    archiveTotalReadBudget = 8 << 20
    archiveMaxDepth = 2
)

func archiveExecutableSignature(b []byte) bool {
    return bytes.HasPrefix(b, []byte("MZ")) || bytes.HasPrefix(b, []byte{0x7f, 'E', 'L', 'F'})
}

func archiveUnsafeName(name string) bool {
    clean := strings.ReplaceAll(name, "\\", "/")
    if strings.HasPrefix(clean, "/") || strings.ContainsRune(clean, 0) {
        return true
    }
    if len(clean) >= 2 && clean[1] == ':' {
        return true
    }
    for _, part := range strings.Split(clean, "/") {
        if part == ".." {
            return true
        }
    }
    return false
}

func inspectZIPAttachment(payload []byte, name string, add func(string, string, float64)) {
    budget := archiveTotalReadBudget
    remainingEntries := archiveMaxEntries
    remainingExpanded := archiveMaxExpanded
    var inspect func([]byte, string, int)
    inspect = func(data []byte, label string, depth int) {
        zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
        if err != nil {
            add("ARCHIVE_UNREADABLE", "ZIP archive structure not readable: "+label, 0)
            return
        }
        if len(zr.File) > archiveMaxEntries {
            add("ARCHIVE_LIMIT", "Archive contains over 100 entries: "+label, 2)
        }
        var declared uint64
        for i, f := range zr.File {
            if i >= archiveMaxEntries {
                break
            }
            if remainingEntries == 0 {
                add("ARCHIVE_LIMIT", "Combined nested ZIP entry budget exceeded: "+label, 2)
                return
            }
            remainingEntries--
            if f.UncompressedSize64 > remainingExpanded {
                add("ARCHIVE_EXPANSION_RISK", "Combined nested ZIP expansion budget exceeded: "+label, 3)
                break
            }
            remainingExpanded -= f.UncompressedSize64
            if f.UncompressedSize64 > archiveMaxExpanded-declared {
                add("ARCHIVE_EXPANSION_RISK", "Archive declares over 30 MiB expanded content: "+label, 3)
                break
            }
            declared += f.UncompressedSize64
            if f.Flags&1 != 0 {
                add("ARCHIVE_ENCRYPTED", "Encrypted ZIP entry cannot be inspected: "+label, 0)
                continue
            }
            if f.CompressedSize64 > 0 && f.UncompressedSize64/f.CompressedSize64 > 500 && f.UncompressedSize64 > 1<<20 {
                add("ARCHIVE_EXPANSION_RISK", "Very high archive compression ratio: "+label, 3)
            }
            member := strings.ReplaceAll(f.Name, "\\", "/")
            if archiveUnsafeName(f.Name) {
                add("ARCHIVE_TRAVERSAL_NAME", "Unsafe archive member path in: "+label, 2)
            }
            if f.Mode()&os.ModeSymlink != 0 {
                add("ARCHIVE_SYMLINK", "Archive contains a symbolic link: "+label, 2)
                continue
            }
            if f.FileInfo().IsDir() {
                continue
            }
            if riskyFilename(path.Base(member)) {
                add("ARCHIVE_RISKY_MEMBER", "Risky filename inside ZIP: "+path.Base(member), 5)
            }
            // Skip decompression of large members, even if compressed to a few
            // bytes. Never let a nested archive bypass the shared read budget.
            if f.UncompressedSize64 > archiveMaxMemberRead || budget <= 0 {
                continue
            }
            limit := int64(archiveMaxMemberRead + 1)
            if limit > int64(budget)+1 {
                limit = int64(budget)+1
            }
            rc, err := f.Open()
            if err != nil {
                add("ARCHIVE_MEMBER_UNREADABLE", "Cannot open archive member in: "+label, 0)
                continue
            }
            content, readErr := io.ReadAll(io.LimitReader(rc, limit))
            closeErr := rc.Close()
            if readErr != nil || closeErr != nil {
                add("ARCHIVE_MEMBER_UNREADABLE", "Cannot read archive member in: "+label, 0)
                continue
            }
            if len(content) > budget || len(content) > archiveMaxMemberRead {
                budget = 0
                add("ARCHIVE_LIMIT", "Archive inspection read budget exceeded: "+label, 0)
                break
            }
            budget -= len(content)
            if uint64(len(content)) != f.UncompressedSize64 {
                add("ARCHIVE_MEMBER_UNREADABLE", "Archive member size mismatch in: "+label, 0)
                continue
            }
            if archiveExecutableSignature(content) {
                add("ARCHIVE_EXECUTABLE_CONTENT", fmt.Sprintf("Executable signature in ZIP member %s (%s)", path.Base(member), label), 6)
            }
            if depth < archiveMaxDepth && bytes.HasPrefix(content, []byte("PK\x03\x04")) {
                inspect(content, path.Base(member)+" in "+label, depth+1)
            }
        }
    }
    inspect(payload, name, 0)
}
