package backup

import (
    "fmt"
    "io/fs"
    "os"
    "path/filepath"
    "runtime"
    "sort"
)

// syncRestoredTree makes the extracted directory hierarchy durable before the
// final no-replace rename. Syncing only file contents is insufficient: after a
// power loss, newly created directory entries may disappear even if each file
// was fsynced. Descendants are synced before their parents.
func syncRestoredTree(root string) error {
    if runtime.GOOS != "linux" {
        // Windows directory fsync semantics differ; do not claim a Linux
        // power-loss durability guarantee on other platforms.
        return nil
    }
    var directories []string
    err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
        if walkErr != nil { return walkErr }
        info, err := os.Lstat(path)
        if err != nil { return err }
        if info.Mode()&os.ModeSymlink != 0 {
            return fmt.Errorf("restore staging contains a symlink: %s", path)
        }
        if entry.IsDir() {
            if !info.IsDir() { return fmt.Errorf("restore staging directory changed: %s", path) }
            directories = append(directories, path)
        } else if !info.Mode().IsRegular() {
            return fmt.Errorf("restore staging contains a non-regular file: %s", path)
        }
        return nil
    })
    if err != nil { return err }
    sort.Slice(directories, func(i, j int) bool {
        return len(directories[i]) > len(directories[j])
    })
    for _, dir := range directories {
        f, err := os.Open(dir)
        if err != nil { return fmt.Errorf("open restore directory %s: %w", dir, err) }
        info, statErr := f.Stat()
        if statErr == nil && !info.IsDir() {
            statErr = fmt.Errorf("restore staging directory changed: %s", dir)
        }
        if statErr == nil { statErr = f.Sync() }
        closeErr := f.Close()
        if statErr != nil { return fmt.Errorf("sync restore directory %s: %w", dir, statErr) }
        if closeErr != nil { return fmt.Errorf("close restore directory %s: %w", dir, closeErr) }
    }
    return nil
}
