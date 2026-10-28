package core

// The PSL is used only to discover organizational domains. A two-label
// heuristic risks authenticating sibling tenants under co.uk, github.io, etc.

import (
	_ "embed"
	"log/slog"
	"os"
	"strings"
	"sync"
)

//go:embed public_suffix_list.txt
var bundledSuffixes string

type suffixData struct {
	exact     map[string]bool
	wildcard  map[string]bool
	exception map[string]bool
}

var suffixOnce sync.Once
var suffixDB suffixData

func parseSuffixList(raw string) suffixData {
	db := suffixData{exact: map[string]bool{}, wildcard: map[string]bool{}, exception: map[string]bool{}}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "!") {
			db.exception[strings.TrimPrefix(line, "!")] = true
		} else if strings.HasPrefix(line, "*.") {
			db.wildcard[strings.TrimPrefix(line, "*.")] = true
		} else {
			db.exact[line] = true
		}
	}
	return db
}
func suffixList() suffixData {
	suffixOnce.Do(func() {
		raw := bundledSuffixes
		if path := os.Getenv("SPAMGATE_PUBLIC_SUFFIX_FILE"); path != "" {
			if b, err := os.ReadFile(path); err == nil {
				raw = string(b)
				slog.Info("loaded configured public suffix list", "file", path)
			} else {
				slog.Warn("public suffix list override unreadable; using bundled snapshot", "error", err)
			}
		}
		suffixDB = parseSuffixList(raw)
	})
	return suffixDB
}

func organizationalDomain(name string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return ""
	}
	db := suffixList()
	// PSL default rule "*" matches one rightmost label.
	best := 1
	exception := 0
	for i := 0; i < len(labels); i++ {
		candidate := strings.Join(labels[i:], ".")
		n := len(labels) - i
		if db.exception[candidate] && n > exception {
			exception = n
		}
		if db.exact[candidate] && n > best {
			best = n
		}
		if i > 0 && db.wildcard[candidate] && n+1 > best {
			best = n + 1
		}
	}
	if exception > 0 {
		best = exception - 1
	}
	if len(labels) <= best {
		return ""
	}
	return strings.Join(labels[len(labels)-best-1:], ".")
}
