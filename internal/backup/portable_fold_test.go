package backup

import (
    "sort"
    "strings"
    "testing"
    "time"
)

func TestPortableFoldIdentityMatchesUnicodeSimpleFold(t *testing.T) {
    pairs := [][2]string{
        {"K", "K"}, {"k", "K"},
        {"S", "ſ"}, {"s", "ſ"},
        {"Ä", "ä"}, {"Mail", "mail"},
    }
    for _, pair := range pairs {
        if !strings.EqualFold(pair[0], pair[1]) {
            t.Fatalf("invalid test fixture: %q and %q", pair[0], pair[1])
        }
        if portableFoldIdentity(pair[0]) != portableFoldIdentity(pair[1]) {
            t.Errorf("missed Unicode simple-fold collision: %q and %q", pair[0], pair[1])
        }
    }
    if portableFoldIdentity("mail/a.eml") == portableFoldIdentity("mail/b.eml") {
        t.Fatal("distinct names collapsed")
    }
}

func TestManifestRejectsUnicodeSimpleFoldAliases(t *testing.T) {
    cases := []struct {
        name string
        paths []string
        reject bool
    }{
        {"kelvin-file", []string{"K.eml", "K.eml"}, true},
        {"long-s-file", []string{"S.eml", "ſ.eml"}, true},
        {"kelvin-ancestor", []string{"K", "K/mail.eml"}, true},
        {"reverse-ancestor", []string{"K/mail.eml", "K"}, true},
        {"long-s-ancestor", []string{"S", "ſ/mail.eml"}, true},
        {"different-children", []string{"K/a.eml", "K/b.eml"}, false},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            entries := make([]Entry, 0, len(tc.paths))
            for _, path := range tc.paths {
                entries = append(entries, Entry{
                    Path: path, Bytes: 1, SHA256: strings.Repeat("a", 64),
                })
            }
            sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
            manifest := Manifest{
                Format: 1, Product: "SpamGate",
                Created: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
                Entries: entries,
            }
            err := validateManifestSemantics(manifest)
            if (err != nil) != tc.reject {
                t.Fatalf("expected reject=%v, got %v", tc.reject, err)
            }
        })
    }
}
