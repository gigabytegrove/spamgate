# SpamGate alpha.8 — Field Desk navigation and Tailwind 4 redesign

## Goals

- A single persistent navigation system replaces overlapping top navigation, management navigation, and advanced tool dropdowns.
- Mail, Protection, and Administration are distinct task groups; every existing route remains accessible.
- Mobile opens the same navigation in a dismissible drawer; reduced-motion is respected.
- No existing API, authentication, session, scanning, delivery, quarantine, updater, or stored data format was changed by this UI pass.
- Status distinguishes mail-flow verification from a listening port; a healthy listener is not proof of successful delivery.

## Visual specification

- Personality: trustworthy, utilitarian, calm. Reference: a well-made paper operations ledger.
- Light only. Canvas `#f6f5ef`, paper `#fffefa`, forest `#254736`, copper focus `#c08426`, text `#35443c`.
- Segoe UI Variable body, Trebuchet MS headings, Cascadia Code data.
- Left 248 px workspace navigation on wide screens; mobile drawer at 820 px and below.
- Compact straight-edged evidence tables, restrained separators and no ornamental dashboard card chrome.
- Signature: a single continuous forest-green navigation rail with a contrasting cream selection.
- Motion: 200 ms mobile drawer; no transitions under `prefers-reduced-motion`.

## Build CSS

Tailwind 4.1.10 is pinned as a build-time development dependency. Production serves a compiled CSS asset from the Go binary; no CDN or runtime Node dependency.

```bash
npm install --ignore-scripts
npm run build:css
npm run check:js
go test ./...
go vet ./...
go build ./cmd/spamgate
```

Existing complex screen-specific styles remain in `app.css` to preserve functionality. New shell styling is in `redesign.css`. Tailwind utilities are compiled from `tailwind.source.css` into `tailwind.css`.

## Remaining work

This pass reorganizes shell navigation and overall identity, but does not rewrite every legacy form, investigation table, or onboarding screen as a Tailwind utility component. Full browser accessibility and user-journey testing is still required, including responsive screenshots and keyboard-only navigation.
