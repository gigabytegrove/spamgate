# Settings navigation correction — 0.6.0-alpha.7

- Main header: **Settings**, visible to administrators, routes to `/settings`.
- Direct software updates link: `/settings/updates`, visible under the management links as **Software updates**.
- Existing protection controls remain at `/policy`, now titled **Protection policy**.
- Settings directory links to software updates, protection policy, mail connections, accounts, API keys and delivery queue.
- Existing updater check/stage/install API and security restrictions are unchanged.
- Updater remains dependent on an official published GitHub Release with a valid matching checksum file; navigation does not itself publish a release.

## Regression checks

`go test ./...`, `go test -race ./...`, `go vet ./...`, and `node --check internal/server/assets/app.js`.
