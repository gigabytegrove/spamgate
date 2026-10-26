.PHONY: build test check run dist
build:
	go build -trimpath -o spamgate ./cmd/spamgate
test:
	go test ./...
check:
	go test ./...
	go vet ./...
dist:
	bash scripts/build-release.sh
run:
	go run ./cmd/spamgate -data ./data -listen 127.0.0.1:38470
