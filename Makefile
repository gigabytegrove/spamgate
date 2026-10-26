.PHONY: build test check run
build:
	go build -trimpath -o spamgate ./cmd/spamgate
test:
	go test ./...
check:
	go test ./...
	go vet ./...
run:
	go run ./cmd/spamgate -data ./data -listen 0.0.0.0:8080
