GO ?= go

.PHONY: fmt vet test cover verify ci build run tidy

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test -race ./...

cover:
	$(GO) test ./... -coverprofile=coverage.out
	$(GO) tool cover -func=coverage.out | tail -1

verify: fmt vet test

ci: verify

build:
	$(GO) build ./...

run:
	$(GO) run .

tidy:
	$(GO) mod tidy
