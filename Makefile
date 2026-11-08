# xumcat — see `make help`
BIN      := bin/xumcat
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)
PKGS     := ./...
COVER_MIN := 75
FUZZTIME ?= 30s

.PHONY: help deps build go/build go/fmt go/vet test test/run test/race test/coverage test/e2e test/fuzz check clean

help: ## Show targets
	@grep -E '^[a-zA-Z/_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-16s %s\n",$$1,$$2}'

deps: ## Download modules
	go mod download

build: go/build ## Build bin/xumcat
go/build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/xumcat

go/fmt: ## Format
	gofmt -w .

go/vet: ## Vet
	go vet $(PKGS)

test: test/run ## Run tests
test/run:
	go test -count=1 $(PKGS)

test/race: ## Run tests with the race detector
	go test -race -count=1 $(PKGS)

test/coverage: ## Coverage report; fails if any package is below $(COVER_MIN)%
	go test -count=1 -coverprofile=coverage.out $(PKGS) | tee coverage.txt
	go tool cover -html=coverage.out -o coverage.html
	@awk -v min=$(COVER_MIN) '/coverage:/ && !/internal\/testcert/ { for (i=1;i<=NF;i++) if ($$i=="coverage:") { p=$$(i+1); sub("%","",p); if (p+0 < min) { print "below " min "%: " $$0; bad=1 } } } END { exit bad }' coverage.txt

test/e2e: go/build ## xumcat <-> xumcat end-to-end tests with real processes (E2E_MB=50)
	XUMCAT=$(abspath $(BIN)) e2e/run.sh

test/fuzz: ## Fuzz every target (FUZZTIME per target, default 30s)
	@for pkg in ./endpoint; do \
	  list=$$(go test -list '^Fuzz' $$pkg) || { echo "$$list"; echo "cannot list fuzz targets in $$pkg"; exit 1; }; \
	  targets=$$(echo "$$list" | grep '^Fuzz'); \
	  [ -n "$$targets" ] || { echo "no fuzz targets in $$pkg"; exit 1; }; \
	  for f in $$targets; do \
	    echo "== $$pkg $$f"; \
	    go test -run '^$$' -fuzz "^$$f$$" -fuzztime $(FUZZTIME) $$pkg || exit 1; \
	  done; \
	done

check: go/fmt go/vet test/race test/coverage ## Pre-commit gate: fmt, vet, race tests, coverage

clean: ## Remove build and coverage output
	rm -rf bin coverage.out coverage.txt coverage.html
