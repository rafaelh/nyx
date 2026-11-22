# CGO_ENABLED=0 is set only where it is needed: -race requires cgo on Linux,
# so it must not be exported for the whole Makefile.
TARGETS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

.PHONY: build dist test lint clean eol-data abusive-data

build:
	CGO_ENABLED=0 go build -trimpath -o nyx ./cmd/nyx

dist:
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "dist/nyx-$$os-$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "-s -w" -o dist/nyx-$$os-$$arch ./cmd/nyx || exit 1; \
	done

# The cross-target vet type-checks every target's files, so an untagged
# platform-specific call (such as golang.org/x/sys/unix) cannot break one
# supported OS or architecture unnoticed. It runs before the tests so that a
# failing test cannot hide it.
test:
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "vet $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go vet ./... || exit 1; \
	done
	go test -race ./...

# golangci-lint is pinned in tools/go.mod, a module of its own so its dependencies stay out of
# nyx's. go tool builds it with the project's toolchain on first use and caches it, so nothing needs
# installing. Upgrade with:
#   go get -tool -modfile=tools/go.mod github.com/golangci/golangci-lint/v2/cmd/golangci-lint@vX.Y.Z
lint:
	go tool -modfile=tools/go.mod golangci-lint run ./...

clean:
	rm -rf nyx dist

# Refreshes the embedded end-of-life data (internal/eol/data and DATE) from endoflife.date, for
# each product internal/eol/products.yaml names. It needs curl and jq (jq -S keeps the files
# sorted, so a refresh diffs as the data that changed). curl writes to a file rather than a pipe so
# that a failed download stops the target instead of leaving an empty data file. Review the diff
# before committing it.
EOL_PRODUCTS = $(shell sed -n 's/^- product: //p' internal/eol/products.yaml)
eol-data:
	@set -e; for p in $(EOL_PRODUCTS); do \
		echo "internal/eol/data/$$p.json"; \
		curl -fsS --retry 3 -o internal/eol/data/$$p.json.raw "https://endoflife.date/api/$$p.json"; \
		jq -S . internal/eol/data/$$p.json.raw > internal/eol/data/$$p.json.tmp; \
		rm internal/eol/data/$$p.json.raw; \
		mv internal/eol/data/$$p.json.tmp internal/eol/data/$$p.json; \
	done; \
	date -u +%Y-%m-%d > internal/eol/DATE

# Refreshes the embedded snapshot of ipapi.is's most abusive networks and ASNs
# (internal/abusive/snapshot.json): two requests to ipapi.is, one for each list's page. curl writes
# each page to a file in a temporary directory, so that a failed download stops the target before
# the parser runs, and the directory is removed however the target ends. The parser checks both
# pages, prints what changed and replaces the snapshot as a whole, or not at all. Review the diff,
# update the two dates in docs/abusive-networks.md (the summary says to) and commit. No nyx command contacts
# ipapi.is.
abusive-data:
	@set -e; d=$$(mktemp -d); trap 'rm -rf "$$d"' EXIT; \
	curl -fsS --retry 3 -o "$$d/networks.html" https://ipapi.is/most-abusive-networks.html; \
	curl -fsS --retry 3 -o "$$d/asns.html" https://ipapi.is/most-abusive-asn.html; \
	go run ./internal/abusive/refresh -networks "$$d/networks.html" -asns "$$d/asns.html" -snapshot internal/abusive/snapshot.json
