# CGO_ENABLED=0 is set only where it is needed: -race requires cgo on Linux,
# so it must not be exported for the whole Makefile.
TARGETS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

.PHONY: build dist test lint clean eol-data threat-data

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

# Refreshes the built-in copies of the five threat-data lists: Spamhaus's DROP, DROPv6 and ASN-DROP
# (internal/spamhaus/builtin.jsonl) and ipapi.is's most abusive networks and ASNs
# (internal/abusive/snapshot.json). It makes five requests: three to www.spamhaus.org and two to
# ipapi.is. curl writes each list to a file in a temporary directory, so that a failed download
# stops the target before the tool runs, and the directory is removed however the target ends. The
# tool (internal/threatdata/refresh) checks the lists with the rules an update applies, prints what
# was added, removed and changed, and replaces each source's file as a whole, or not at all. It
# leaves a list dated no later than the built-in copy as it is. A list with fewer than half the
# built-in copy's entries is refused; a maintainer who has reviewed it can let it through with
# `make threat-data ALLOW_SHRINK=1`, which lifts no other rule. Review the diff, update the dates
# in docs/abusive-networks.md (the tool says to) and commit.
threat-data:
	@set -e; d=$$(mktemp -d); trap 'rm -rf "$$d"' EXIT; \
	curl -fsS --retry 3 -o "$$d/drop_v4.json" https://www.spamhaus.org/drop/drop_v4.json; \
	curl -fsS --retry 3 -o "$$d/drop_v6.json" https://www.spamhaus.org/drop/drop_v6.json; \
	curl -fsS --retry 3 -o "$$d/asndrop.json" https://www.spamhaus.org/drop/asndrop.json; \
	curl -fsS --retry 3 -o "$$d/networks.html" https://ipapi.is/most-abusive-networks.html; \
	curl -fsS --retry 3 -o "$$d/asns.html" https://ipapi.is/most-abusive-asn.html; \
	go run ./internal/threatdata/refresh -dir "$$d" -spamhaus internal/spamhaus/builtin.jsonl -ipapi internal/abusive/snapshot.json $(if $(ALLOW_SHRINK),-allow-shrink)
