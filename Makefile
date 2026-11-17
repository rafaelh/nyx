# CGO_ENABLED=0 is set only where it is needed: -race requires cgo on Linux,
# so it must not be exported for the whole Makefile.
TARGETS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

.PHONY: build dist test clean eol-data

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
