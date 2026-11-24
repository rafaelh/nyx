# Disable cgo only for builds and vet; Linux race tests need it enabled.
TARGETS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

.PHONY: build dist test lint vuln clean eol-data threat-data release-prep release

build:
	CGO_ENABLED=0 go build -trimpath -o nyx ./cmd/nyx

# Start from an empty dist/ so a release never uploads a stale binary.
dist:
	@rm -rf dist
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "dist/nyx-$$os-$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "-s -w" -o dist/nyx-$$os-$$arch ./cmd/nyx || exit 1; \
	done
	@cd dist && shasum -a 256 nyx-* > SHA256SUMS
	@echo "dist/SHA256SUMS"

# Vet each target to catch platform-specific compile failures before running tests.
test:
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "vet $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go vet ./... || exit 1; \
	done
	go test -race ./...

# Keep lint dependencies in their own module. go tool builds and caches the pinned version.
# Upgrade with:
#   go get -tool -modfile=tools/go.mod github.com/golangci/golangci-lint/v2/cmd/golangci-lint@vX.Y.Z
lint:
	go tool -modfile=tools/go.mod golangci-lint run ./...

# Report known vulnerabilities in dependencies and in the standard library of the local toolchain,
# which a static binary carries. Contacts vuln.go.dev.
vuln:
	go tool -modfile=tools/go.mod govulncheck ./...

# Release in two steps (docs/release-preparation.md): release-prep refreshes dependencies and
# data and runs every check, leaving the changes to review and commit; release tags, builds and
# publishes VERSION with gh.
release-prep:
	scripts/release.sh prepare

release:
	@test -n "$(VERSION)" || { echo "usage: make release VERSION=vX.Y.Z" >&2; exit 2; }
	scripts/release.sh publish "$(VERSION)"

clean:
	rm -rf nyx dist

# Refresh product data and DATE from endoflife.date using curl and jq. Download to a file
# first so failed requests cannot replace data with empty output. Sorted JSON keeps diffs
# readable; review them before committing.
EOL_PRODUCTS = $(shell sed -n 's/^- product: //p' internal/knowledge/eol/products.yaml)
eol-data:
	@set -e; for p in $(EOL_PRODUCTS); do \
		echo "internal/knowledge/eol/data/$$p.json"; \
		curl -fsS --retry 3 -o internal/knowledge/eol/data/$$p.json.raw "https://endoflife.date/api/$$p.json"; \
		jq -S . internal/knowledge/eol/data/$$p.json.raw > internal/knowledge/eol/data/$$p.json.tmp; \
		rm internal/knowledge/eol/data/$$p.json.raw; \
		mv internal/knowledge/eol/data/$$p.json.tmp internal/knowledge/eol/data/$$p.json; \
	done; \
	date -u +%Y-%m-%d > internal/knowledge/eol/DATE

# Download five lists to temporary files, then validate and atomically replace each source's
# embedded bundle. Failed downloads stop before refresh; temporary files are always removed.
# The tool reports entry changes and retains older/equal lists. ALLOW_SHRINK=1 bypasses only
# the half-size rejection for reviewed data. Review the diff and update the five dates in
# docs/abusive-networks.md before committing.
threat-data:
	@set -e; d=$$(mktemp -d); trap 'rm -rf "$$d"' EXIT; \
	curl -fsS --retry 3 -o "$$d/drop_v4.json" https://www.spamhaus.org/drop/drop_v4.json; \
	curl -fsS --retry 3 -o "$$d/drop_v6.json" https://www.spamhaus.org/drop/drop_v6.json; \
	curl -fsS --retry 3 -o "$$d/asndrop.json" https://www.spamhaus.org/drop/asndrop.json; \
	curl -fsS --retry 3 -o "$$d/networks.html" https://ipapi.is/most-abusive-networks.html; \
	curl -fsS --retry 3 -o "$$d/asns.html" https://ipapi.is/most-abusive-asn.html; \
	go run ./internal/threatdata/refresh -dir "$$d" -spamhaus internal/threatdata/spamhaus/builtin.jsonl -ipapi internal/threatdata/abusive/snapshot.json $(if $(filter 1,$(ALLOW_SHRINK)),-allow-shrink)
