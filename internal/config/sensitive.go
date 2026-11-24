package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

// SensitivePath pairs a requested path with response evidence of exposure. Every entry requires
// a body regex or byte prefix, preventing generic 200 responses from matching by status alone.
// Body regexes inspect at most 1 MiB.
type SensitivePath struct {
	Path      string
	Signature string // RE2; empty if Magic is used alone
	Magic     []byte // body prefix; empty if Signature is used alone
	Status    int    // default 200
	Severity  string // high, medium or low; default medium
}

// Hash versions response matchers so signature, magic or status changes create new jobs.
func (p SensitivePath) Hash() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%x\x00%d", p.Signature, p.Magic, p.Status)))
	return hex.EncodeToString(sum[:4])
}

// SeverityRank requests high, medium and low entries in that order. Unknown severities sort
// last as a fallback; normal list validation rejects them.
func (p SensitivePath) SeverityRank() int {
	switch p.Severity {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	}
	return 3
}

// Describe is the signature recorded with a hit.
func (p SensitivePath) Describe() string {
	var parts []string
	if p.Signature != "" {
		parts = append(parts, p.Signature)
	}
	if len(p.Magic) > 0 {
		parts = append(parts, "magic:"+hex.EncodeToString(p.Magic))
	}
	return strings.Join(parts, " + ")
}

var compiled sync.Map // signature -> *regexp.Regexp

func signatureRE(sig string) *regexp.Regexp {
	if re, ok := compiled.Load(sig); ok {
		return re.(*regexp.Regexp)
	}
	re, err := regexp.Compile(sig)
	if err != nil {
		return nil
	}
	compiled.Store(sig, re)
	return re
}

// Match requires every configured condition and returns the matched evidence signature.
func (p SensitivePath) Match(status int, body []byte) (string, bool) {
	if status != p.Status {
		return "", false
	}
	if len(p.Magic) > 0 && !bytes.HasPrefix(body, p.Magic) {
		return "", false
	}
	if p.Signature != "" {
		re := signatureRE(p.Signature)
		if re == nil || !re.Match(body) {
			return "", false
		}
	}
	if p.Signature == "" && len(p.Magic) == 0 {
		return "", false
	}
	return p.Describe(), true
}

var sensitiveFields = map[string]bool{"path": true, "signature": true, "magic": true, "status": true, "severity": true}

// parseSensitivePaths reads structured YAML entries. String-only entries, unknown fields and
// missing signatures/magic are invalid. Paths must be absolute because they are appended to
// service origins.
func parseSensitivePaths(b []byte) ([]SensitivePath, error) {
	var nodes []yaml.Node
	if err := yaml.Unmarshal(b, &nodes); err != nil {
		return nil, fmt.Errorf("not a valid YAML list: %w", err)
	}
	var out []SensitivePath
	for i, n := range nodes {
		p, err := decodeSensitivePath(i+1, n)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// rawSensitivePath holds the unvalidated YAML form.
type rawSensitivePath struct {
	Path      string `yaml:"path"`
	Signature string `yaml:"signature"`
	Magic     *string
	Status    int    `yaml:"status"`
	Severity  string `yaml:"severity"`
}

// decodeSensitivePath requires a known-field mapping and reports validation by entry number.
func decodeSensitivePath(num int, n yaml.Node) (SensitivePath, error) {
	if n.Kind != yaml.MappingNode {
		return SensitivePath{}, fmt.Errorf("entry %d (%q) is not a mapping: each entry needs a path and a signature or magic", num, strings.TrimSpace(n.Value))
	}
	for j := 0; j+1 < len(n.Content); j += 2 {
		if k := n.Content[j].Value; !sensitiveFields[k] {
			return SensitivePath{}, fmt.Errorf("entry %d: unknown field %q", num, k)
		}
	}
	var raw rawSensitivePath
	if err := n.Decode(&raw); err != nil {
		return SensitivePath{}, fmt.Errorf("entry %d: %w", num, err)
	}
	return raw.check()
}

// check validates absolute paths, RE2 signatures and hexadecimal magic, requiring at least one
// matcher. It defaults status to 200 and severity to medium.
func (raw rawSensitivePath) check() (SensitivePath, error) {
	p := SensitivePath{Path: raw.Path, Signature: raw.Signature, Status: raw.Status, Severity: raw.Severity}
	if _, err := url.ParseRequestURI(p.Path); err != nil || !strings.HasPrefix(p.Path, "/") {
		return SensitivePath{}, fmt.Errorf("entry %q is not a path starting with /", p.Path)
	}
	if p.Status == 0 {
		p.Status = 200
	}
	if p.Status < 100 || p.Status > 599 {
		return SensitivePath{}, fmt.Errorf("entry %q: status %d is not an HTTP status", p.Path, p.Status)
	}
	switch p.Severity {
	case "":
		p.Severity = "medium"
	case "high", "medium", "low":
	default:
		return SensitivePath{}, fmt.Errorf("entry %q: severity %q is not high, medium or low", p.Path, p.Severity)
	}
	if p.Signature != "" {
		if _, err := regexp.Compile(p.Signature); err != nil {
			return SensitivePath{}, fmt.Errorf("entry %q: signature %q: %w", p.Path, p.Signature, err)
		}
	}
	if raw.Magic != nil {
		m, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(*raw.Magic), " ", ""))
		if err != nil || len(m) == 0 {
			return SensitivePath{}, fmt.Errorf("entry %q: magic %q is not a hex byte prefix", p.Path, *raw.Magic)
		}
		p.Magic = m
	}
	if p.Signature == "" && len(p.Magic) == 0 {
		return SensitivePath{}, fmt.Errorf("entry %q has neither a signature nor magic; every entry needs one so a catch-all 200 is not flagged", p.Path)
	}
	return p, nil
}
