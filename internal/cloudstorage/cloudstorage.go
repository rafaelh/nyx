// Package cloudstorage describes S3, GCS and Azure storage names, references, guesses and
// display keys without I/O.
package cloudstorage

import (
	"iter"
	"net/url"
	"regexp"
	"strings"

	"github.com/rafaelh/nyx/internal/dnsname"
)

// Providers.
const (
	S3    = "s3"
	GCS   = "gcs"
	Azure = "azure"
)

// Providers fixes storage-guess expansion order.
var Providers = []string{S3, GCS, Azure}

// Ref identifies a bucket or Azure account/container from a URL or host. Container applies only
// to Azure.
type Ref struct {
	Provider, Name, Container, Object string
}

// Reference links storage to an in-scope hostname or page. Via distinguishes CNAME, plain link
// and browser-loaded asset references; From records the source.
type Reference struct {
	Ref
	Via, From string
}

// AzureContainers supplies default names for existing accounts.
var AzureContainers = []string{"$web", "$root", "public", "assets", "static", "media", "images", "files", "uploads", "backup", "data", "logs"}

// guessWords fixes the priority of generated name variants.
var guessWords = []string{"backup", "backups", "dev", "prod", "staging", "test", "assets", "static", "media", "files", "uploads", "public", "private", "data", "logs", "www", "web", "cdn", "images", "docs"}

var (
	// <bucket>.s3.amazonaws.com, .s3.<region>., .s3-<region>., .s3-website-<region>., .s3-website.<region>.
	s3VirtualHost = regexp.MustCompile(`^(.+)\.s3(?:[.-](?:website[.-]|dualstack\.)?[a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?$`)
	// s3.amazonaws.com, s3.<region>.amazonaws.com, s3-<region>.amazonaws.com (path-style)
	s3PathHost = regexp.MustCompile(`^s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?$`)
	// <acct>.blob.core.windows.net, <acct>.web.core.windows.net and the zoned
	// static-website form <acct>.z<n>.web.core.windows.net
	azureHost  = regexp.MustCompile(`^([a-z0-9]{3,24})\.(?:z[0-9]+\.)?(blob|web)\.core\.windows\.net$`)
	gcsVirtual = regexp.MustCompile(`^(.+)\.storage\.googleapis\.com$`)
)

// ParseRef accepts storage URLs and bare hosts.
func ParseRef(s string) (Ref, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Ref{}, false
	}
	raw := s
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return Ref{}, false
	}
	host := strings.ToLower(u.Hostname())
	path := strings.TrimPrefix(u.EscapedPath(), "/")
	if p, err := url.PathUnescape(path); err == nil {
		path = p
	}
	first, rest, _ := strings.Cut(path, "/")

	switch {
	case host == "storage.googleapis.com" || host == "storage.cloud.google.com":
		if first == "" {
			return Ref{}, false
		}
		return Ref{Provider: GCS, Name: first, Object: rest}, true
	case gcsVirtual.MatchString(host):
		name := gcsVirtual.FindStringSubmatch(host)[1]
		if name == "c" { // c.storage.googleapis.com denotes alias-based addressing, not bucket c
			return Ref{}, false
		}
		return Ref{Provider: GCS, Name: name, Object: path}, true
	case s3PathHost.MatchString(host):
		if first == "" {
			return Ref{}, false
		}
		return Ref{Provider: S3, Name: first, Object: rest}, true
	case s3VirtualHost.MatchString(host):
		return Ref{Provider: S3, Name: s3VirtualHost.FindStringSubmatch(host)[1], Object: path}, true
	case azureHost.MatchString(host):
		m := azureHost.FindStringSubmatch(host)
		if m[2] == "web" {
			return Ref{Provider: Azure, Name: m[1], Container: "$web", Object: path}, true
		}
		return Ref{Provider: Azure, Name: m[1], Container: first, Object: rest}, true
	}
	return Ref{}, false
}

// ParseCNAME handles alias-based bucket names: c.storage.googleapis.com names the service,
// while the alias supplies the bucket.
func ParseCNAME(alias, target string) (Ref, bool) {
	if strings.EqualFold(strings.TrimSuffix(target, "."), "c.storage.googleapis.com") {
		return Ref{Provider: GCS, Name: dnsname.Normalise(alias)}, true
	}
	return ParseRef(strings.TrimSuffix(target, "."))
}

// RootBases derives guesses from a root's label, dash-joined name and full name.
func RootBases(root string) []string {
	root = dnsname.Normalise(root)
	label, _, _ := strings.Cut(dnsname.Registrable(root), ".")
	return dedupe([]string{label, strings.ReplaceAll(root, ".", "-"), root})
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// OrgBases joins meaningful organisation words with and without dashes.
func OrgBases(org string) []string {
	words := strings.Fields(nonAlnum.ReplaceAllString(strings.ToLower(org), " "))
	if len(words) == 0 {
		return nil
	}
	return dedupe([]string{strings.Join(words, ""), strings.Join(words, "-")})
}

func dedupe(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Guess tries bare bases, then base-word and word-base variants, up to cap. Stable ordering
// means raising the cap only adds guesses.
func Guess(bases []string, cap int) []string {
	var all []string
	all = append(all, bases...)
	for _, b := range bases {
		for _, w := range guessWords {
			all = append(all, b+"-"+w)
		}
	}
	for _, b := range bases {
		for _, w := range guessWords {
			all = append(all, w+"-"+b)
		}
	}
	all = dedupe(all)
	if cap >= 0 && len(all) > cap {
		all = all[:cap]
	}
	return all
}

// InputGuesses preserves root/organisation priority and identifies each guess's source input.
func InputGuesses(roots, orgs []string, cap int) iter.Seq2[string, Ref] {
	return func(yield func(string, Ref) bool) {
		for _, set := range []struct {
			inputs []string
			bases  func(string) []string
		}{{roots, RootBases}, {orgs, OrgBases}} {
			for _, in := range set.inputs {
				for _, g := range Guesses(set.bases(in), cap) {
					if !yield(in, g) {
						return
					}
				}
			}
		}
	}
}

// Guesses expands names in Providers order, dropping invalid provider-specific names. Azure
// uses account names rather than buckets.
func Guesses(bases []string, cap int) []Ref {
	var out []Ref
	for _, n := range Guess(bases, cap) {
		for _, p := range Providers {
			if pn, ok := ProviderName(p, n); ok {
				out = append(out, Ref{Provider: p, Name: pn})
			}
		}
	}
	return out
}

var (
	bucketName   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	accountName  = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	accountStrip = strings.NewReplacer("-", "", ".", "")
)

// ProviderName validates S3/GCS names and normalises Azure accounts by dropping hyphens/dots.
// S3/GCS allow 3–63 characters; Azure requires 3–24 alphanumerics.
func ProviderName(provider, name string) (string, bool) {
	switch provider {
	case S3, GCS:
		if !bucketName.MatchString(name) || strings.Contains(name, "..") || strings.Contains(name, ".-") || strings.Contains(name, "-.") {
			return "", false
		}
		return name, true
	case Azure:
		n := accountStrip.Replace(name)
		if !accountName.MatchString(n) {
			return "", false
		}
		return n, true
	}
	return "", false
}

// Key identifies S3/GCS buckets or Azure containers in stored records.
func Key(provider, name, container string) string {
	if container != "" {
		return provider + "|" + name + "/" + container
	}
	return provider + "|" + name
}

// AccountKey identifies an Azure account consistently in storage checks and missing-resource
// sets.
func AccountKey(name string) string { return "azure-account|" + name }

// URL builds the provider's path-style listing endpoint.
func URL(provider, name, container string) string {
	switch provider {
	case GCS:
		return "https://storage.googleapis.com/" + name
	case Azure:
		u := "https://" + name + ".blob.core.windows.net"
		if container != "" {
			u += "/" + container
		}
		return u
	}
	return "https://s3.amazonaws.com/" + name
}

// PublicState reports yes if any anonymous object HEAD succeeded, no if all refused, and
// unknown without checked objects.
func PublicState(results []bool) string {
	if len(results) == 0 {
		return "unknown"
	}
	for _, ok := range results {
		if ok {
			return "yes"
		}
	}
	return "no"
}
