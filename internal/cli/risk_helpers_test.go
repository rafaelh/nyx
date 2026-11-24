package cli_test

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// risk adds selected exposure stages to a fake web world.
type risk struct{ *web }

func newRisk(t *testing.T, stages ...string) *risk {
	t.Helper()
	return &risk{newWebWith(t, stages...)}
}

// rows indexes an engagement CSV by column names.
func (x *risk) rows(file string) []map[string]string { return x.table(eng, file) }

// current filters historical CSV rows out.
func current(rows []map[string]string) []map[string]string {
	var out []map[string]string
	for _, r := range rows {
		if r["current"] == "true" {
			out = append(out, r)
		}
	}
	return out
}

// typeURLs returns sorted type/url pairs from current rows.
func typeURLs(rows []map[string]string) []string {
	var out []string
	for _, r := range current(rows) {
		out = append(out, r["type"]+"="+r["url"])
	}
	slices.Sort(out)
	return out
}

// col extracts sorted column values.
func col(rows []map[string]string, name string) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r[name])
	}
	slices.Sort(out)
	return out
}

// summaryFindings extracts findings from the summary event.
func (x *risk) summaryFindings() []map[string]any {
	x.t.Helper()
	var out []map[string]any
	list, _ := x.h.summaryEvent()["findings"].([]any)
	for _, f := range list {
		out = append(out, f.(map[string]any))
	}
	return out
}

func (x *risk) summaryTargets() []string {
	var out []string
	for _, f := range x.summaryFindings() {
		out = append(out, fmt.Sprintf("%v=%v", f["target"], f["severity"]))
	}
	slices.Sort(out)
	return out
}

func (x *risk) state(stage string) event { return lastState(x.h.events(), stage) }

// Storage service fakes

// bucket supplies anonymous listing and per-object HEAD responses.
type bucket struct {
	list      int      // 200 lists objects; 403 is private; zero/404 means missing
	keys      []string // object keys for successful listings
	truncated bool     // whether results were truncated
	objs      map[string]int
	redirect  string // simulate an S3 regional redirect
}

func xmlList(keys []string, truncated bool) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>b</Name>`)
	fmt.Fprintf(&b, "<KeyCount>%d</KeyCount><IsTruncated>%v</IsTruncated>", len(keys), truncated)
	for _, k := range keys {
		fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>1</Size></Contents>", k)
	}
	b.WriteString("</ListBucketResult>")
	return b.String()
}

func azureList(keys []string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs>`)
	for _, k := range keys {
		fmt.Fprintf(&b, "<Blob><Name>%s</Name></Blob>", k)
	}
	b.WriteString("</Blobs><NextMarker /></EnumerationResults>")
	return b.String()
}

func numberedKeys(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("k%04d", i)
	}
	return out
}

// bucketHandler accepts path-style S3/GCS fixture requests.
func bucketHandler(bs map[string]bucket) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
		b, ok := bs[parts[0]]
		if !ok || (b.list == 0 && len(parts) == 1) {
			missingStorage("amazonaws.com")(w, r)
			return
		}
		if len(parts) == 2 && parts[1] != "" {
			code := b.objs[parts[1]]
			if code == 0 {
				code = 403
			}
			w.WriteHeader(code)
			return
		}
		if b.redirect != "" {
			w.Header().Set("x-amz-bucket-region", b.redirect)
			w.WriteHeader(http.StatusMovedPermanently)
			_, _ = w.Write([]byte(`<Error><Code>PermanentRedirect</Code></Error>`))
			return
		}
		switch b.list {
		case 200:
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(xmlList(b.keys, b.truncated)))
		default:
			w.WriteHeader(b.list)
			_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`))
		}
	}
}

// containerHandler accepts Azure listing GETs and per-blob HEADs.
func containerHandler(cs map[string]bucket) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
		c, ok := cs[parts[0]]
		if !ok || (c.list == 0 && len(parts) == 1) {
			missingStorage("blob.core.windows.net")(w, r)
			return
		}
		if len(parts) == 2 && parts[1] != "" {
			code := c.objs[parts[1]]
			if code == 0 {
				code = 404
			}
			w.WriteHeader(code)
			return
		}
		if c.list == 200 {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(azureList(c.keys)))
			return
		}
		w.WriteHeader(c.list)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><Error><Code>PublicAccessNotPermitted</Code></Error>`))
	}
}

// listRequests selects listing GETs from a fake's request log.
func listRequests(s *source) []string {
	var out []string
	for _, r := range s.requestLog() {
		if r.Method == http.MethodGet {
			out = append(out, r.URI)
		}
	}
	return out
}

func heads(s *source) []string {
	var out []string
	for _, r := range s.requestLog() {
		if r.Method == http.MethodHead {
			out = append(out, r.URI)
		}
	}
	slices.Sort(out)
	return out
}
